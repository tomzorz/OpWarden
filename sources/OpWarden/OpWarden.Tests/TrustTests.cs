using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using OpWarden.Broker;
using OpWarden.Broker.Callers;
using OpWarden.Broker.Pipes;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Management;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// Spec section 8 against the real broker: who may connect, which session agent is
/// pinned, and who may change rules.
/// </summary>
public sealed partial class TrustTests
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly Rule ClaudeReads = new(Claude, OpAction.Read, null, null, null, Verdict.Allow);

    private static bool Elevated
    {
        get
        {
            using var self = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(self).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    [Fact]
    public async Task A_session_agent_running_another_executable_is_refused_and_audited()
    {
        await using var broker = BrokerHarness.Start(Claude, sessionAgentPath: BuiltExecutables.SessionAgent);
        await using var agent = await broker.ConnectAgentAsync();

        var refused = await agent.NextAsync<AgentRefused>();

        Assert.Contains("does not run the installed session agent", refused.Reason, StringComparison.Ordinal);
        var entry = Assert.Single(broker.AuditEntries("agent-refused"));
        Assert.Contains(Environment.ProcessPath!, entry.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(broker.AuditEntries("agent-pinned"));
    }

    [Fact]
    public async Task One_session_agent_is_pinned_at_a_time_and_the_next_one_after_it_closes()
    {
        await using var broker = BrokerHarness.Start(Claude);
        var first = await broker.ConnectAgentAsync();
        await WaitUntilAsync(() => broker.AuditEntries("agent-pinned").Count == 1);

        await using (var second = await broker.ConnectAgentAsync())
        {
            Assert.Equal("another session agent is pinned", (await second.NextAsync<AgentRefused>()).Reason);
        }

        await first.DisposeAsync();
        await using var third = await ConnectPinnedAsync(broker, pinnedBefore: 1);

        // The newly pinned session agent is the one that decides.
        var run = broker.RunShimAsync(["read", "op://V/I/K"]);
        await third.DecideAsync(await third.NextAsync<ShowPrompt>(), PromptDecision.AllowOnce);
        Assert.Equal(0, (await run).ExitCode);
    }

    [Fact]
    public void The_pipes_let_the_user_connect_but_not_add_instances_and_shut_out_the_network()
    {
        var user = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        using var self = WindowsIdentity.GetCurrent();

        var rules = PipeServer.SecurityFor(user).GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToList();

        var forUser = Assert.Single(rules, r => r.IdentityReference.Equals(user));
        Assert.Equal(AccessControlType.Allow, forUser.AccessControlType);
        Assert.True(forUser.PipeAccessRights.HasFlag(PipeAccessRights.ReadWrite));
        Assert.False(forUser.PipeAccessRights.HasFlag(PipeAccessRights.CreateNewInstance));

        var network = Assert.Single(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)));
        Assert.Equal(AccessControlType.Deny, network.AccessControlType);

        var broker = Assert.Single(rules, r => r.IdentityReference.Equals(self.User));
        Assert.Equal(PipeAccessRights.FullControl, broker.PipeAccessRights & PipeAccessRights.FullControl);
        Assert.Equal(3, rules.Count);
    }

    [Fact]
    public async Task The_broker_will_not_start_on_a_squatted_pipe()
    {
        var pipes = BrokerHarness.NewPipeNames();
        await using var squatter = new NamedPipeServerStream(pipes.Shim, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var data = Directory.CreateTempSubdirectory("opwarden-squat-");
        try
        {
            using var self = WindowsIdentity.GetCurrent();
            var options = new BrokerHostOptions(BuiltExecutables.Probe, data.FullName, self.User!, Environment.ProcessPath!, pipes, TimeSpan.FromSeconds(5), _ => new CallerResolution(Claude, []), _ => { });

            var failure = Assert.Throws<IOException>(() => BrokerHost.Start(options));

            Assert.Contains(pipes.Shim, failure.Message, StringComparison.Ordinal);
            Assert.Contains("squatting", failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            data.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task The_management_pipe_reads_the_rules_without_elevation()
    {
        await using var broker = BrokerHarness.Start(Claude, [ClaudeReads]);

        var response = await broker.ManageAsync(new ListRules());

        Assert.Null(response.Error);
        Assert.Equal([ClaudeReads], response.Rules!.Rules);
    }

    [Fact]
    public async Task A_rule_change_takes_an_elevated_administrator()
    {
        await using var broker = BrokerHarness.Start(Claude);

        var response = await broker.ManageAsync(new AddRules([ClaudeReads]));

        // The test runs as whatever it was started as; each branch is the requirement.
        if (Elevated)
        {
            Assert.Null(response.Error);
            Assert.Equal([ClaudeReads], broker.Rules.Current.Rules);
            Assert.Equal("management", Assert.Single(broker.AuditEntries("rule-change")).GetProperty("source").GetString());
        }
        else
        {
            Assert.Contains("REQ-TRUST-5", response.Error, StringComparison.Ordinal);
            Assert.Empty(broker.Rules.Current.Rules);
            var refused = Assert.Single(broker.AuditEntries("management-refused"));
            Assert.Contains(Environment.UserName, refused.GetProperty("detail").GetString(), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Flushing_the_cache_takes_no_elevation()
    {
        await using var broker = BrokerHarness.Start(Claude);
        broker.Cache.Put(new("claude-code", "read"), "secret"u8, CacheTtl.FifteenMinutes);

        var response = await broker.ManageAsync(new FlushCache());

        Assert.Null(response.Error);
        Assert.Equal(1, response.Flushed);
        Assert.Equal(0, broker.Cache.Count);
        Assert.Single(broker.AuditEntries("cache-flush"));
    }

    [Fact]
    public void The_process_table_describes_processes_the_broker_cannot_open()
    {
        // Under the service account every user process is one of these, so this is the
        // service's view of the machine, taken from a user session.
        var unopenable = LiveProcesses.Snapshot().Where(p => p.ProcessId > 4 && !CanOpen(p.ProcessId)).ToList();
        Assert.SkipWhen(unopenable.Count == 0, "Every process on this machine opens for this user.");

        Assert.All(unopenable, p => Assert.True(p.CreateTime > 0, $"process {p.ProcessId} ({p.ImagePath}) has no start time"));
        Assert.Contains(unopenable, p => Path.IsPathFullyQualified(p.ImagePath ?? ""));
    }

    [Fact]
    public async Task Service_mode_outside_the_service_control_manager_says_so()
    {
        var data = Directory.CreateTempSubdirectory("opwarden-service-");
        try
        {
            using var self = WindowsIdentity.GetCurrent();
            var config = Path.Combine(data.FullName, "broker.json");
            await File.WriteAllTextAsync(config, $$"""{"opPath":"C:\\op\\op.exe","dataDirectory":"data","userSid":"{{self.User}}"}""", TestContext.Current.CancellationToken);

            using var broker = Process.Start(new ProcessStartInfo(BuiltExecutables.Broker, ["--service", "--config", config]) { UseShellExecute = false, RedirectStandardError = true })!;
            var stderr = await broker.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            await broker.WaitForExitAsync(TestContext.Current.CancellationToken);

            Assert.Equal(1063, broker.ExitCode);
            Assert.Contains("service control manager", stderr, StringComparison.Ordinal);
        }
        finally
        {
            data.Delete(recursive: true);
        }
    }

    [Fact]
    public void Under_the_service_the_config_must_name_the_interactive_user()
    {
        var data = Directory.CreateTempSubdirectory("opwarden-config-");
        try
        {
            var config = Path.Combine(data.FullName, "broker.json");
            File.WriteAllText(config, """{"opPath":"C:\\op\\op.exe","dataDirectory":"data"}""");

            Assert.Null(BrokerConfig.Load(config, service: true, out var error));
            Assert.Contains("userSid is required", error, StringComparison.Ordinal);

            using var self = WindowsIdentity.GetCurrent();
            Assert.Equal(self.User, BrokerConfig.Load(config, service: false, out _)!.User);
        }
        finally
        {
            data.Delete(recursive: true);
        }
    }

    /// <summary>
    /// Connects until the broker pins the connection: the previous session agent's pin is
    /// released when the broker notices it closed, which races the next connection.
    /// </summary>
    private static async Task<TestAgent> ConnectPinnedAsync(BrokerHarness broker, int pinnedBefore)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var refusedBefore = broker.AuditEntries("agent-refused").Count;
            var agent = await broker.ConnectAgentAsync();
            await WaitUntilAsync(() => broker.AuditEntries("agent-pinned").Count > pinnedBefore || broker.AuditEntries("agent-refused").Count > refusedBefore);
            if (broker.AuditEntries("agent-pinned").Count > pinnedBefore) return agent;
            await agent.DisposeAsync();
            await Task.Delay(100);
        }

        throw new TimeoutException("The broker never pinned the next session agent.");
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("The condition did not hold within 5 seconds.");
            await Task.Delay(20);
        }
    }

    private static bool CanOpen(int processId)
    {
        var handle = OpenProcess(0x1000, false, (uint)processId);
        if (handle == 0) return false;
        _ = CloseHandle(handle);
        return true;
    }

    [LibraryImport("kernel32.dll")] private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint handle);
}
