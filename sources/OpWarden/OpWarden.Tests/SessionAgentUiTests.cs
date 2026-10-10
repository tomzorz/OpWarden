using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Automation;
using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The real session agent against a test broker, driven through UI Automation: prompts
/// appear and a button press reaches the broker, toasts name what was read, and the
/// windows the tray opens fill in. Opt-in, because it puts windows on the desktop: set
/// OPWARDEN_UI_TESTS=1, and OPWARDEN_UI_SCREENSHOTS to a folder, which the agent then
/// fills with a PNG of each window it shows.
/// </summary>
/// <remarks>
/// The button press is a UI Automation invoke, which is exactly the scripted input that
/// spec section 17 leaves open: these tests passing is that open question, demonstrated.
/// </remarks>
public sealed partial class SessionAgentUiTests
{
    private const int ExitDenied = 77;
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");

    private static bool Enabled => Environment.GetEnvironmentVariable("OPWARDEN_UI_TESTS") == "1";

    [Fact]
    public async Task A_full_prompt_renders_and_allow_once_reaches_the_broker()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var run = broker.RunShimAsync(["read", "op://Private/GitHub/password"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Invoke(prompt, "AllowOnceButton");

            Assert.Equal(0, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task A_run_prompt_lists_its_references_and_disallow_once_denies()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var envFile = Path.Combine(broker.DataDirectory, "tofu.env");
            await File.WriteAllLinesAsync(envFile, ["PG_USER=op://Infra/postgres/username", "PG_PASSWORD=op://Infra/postgres/password", "HYPERVISOR_TOKEN=op://Infra/hypervisor/api token"], TestContext.Current.CancellationToken);
            var run = broker.RunShimAsync(["run", "--env-file", envFile, "--", "tofu", "plan"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Assert.NotNull(prompt.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "Infra / hypervisor / api token")));
            Invoke(prompt, "DisallowOnceButton");

            Assert.Equal(ExitDenied, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task An_unknown_caller_gets_only_the_once_buttons()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(CallerIdentity.Unknown, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var run = broker.RunShimAsync(["item", "get", "GitHub", "--vault", "Private"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Assert.Null(Find(prompt, "AlwaysAllowButton"));
            Invoke(prompt, "DisallowOnceButton");
            Assert.Equal(ExitDenied, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task A_read_a_rule_lets_through_raises_a_toast_naming_it()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, "Infra", null, null, Verdict.Allow)], sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            await WaitUntilPinnedAsync(broker);
            Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/tofu-state/passphrase"])).ExitCode);

            var toast = await WaitForWindowAsync(agent, "ReadToast");

            Assert.NotNull(toast.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "claude-code read a secret")));
            Assert.NotNull(toast.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "Infra / tofu-state / passphrase")));
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_rules_window_lists_the_stored_rules_read_only()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, "Infra", "GitHub", null, Verdict.Allow, CacheTtl.EightHours), new Rule(null, OpAction.Delete, null, null, null, Verdict.Deny)], sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker, "rules");
        try
        {
            var window = await WaitForWindowAsync(agent, "RulesWindow");
            var rows = await WaitForAsync(() => window.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem)), found => found.Count == 2);

            Assert.Equal(2, rows.Count);
            Assert.NotNull(Find(window, "ElevateButton"));
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_audit_and_status_windows_show_what_the_broker_recorded()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)], sessionAgentPath: BuiltExecutables.SessionAgent);
        Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/postgres/password"])).ExitCode);
        using var agent = StartAgent(broker, "audit", "status");
        try
        {
            var audit = await WaitForWindowAsync(agent, "AuditWindow");
            var rows = await WaitForAsync(() => audit.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem)), found => found.Count > 0);
            Assert.NotEmpty(rows.Cast<AutomationElement>());

            var status = await WaitForWindowAsync(agent, "StatusWindow");
            var cached = await WaitForAsync(() => Find(status, "CachedValues"), element => element?.Current.Name == "0");
            Assert.Equal("0", cached!.Current.Name);
        }
        finally
        {
            agent.Kill();
        }
    }

    private static Process StartAgent(BrokerHarness broker, params string[] open)
    {
        var info = new ProcessStartInfo(BuiltExecutables.SessionAgent) { UseShellExecute = false };
        foreach (var argument in new[] { "--pipe", broker.AgentPipeName, "--manage-pipe", broker.Pipes.Management }) info.ArgumentList.Add(argument);
        foreach (var window in open)
        {
            info.ArgumentList.Add("--open");
            info.ArgumentList.Add(window);
        }

        return Process.Start(info) ?? throw new InvalidOperationException("Could not start the session agent.");
    }

    /// <summary>
    /// The agent's top-level window with this automation ID. Windows are found with Win32
    /// and only then handed to UI Automation: .NET's managed UI Automation client takes tens
    /// of seconds to walk a desktop's top-level windows (45 s for one search on a real
    /// desktop, where .NET Framework's takes 46 ms), but answers in milliseconds for a
    /// window it is handed.
    /// </summary>
    private static async Task<AutomationElement> WaitForWindowAsync(Process agent, string automationId)
    {
        var window = await WaitForAsync(() => WindowsOf(agent.Id).Select(ElementOf).FirstOrDefault(w => w?.Current.AutomationId == automationId), found => found is not null);
        return window!;
    }

    private static List<nint> WindowsOf(int processId)
    {
        var windows = new List<nint>();
        nint window = 0;
        while ((window = FindWindowExW(0, window, null, null)) != 0)
        {
            _ = GetWindowThreadProcessId(window, out var owner);
            if (owner == processId && IsWindowVisible(window)) windows.Add(window);
        }

        return windows;
    }

    private static AutomationElement? ElementOf(nint window)
    {
        try
        {
            return AutomationElement.FromHandle(window);
        }
        catch (ElementNotAvailableException)
        {
            // The window closed between finding it and asking about it.
            return null;
        }
    }

    private static async Task<T> WaitForAsync<T>(Func<T> look, Func<T, bool> done)
    {
        for (var i = 0; i < 150; i++)
        {
            var found = look();
            if (done(found)) return found;
            await Task.Delay(100);
        }

        throw new TimeoutException("The session agent did not show what was expected within 15 seconds.");
    }

    private static async Task WaitUntilPinnedAsync(BrokerHarness broker) =>
        await WaitForAsync(() => broker.AuditEntries("agent-pinned").Count, pins => pins > 0);

    private static AutomationElement? Find(AutomationElement window, string automationId) =>
        window.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.AutomationIdProperty, automationId));

    private static void Invoke(AutomationElement window, string automationId)
    {
        var button = Find(window, automationId);
        Assert.NotNull(button);
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial nint FindWindowExW(nint parent, nint after, string? className, string? title);
    [LibraryImport("user32.dll")] private static partial uint GetWindowThreadProcessId(nint window, out int processId);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsWindowVisible(nint window);
}
