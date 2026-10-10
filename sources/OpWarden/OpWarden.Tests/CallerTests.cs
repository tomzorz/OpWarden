using System.Diagnostics;
using System.Text;
using OpWarden.Broker.Callers;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class ProcessEventDecoderTests
{
    private static byte[] Payload(byte version, int processId, long createTime, int parentId, int session, string image, int sidSubAuthorities = 1)
    {
        var buffer = new List<byte>();
        void U32(int v) => buffer.AddRange(BitConverter.GetBytes(v));
        void U64(long v) => buffer.AddRange(BitConverter.GetBytes(v));

        U32(processId);
        if (version == 3) U64(1234); // ProcessSequenceNumber
        U64(createTime);
        U32(parentId);
        if (version == 3) U64(1233); // ParentProcessSequenceNumber
        U32(session);
        if (version >= 1) U32(0); // Flags
        if (version == 3)
        {
            U32(1); // ProcessTokenElevationType
            U32(0); // ProcessTokenIsElevated
            buffer.Add(1); // SID revision
            buffer.Add((byte)sidSubAuthorities);
            buffer.AddRange(new byte[6]);
            for (var i = 0; i < sidSubAuthorities; i++) U32(0x2000 + i);
        }

        buffer.AddRange(Encoding.Unicode.GetBytes(image + "\0"));
        if (version >= 2) U32(0); // ImageChecksum and what follows
        return [.. buffer];
    }

    [Theory]
    [InlineData((byte)0, 1)]
    [InlineData((byte)1, 1)]
    [InlineData((byte)2, 1)]
    [InlineData((byte)3, 1)]
    [InlineData((byte)3, 0)]
    [InlineData((byte)3, 5)]
    public void Decodes_every_known_version(byte version, int sidSubAuthorities)
    {
        var entry = ProcessEventDecoder.DecodeStart(version, Payload(version, 4242, 133_000_000_000_000_000, 77, 3, @"C:\Tools\bash.exe", sidSubAuthorities));

        Assert.Equal(new ProcessEntry(4242, 77, 133_000_000_000_000_000, @"C:\Tools\bash.exe", 3), entry);
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData((byte)2)]
    public void Decodes_every_known_stop_version(byte version)
    {
        var payload = new List<byte>();
        payload.AddRange(BitConverter.GetBytes(4242));
        if (version == 2) payload.AddRange(BitConverter.GetBytes(1234L)); // ProcessSequenceNumber
        payload.AddRange(BitConverter.GetBytes(133_000_000_000_000_000L));
        payload.AddRange(BitConverter.GetBytes(133_000_000_050_000_000L));
        payload.AddRange(BitConverter.GetBytes(0)); // ExitCode and what follows

        Assert.Equal(new ProcessExit(4242, 133_000_000_000_000_000, 133_000_000_050_000_000), ProcessEventDecoder.DecodeStop(version, [.. payload]));
    }

    [Fact]
    public void An_unknown_or_truncated_stop_decodes_to_nothing()
    {
        Assert.Null(ProcessEventDecoder.DecodeStop(7, new byte[40]));
        Assert.Null(ProcessEventDecoder.DecodeStop(2, new byte[20]));
    }

    [Fact]
    public void An_unknown_version_decodes_to_nothing()
    {
        Assert.Null(ProcessEventDecoder.DecodeStart(9, Payload(3, 1, 2, 3, 4, "x.exe")));
    }

    [Fact]
    public void A_truncated_payload_decodes_to_nothing()
    {
        Assert.Null(ProcessEventDecoder.DecodeStart(3, Payload(3, 1, 2, 3, 4, "x.exe").AsSpan(0, 40)));
    }

    [Fact]
    public void A_payload_without_a_sid_where_v3_expects_one_decodes_to_nothing()
    {
        var payload = Payload(3, 1, 2, 3, 4, "x.exe");
        payload[48] = 0;

        Assert.Null(ProcessEventDecoder.DecodeStart(3, payload));
    }

    [Fact]
    public void Device_paths_become_drive_paths()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var device = DosDevice(windows[..2]);

        Assert.Equal(Path.Combine(windows, "explorer.exe"), DevicePaths.ToDrivePath(device + windows[2..] + @"\explorer.exe"));
        Assert.Equal(@"C:\plain\path.exe", DevicePaths.ToDrivePath(@"C:\plain\path.exe"));
    }

    private static unsafe string DosDevice(string drive)
    {
        var buffer = stackalloc char[512];
        _ = QueryDosDeviceW(drive, buffer, 512);
        return new string(buffer);
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern unsafe uint QueryDosDeviceW(string device, char* target, uint max);
}

public sealed class ProcessMapTests
{
    [Fact]
    public void A_parent_is_the_entry_that_was_running_when_the_child_started()
    {
        var map = new ProcessMap();
        map.Record(new ProcessEntry(100, 4, 1_000, "old.exe", ExitTime: 2_000));
        map.Record(new ProcessEntry(100, 4, 5_000, "new.exe", ExitTime: 9_000));

        Assert.Equal("new.exe", Assert.IsType<ParentLookup.Found>(map.FindParent(100, 6_000)).Entry.ImagePath);
        Assert.Equal("old.exe", Assert.IsType<ParentLookup.Found>(map.FindParent(100, 1_500)).Entry.ImagePath);
        Assert.IsType<ParentLookup.Missing>(map.FindParent(100, 500));
    }

    [Fact]
    public void An_earlier_process_with_the_same_id_never_stands_in_for_a_parent_still_unreported()
    {
        // The shape the first service run recorded: a monitoring plug-in held the ID, exited,
        // and the ID went to a shell whose start event had not arrived.
        var map = new ProcessMap();
        map.Record(new ProcessEntry(15468, 17124, 1_000, "monitor-plugin.exe", ExitTime: 1_900));

        Assert.IsType<ParentLookup.Missing>(map.FindParent(15468, 3_000));
    }

    [Fact]
    public void An_entry_whose_exit_has_not_arrived_is_unsettled()
    {
        var map = new ProcessMap();
        map.Record(new ProcessEntry(40, 30, 1_000, "bash.exe"));

        Assert.IsType<ParentLookup.ExitUnreported>(map.FindParent(40, 2_000));
    }

    [Fact]
    public void An_exit_that_arrives_before_its_start_is_kept_for_it()
    {
        var map = new ProcessMap();
        map.RecordExit(new ProcessExit(40, 1_000, 2_500));
        map.Record(new ProcessEntry(40, 30, 1_000, "bash.exe"));

        Assert.Equal(2_500, map.Find(40, long.MaxValue)?.ExitTime);
    }

    [Fact]
    public void Seeing_a_process_again_keeps_its_recorded_exit()
    {
        var map = new ProcessMap();
        map.Record(new ProcessEntry(40, 30, 1_000, "bash.exe"));
        map.RecordExit(new ProcessExit(40, 1_000, 2_500));
        map.Record(new ProcessEntry(40, 30, 1_000, "bash.exe"));

        Assert.Equal(2_500, map.Find(40, long.MaxValue)?.ExitTime);
        Assert.Equal(1, map.Count);
    }

    [Fact]
    public void A_seeded_parent_that_started_after_its_child_is_not_its_parent()
    {
        var map = new ProcessMap();
        map.Seed([new ProcessEntry(10, 4, 2_000, "reused-parent.exe"), new ProcessEntry(20, 10, 1_000, "older-child.exe"), new ProcessEntry(30, 10, 3_000, "real-child.exe")], takenAt: 4_000);

        Assert.Equal(ProcessEntry.UnknownParent, map.Find(20, long.MaxValue)?.ParentId);
        Assert.Equal(10, map.Find(30, long.MaxValue)?.ParentId);
    }

    [Fact]
    public void Retention_keeps_the_ancestry_of_running_processes_and_nothing_else()
    {
        var map = new ProcessMap();
        map.Record(new ProcessEntry(1, 0, 100, "root.exe"));
        map.Record(new ProcessEntry(2, 1, 200, "exited-bash.exe"));
        map.Record(new ProcessEntry(3, 2, 300, "running.exe"));
        map.Record(new ProcessEntry(9, 1, 250, "exited-orphan.exe"));

        map.Retain([new ProcessEntry(3, 2, 300, "running.exe")]);

        Assert.Equal(3, map.Count);
        Assert.Null(map.Find(9, long.MaxValue));
        Assert.NotNull(map.Find(2, long.MaxValue));
    }

    [Fact]
    public void The_cap_drops_the_oldest_entries_and_says_how_many()
    {
        var map = new ProcessMap(maxEntries: 2);
        foreach (var i in Enumerable.Range(1, 4)) map.Record(new ProcessEntry(i, 0, i * 100, $"p{i}.exe"));

        var dropped = map.Retain([.. Enumerable.Range(1, 4).Select(i => new ProcessEntry(i, 0, i * 100, $"p{i}.exe"))]);

        Assert.Equal(2, dropped);
        Assert.Null(map.Find(1, long.MaxValue));
        Assert.NotNull(map.Find(4, long.MaxValue));
    }
}

public sealed class CallerResolverTests
{
    private static readonly string Explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
    private static readonly string ShellHost = Path.Combine(Environment.SystemDirectory, "sihost.exe");
    private const int Session = 1;

    private static readonly AgentHost[] Agents = [new("claude-code", "claude.exe", "Anthropic, PBC"), new("opencode", "opencode.exe", null)];

    private static readonly Dictionary<string, string> Signers = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"C:\Users\u\.local\bin\claude.exe"] = "Anthropic, PBC",
        [@"C:\Program Files\WindowsApps\Claude\Claude.exe"] = "Anthropic, PBC",
        [@"C:\Temp\claude.exe"] = "Someone Else",
    };

    // A process tree as (id, parent, created, path). The shim is always 1000. seededAt is
    // when the broker took its snapshot; the default puts every process before it, so a
    // parent the map lacks ends the walk instead of waiting for events.
    private static CallerResolution Resolve(ProcessEntry[] live, ProcessEntry[]? exitedButMapped = null, ProcessEntry[]? mapped = null, long seededAt = long.MaxValue) =>
        Resolver(live, out _, exitedButMapped, mapped, seededAt).Resolve(1000);

    private static CallerResolver Resolver(ProcessEntry[] live, out ProcessMap map, ProcessEntry[]? exitedButMapped = null, ProcessEntry[]? mapped = null, long seededAt = long.MaxValue)
    {
        map = new ProcessMap();
        map.Seed([], seededAt);
        foreach (var entry in (mapped ?? live).Concat(exitedButMapped ?? [])) map.Record(entry);
        var byId = live.ToDictionary(p => p.ProcessId);
        return new CallerResolver(map, Agents, path => Signers.GetValueOrDefault(path), id => byId.TryGetValue(id, out var p) ? p : null, () => Session);
    }

    private static ProcessEntry P(int id, int parent, long created, string path) => new(id, parent, created, path, Session);

    private static ProcessEntry X(int id, int parent, long created, long exited, string path) => new(id, parent, created, path, Session, exited);

    [Fact]
    public void The_nearest_agent_host_wins_over_one_further_up()
    {
        var result = Resolve(
        [
            P(10, 0, 10, Explorer),
            P(20, 10, 20, @"C:\Program Files\WindowsApps\Claude\Claude.exe"),
            P(30, 20, 30, @"C:\Users\u\.local\bin\claude.exe"),
            P(40, 30, 40, @"C:\Program Files\Git\usr\bin\bash.exe"),
            P(1000, 40, 50, @"C:\OpWarden\op.exe"),
        ]);

        Assert.Equal(CallerIdentity.Agent("claude-code"), result.Caller);
        Assert.Equal(["op.exe(1000)", "bash.exe(40)", "claude.exe(30)"], result.Chain);
    }

    [Fact]
    public void An_msys2_parent_that_exited_is_still_walked_through_the_map()
    {
        // MSYS2's exec: bash(40) started the shim and then exited; Windows still names 40
        // as the parent, but only the map remembers who 40 was.
        var result = Resolve(
            live: [P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe"), P(1000, 40, 50, @"C:\OpWarden\op.exe")],
            exitedButMapped: [X(40, 30, 40, 60, @"C:\Program Files\Git\usr\bin\bash.exe")]);

        Assert.Equal(CallerIdentity.Agent("claude-code"), result.Caller);
    }

    [Fact]
    public void A_running_parent_wins_over_an_earlier_process_that_had_its_id()
    {
        // From the first service run: the map named a monitoring plug-in that had held the
        // subshell's ID earlier as op's parent, because the subshell's start had not arrived.
        var live = new[] { P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe"), P(25288, 30, 40, @"C:\Program Files\Git\usr\bin\bash.exe"), P(1000, 25288, 50, @"C:\OpWarden\op.exe") };
        var stale = X(25288, 17124, 5, 8, @"C:\Tools\monitor-plugin.exe");

        var result = Resolve(live, mapped: [.. live, stale], seededAt: 1);

        Assert.Equal(CallerIdentity.Agent("claude-code"), result.Caller);
        Assert.Equal(["op.exe(1000)", "bash.exe(25288)", "claude.exe(30)"], result.Chain);
    }

    [Fact]
    public void An_exited_parent_whose_start_has_not_arrived_makes_the_walk_wait_not_guess()
    {
        // The exec-retired shell (15468) has exited and its start is still in ETW's buffers;
        // an earlier holder of 15468, long gone, must not stand in for it.
        var live = new[] { P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe"), P(16020, 15468, 45, @"C:\Program Files\Git\usr\bin\bash.exe"), P(1000, 16020, 50, @"C:\OpWarden\op.exe") };
        var stale = X(15468, 17124, 5, 8, @"C:\Tools\monitor-plugin.exe");
        var resolver = Resolver(live, out var map, mapped: [.. live, stale], seededAt: 1);

        var waiting = resolver.Resolve(1000);
        Assert.True(waiting.AwaitsEvents);
        Assert.Equal(CallerIdentity.Unknown, waiting.Caller);
        Assert.Equal(CallerResolution.AwaitingMarker, waiting.Chain[^1]);

        map.Record(X(15468, 30, 42, 46, @"C:\Program Files\Git\usr\bin\bash.exe"));
        var resolved = resolver.Resolve(1000);

        Assert.Equal(CallerIdentity.Agent("claude-code"), resolved.Caller);
        Assert.False(resolved.AwaitsEvents);
    }

    [Fact]
    public void An_exited_parent_whose_exit_has_not_arrived_makes_the_walk_wait()
    {
        var live = new[] { P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe"), P(1000, 40, 50, @"C:\OpWarden\op.exe") };

        var result = Resolve(live, exitedButMapped: [P(40, 30, 40, @"C:\Program Files\Git\usr\bin\bash.exe")], seededAt: 1);

        Assert.True(result.AwaitsEvents);
    }

    [Fact]
    public void A_missing_parent_older_than_the_snapshot_ends_the_walk_without_waiting()
    {
        var live = new[] { P(10, 0, 10, Explorer), P(1000, 40, 50, @"C:\OpWarden\op.exe") };

        var result = Resolve(live, seededAt: 100);

        Assert.False(result.AwaitsEvents);
        Assert.Equal("(end: no provable parent)", result.Chain[^1]);
    }

    [Fact]
    public void Without_the_map_the_same_exited_parent_leaves_the_caller_unknown()
    {
        var live = new[] { P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe"), P(1000, 40, 50, @"C:\OpWarden\op.exe") };

        Assert.Equal(CallerIdentity.Unknown, Resolve(live, mapped: []).Caller);
    }

    [Fact]
    public void A_claude_exe_with_another_signer_ends_the_walk_as_unknown()
    {
        // Walking past it would reach explorer and hand an impostor, or a real agent whose
        // signature could not be read, the interactive user's rules.
        var result = Resolve([P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\Temp\claude.exe"), P(1000, 30, 50, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
        Assert.Equal("(end: not signed by Anthropic, PBC)", result.Chain[^1]);
    }

    [Fact]
    public void An_unsigned_agent_host_matches_on_its_name_alone()
    {
        Assert.Equal(CallerIdentity.Agent("opencode"), Resolve([P(10, 0, 10, Explorer), P(30, 10, 30, @"C:\scoop\opencode.exe"), P(1000, 30, 50, @"C:\OpWarden\op.exe")]).Caller);
    }

    [Fact]
    public void Reaching_the_logon_shell_with_no_agent_is_the_interactive_user()
    {
        var result = Resolve([P(10, 0, 10, Explorer), P(20, 10, 20, @"C:\Program Files\WindowsApps\Terminal\WindowsTerminal.exe"), P(30, 20, 30, @"C:\Program Files\PowerShell\pwsh.exe"), P(1000, 30, 50, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.InteractiveUser, result.Caller);
    }

    [Fact]
    public void Windows_Terminal_started_through_the_shell_host_is_the_interactive_user()
    {
        // The shape measured on a real machine: packaged apps hang off sihost, not explorer.
        var result = Resolve([P(10, 0, 10, ShellHost), P(20, 10, 20, @"C:\Program Files\WindowsApps\Terminal\WindowsTerminal.exe"), P(30, 20, 30, @"C:\Program Files\PowerShell\pwsh.exe"), P(1000, 30, 50, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.InteractiveUser, result.Caller);
    }

    [Fact]
    public void A_sihost_exe_outside_the_system_directory_is_no_logon_shell()
    {
        var result = Resolve([P(10, 0, 10, @"C:\Temp\sihost.exe"), P(1000, 10, 50, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
    }

    [Fact]
    public void An_explorer_in_another_session_is_not_this_user_s_shell()
    {
        var result = Resolve([new ProcessEntry(10, 0, 10, Explorer, SessionId: 7), P(1000, 10, 50, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
    }

    [Fact]
    public void A_live_parent_younger_than_its_child_is_a_reused_id_and_ends_the_walk()
    {
        var result = Resolve(live: [P(10, 0, 10, Explorer), P(30, 10, 900, @"C:\impostor.exe"), P(1000, 30, 50, @"C:\OpWarden\op.exe")], mapped: []);

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
        Assert.Contains("(end: no provable parent)", result.Chain);
    }

    [Fact]
    public void A_parent_loop_cannot_form_because_a_parent_must_start_first()
    {
        var result = Resolve([P(1000, 2000, 50, @"C:\OpWarden\op.exe"), P(2000, 1000, 40, @"C:\loop.exe")], mapped: [P(1000, 2000, 50, @"C:\OpWarden\op.exe"), P(2000, 1000, 40, @"C:\loop.exe"), P(1000, 2000, 30, @"C:\OpWarden\op.exe")]);

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
    }
}

public sealed class EventCatchUpTests
{
    private const int Session = 1;
    private static readonly string Explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
    private static readonly AgentHost[] Agents = [new("claude-code", "claude.exe", null)];

    // The exec-retired shell (40) is not in the map yet; the event source delivers it on flush.
    private static (CallerResolver Resolver, ProcessMap Map) Retired()
    {
        var live = new[] { new ProcessEntry(10, 0, 10, Explorer, Session), new ProcessEntry(30, 10, 30, @"C:\Users\u\.local\bin\claude.exe", Session), new ProcessEntry(1000, 40, 50, @"C:\OpWarden\op.exe", Session) };
        var map = new ProcessMap();
        map.Seed(live, takenAt: 1);
        var byId = live.ToDictionary(p => p.ProcessId);
        return (new CallerResolver(map, Agents, _ => null, id => byId.TryGetValue(id, out var p) ? p : null, () => Session), map);
    }

    [Fact]
    public async Task Late_events_delivered_by_a_flush_resolve_the_caller()
    {
        var (resolver, map) = Retired();
        var flushes = 0;

        var result = await EventCatchUp.ResolveAsync(() => resolver.Resolve(1000), () =>
        {
            if (++flushes == 2) map.Record(new ProcessEntry(40, 30, 40, @"C:\Program Files\Git\usr\bin\bash.exe", Session, ExitTime: 55));
        });

        Assert.Equal(CallerIdentity.Agent("claude-code"), result.Caller);
        Assert.False(result.AwaitsEvents);
    }

    [Fact]
    public async Task Events_that_never_arrive_end_the_walk_as_unknown_within_the_budget()
    {
        var (resolver, _) = Retired();

        var result = await EventCatchUp.ResolveAsync(() => resolver.Resolve(1000), () => { }, TimeSpan.FromMilliseconds(50));

        Assert.Equal(CallerIdentity.Unknown, result.Caller);
        Assert.False(result.AwaitsEvents);
        Assert.Equal("(end: process events did not arrive in time)", result.Chain[^1]);
    }

    [Fact]
    public async Task Without_an_event_session_the_walk_does_not_wait()
    {
        var (resolver, _) = Retired();

        var result = await EventCatchUp.ResolveAsync(() => resolver.Resolve(1000), flush: null);

        Assert.Equal("(end: no provable parent)", result.Chain[^1]);
    }
}

/// <summary>
/// The Win32 pieces against the real machine: no fakes, only processes this test starts.
/// </summary>
public sealed class LiveCallerTests
{
    [Fact]
    public void The_live_walk_finds_a_real_child_and_its_real_parent()
    {
        using var child = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 5 127.0.0.1 > nul") { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            var resolver = new CallerResolver(new ProcessMap(), [], _ => null, LiveProcesses.Find, () => LiveProcesses.ConsoleSessionId);

            var result = resolver.Resolve(child.Id);

            Assert.Equal($"cmd.exe({child.Id})", result.Chain[0]);
            Assert.Contains($"({Environment.ProcessId})", result.Chain[1], StringComparison.Ordinal);
        }
        finally
        {
            child.Kill();
        }
    }

    [Fact]
    public void The_snapshot_describes_this_process()
    {
        var self = Assert.Single(LiveProcesses.Snapshot(), p => p.ProcessId == Environment.ProcessId);

        Assert.True(self.CreateTime > 0);
        Assert.Equal(Environment.ProcessPath, self.ImagePath, ignoreCase: true);
    }

    [Fact]
    public void Authenticode_names_a_real_signer_and_refuses_an_unsigned_file()
    {
        Assert.Null(Authenticode.SignerOf(BuiltExecutables.Probe));

        var op = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Select(d => Path.Combine(d, "op.exe")).FirstOrDefault(p => File.Exists(p) && FileVersionInfo.GetVersionInfo(p).ProductName != "OpWarden");
        Assert.SkipWhen(op is null, "No op CLI on PATH to check a third-party signature against.");

        Assert.Equal("Agilebits", Authenticode.SignerOf(op!));
    }

    /// <summary>
    /// Passes either way, because whether Windows grants the session depends on who runs
    /// the tests: with access, a real child's start must land in the map with its real
    /// parent; without, the failure must say why (REQ-CALL-20).
    /// </summary>
    [Fact]
    public async Task The_process_event_session_records_real_starts_or_says_why_not()
    {
        var map = new ProcessMap();
        using var session = ProcessEventSession.TryStart(map, out var failure);
        if (session is null)
        {
            TestContext.Current.SendDiagnosticMessage($"No process-event session: {failure}");
            Assert.False(string.IsNullOrWhiteSpace(failure));
            return;
        }

        TestContext.Current.SendDiagnosticMessage("Process-event session running; checking a real start.");

        await Task.Delay(1000, TestContext.Current.CancellationToken);
        using var child = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0") { UseShellExecute = false, CreateNoWindow = true })!;
        await child.WaitForExitAsync(TestContext.Current.CancellationToken);

        for (var i = 0; i < 50 && map.Find(child.Id, long.MaxValue) is null; i++) await Task.Delay(100, TestContext.Current.CancellationToken);

        var entry = map.Find(child.Id, long.MaxValue);
        Assert.NotNull(entry);
        Assert.Equal(Environment.ProcessId, entry.Value.ParentId);
        Assert.EndsWith("cmd.exe", entry.Value.ImagePath, StringComparison.OrdinalIgnoreCase);
    }
}
