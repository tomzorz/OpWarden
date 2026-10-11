using System.Text;
using System.Windows;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;
using OpWarden.SessionAgent;

namespace OpWarden.Tests;

/// <summary>
/// The session agent's logic that needs no desktop: how toasts fold a burst of reads
/// together (REQ-RULE-39), which window a read came from and where its toast goes
/// (REQ-RULE-41 to REQ-RULE-44), how the audit window follows the log, and the agent's
/// arguments.
/// </summary>
public sealed class SessionAgentLogicTests : IDisposable
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly DateTimeOffset Noon = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    // A 1920 x 1080 monitor at 100 % with the taskbar at the bottom, and a toast's
    // transparent inset as ToastWindow.xaml sets it.
    private static readonly MonitorArea Screen = new(new Rect(0, 0, 1920, 1040), 1.0);
    private static readonly Thickness Inset = new(12, 6, 12, 6);

    private readonly DirectoryInfo _scratch = Directory.CreateTempSubdirectory("opwarden-agent-");

    public void Dispose() => _scratch.Delete(recursive: true);

    private static ReadAllowed Read(string key, ReadSource source = ReadSource.Rule, double seconds = 0, CallerIdentity? caller = null, DateTimeOffset? expires = null) =>
        new(caller ?? Claude, "read", [new SecretPath("Infra", "tofu-state", key)], source, expires, Noon.AddSeconds(seconds), []);

    [Fact]
    public void Two_reads_a_moment_apart_share_one_toast()
    {
        var toast = ReadToast.Start(Read("age key")).Absorb(Read("passphrase", seconds: 1.5));

        Assert.NotNull(toast);
        Assert.Equal("claude-code read 2 secrets", toast.Title);
        Assert.Equal(["Infra / tofu-state / age key", "Infra / tofu-state / passphrase"], toast.Lines);
    }

    [Fact]
    public void A_single_read_names_its_secret_on_a_line_of_its_own()
    {
        var toast = ReadToast.Start(Read("passphrase"));

        Assert.Equal("claude-code read a secret", toast.Title);
        Assert.Equal(["Infra / tofu-state / passphrase"], toast.Lines);
    }

    [Fact]
    public void Another_caller_another_source_or_a_late_read_starts_a_new_toast()
    {
        var toast = ReadToast.Start(Read("age key"));

        Assert.Null(toast.Absorb(Read("passphrase", caller: CallerIdentity.InteractiveUser)));
        Assert.Null(toast.Absorb(Read("passphrase", source: ReadSource.Cache)));
        Assert.Null(toast.Absorb(Read("passphrase", seconds: ReadToast.BurstWindow.TotalSeconds + 1)));
    }

    [Fact]
    public void The_same_secret_read_twice_is_listed_once()
    {
        var toast = ReadToast.Start(Read("passphrase")).Absorb(Read("passphrase", seconds: 1));

        Assert.Equal("claude-code read a secret", toast!.Title);
        Assert.Single(toast.Lines);
    }

    [Fact]
    public void A_cached_read_says_how_long_the_cache_keeps_it()
    {
        var toast = ReadToast.Start(Read("passphrase", ReadSource.Cache, expires: Noon.AddHours(7).AddMinutes(30)));

        Assert.Contains("7 h 30 min left", toast.Footer(Noon), StringComparison.Ordinal);
        Assert.Contains("Windows Hello", ReadToast.Start(Read("passphrase")).Footer(Noon), StringComparison.Ordinal);
    }

    [Fact]
    public void The_origin_window_is_the_frontmost_window_of_the_nearest_ancestor_that_has_one()
    {
        // bash owns no window; Windows Terminal above it owns two, and another app's
        // window is in front of both.
        ProcessIdentity bash = new(40, 400), terminal = new(20, 200);
        CandidateWindow[] frontToBack = [new(0x30, 99, 990), new(0x10, 20, 200), new(0x11, 20, 200)];

        Assert.Equal(0x10, OriginWindow.Choose([bash, terminal], frontToBack));
    }

    [Fact]
    public void A_window_whose_owner_started_at_another_time_is_not_the_ancestor_s()
    {
        // The terminal exited and a later process got its ID; that process's window must
        // not draw the toast.
        ProcessIdentity terminal = new(20, 200), editor = new(10, 100);
        CandidateWindow[] frontToBack = [new(0x10, 20, 250), new(0x20, 10, 100)];

        Assert.Equal(0x20, OriginWindow.Choose([terminal, editor], frontToBack));
        Assert.Equal(0, OriginWindow.Choose([terminal], frontToBack));
    }

    [Fact]
    public void A_toast_sits_on_its_window_at_the_window_s_width_with_no_gap()
    {
        var origin = new OriginGeometry(new Rect(300, 400, 800, 500), Screen);

        var width = ToastPlacement.WidthOnWindow(origin, Inset);
        var corner = Assert.Single(ToastPlacement.OnWindow(origin, [new Size(width, 112)], Inset)!);

        // The frame is the window less its inset: it starts at the window's left edge and
        // ends on its top edge.
        Assert.Equal(800 + 24, width);
        Assert.Equal(300, corner.X + 12);
        Assert.Equal(400, corner.Y + 112 - 6);
    }

    [Fact]
    public void Older_toasts_stack_above_the_newest_one_on_the_window()
    {
        var origin = new OriginGeometry(new Rect(300, 600, 800, 300), Screen);

        var corners = ToastPlacement.OnWindow(origin, [new Size(824, 112), new Size(824, 132)], Inset)!;

        Assert.Equal(600, corners[0].Y + 112 - 6);
        Assert.Equal(corners[0].Y, corners[1].Y + 132);
    }

    [Fact]
    public void A_window_narrower_than_a_toast_gets_one_centred_over_it()
    {
        var origin = new OriginGeometry(new Rect(500, 400, 200, 300), Screen);

        var width = ToastPlacement.WidthOnWindow(origin, Inset);
        var corner = Assert.Single(ToastPlacement.OnWindow(origin, [new Size(width, 112)], Inset)!);

        Assert.Equal(ToastPlacement.NarrowestFrameOnWindow + 24, width);
        Assert.Equal(600, corner.X + 12 + (ToastPlacement.NarrowestFrameOnWindow / 2));
    }

    [Fact]
    public void A_toast_on_a_window_partly_off_screen_stays_in_the_work_area()
    {
        var origin = new OriginGeometry(new Rect(-200, 400, 600, 300), Screen);

        var corner = Assert.Single(ToastPlacement.OnWindow(origin, [new Size(ToastPlacement.WidthOnWindow(origin, Inset), 112)], Inset)!);

        Assert.Equal(0, corner.X + 12);
    }

    [Theory]
    [InlineData(1040)] // maximized: the work area
    [InlineData(1080)] // full screen: the whole monitor, taskbar included
    public void A_window_with_no_room_above_gets_its_toasts_in_its_top_right_corner(double height)
    {
        var origin = new OriginGeometry(new Rect(0, 0, 1920, height), Screen);

        Assert.Null(ToastPlacement.OnWindow(origin, [new Size(1944, 112)], Inset));
        var corners = ToastPlacement.InCorner(origin, [new Size(400, 112), new Size(400, 112)], Inset);

        // The frame keeps 16 DIPs from the top and right edges; the next toast goes below.
        Assert.Equal(1920 - ToastPlacement.CornerInset, corners[0].X + 400 - 12);
        Assert.Equal(ToastPlacement.CornerInset, corners[0].Y + 6);
        Assert.Equal(corners[0].Y + 112, corners[1].Y);
    }

    [Fact]
    public void A_window_snapped_to_the_top_gets_its_toasts_in_its_own_corner()
    {
        var origin = new OriginGeometry(new Rect(0, 0, 960, 1040), Screen);

        var corner = Assert.Single(ToastPlacement.InCorner(origin, [new Size(400, 112)], Inset));

        Assert.Equal(960 - ToastPlacement.CornerInset, corner.X + 400 - 12);
    }

    [Fact]
    public void DIPs_turn_into_pixels_at_the_monitor_s_scale()
    {
        var origin = new OriginGeometry(new Rect(600, 900, 1200, 600), new MonitorArea(new Rect(0, 0, 2880, 1680), 1.5));

        var width = ToastPlacement.WidthOnWindow(origin, Inset);
        var corner = Assert.Single(ToastPlacement.OnWindow(origin, [new Size(width, 112)], Inset)!);

        Assert.Equal(800 + 24, width);
        Assert.Equal(600, corner.X + (12 * 1.5));
        Assert.Equal(900, corner.Y + ((112 - 6) * 1.5));
    }

    [Fact]
    public void Toasts_without_an_origin_window_stack_up_from_above_the_notification_area()
    {
        var corners = ToastPlacement.AboveNotificationArea(Screen, [new Size(400, 112), new Size(400, 90)]);

        Assert.Equal(new Point(1520, 928), corners[0]);
        Assert.Equal(new Point(1520, 838), corners[1]);
    }

    [Fact]
    public void The_audit_reader_returns_only_what_was_appended_and_waits_for_a_whole_line()
    {
        var log = Path.Combine(_scratch.FullName, "audit.jsonl");
        File.WriteAllText(log, Line("invocation", "allow") + "\n");
        var reader = new AuditLogReader(log);

        Assert.Single(reader.ReadNew());
        Assert.Empty(reader.ReadNew());

        var next = Line("invocation", "deny");
        File.AppendAllText(log, next[..20]);
        Assert.Empty(reader.ReadNew());
        File.AppendAllText(log, next[20..] + "\n");

        var row = Assert.Single(reader.ReadNew());
        Assert.Equal("Deny", row.Verdict);
        Assert.True(row.IsProblem);
        Assert.Equal("Infra / tofu-state / passphrase", row.Secret);
        Assert.Equal(["op.exe(10)", "claude.exe(5)"], row.Chain);
    }

    [Fact]
    public void The_audit_reader_starts_over_when_the_log_was_begun_anew()
    {
        var log = Path.Combine(_scratch.FullName, "audit.jsonl");
        File.WriteAllText(log, Line("invocation", "allow") + "\n" + Line("invocation", "allow") + "\n");
        var reader = new AuditLogReader(log);
        Assert.Equal(2, reader.ReadNew().Count);

        File.WriteAllText(log, Line("integrity-failure", null) + "\n");

        var row = Assert.Single(reader.ReadNew());
        Assert.Equal("integrity-failure", row.Event);
    }

    [Fact]
    public void A_rule_change_describes_the_rule()
    {
        var row = AuditLogReader.Parse("""{"timestamp":"2026-10-10T12:00:00+00:00","event":"rule-change","source":"management","rule":{"caller":{"name":"claude-code"},"action":"Read","vault":"Infra","verdict":"Allow"},"detail":"The management window stored this rule."}""");

        Assert.Equal("The management window stored this rule. (allow caller claude-code, action Read, vault Infra)", row!.Detail);
    }

    [Fact]
    public void A_line_that_is_not_an_entry_is_skipped()
    {
        Assert.Null(AuditLogReader.Parse("{ not json"));
        Assert.Null(AuditLogReader.Parse(""));
    }

    [Fact]
    public void The_agent_reads_its_pipes_and_the_windows_to_open()
    {
        var options = AgentOptions.Parse(["--pipe", "a", "--manage-pipe", "m", "--open", "audit", "--open", "status"]);

        Assert.Equal("a", options.AgentPipe);
        Assert.Equal("m", options.ManagementPipe);
        Assert.False(options.Manage);
        Assert.Equal(["audit", "status"], options.Open);
        Assert.Equal("--pipe a --manage-pipe m", options.PipeArguments);
        Assert.True(AgentOptions.Parse(["--manage"]).Manage);
    }

    private static string Line(string eventName, string? verdict)
    {
        var builder = new StringBuilder();
        builder.Append($$"""{"timestamp":"2026-10-10T12:00:00+00:00","event":"{{eventName}}","caller":{"name":"claude-code"},"callerChain":["op.exe(10)","claude.exe(5)"],"command":"read","arguments":["read","op://Infra/tofu-state/passphrase"],"path":{"vault":"Infra","item":"tofu-state","key":"passphrase"}""");
        if (verdict is not null) builder.Append($$""","verdict":"{{char.ToUpperInvariant(verdict[0])}}{{verdict[1..]}}","reason":"rule" """.TrimEnd());
        builder.Append('}');
        return builder.ToString();
    }
}
