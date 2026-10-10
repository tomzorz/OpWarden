using System.Text;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;
using OpWarden.SessionAgent;

namespace OpWarden.Tests;

/// <summary>
/// The session agent's logic that needs no desktop: how toasts fold a burst of reads
/// together (REQ-RULE-39), how the audit window follows the log, and the agent's arguments.
/// </summary>
public sealed class SessionAgentLogicTests : IDisposable
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly DateTimeOffset Noon = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    private readonly DirectoryInfo _scratch = Directory.CreateTempSubdirectory("opwarden-agent-");

    public void Dispose() => _scratch.Delete(recursive: true);

    private static ReadAllowed Read(string key, ReadSource source = ReadSource.Rule, double seconds = 0, CallerIdentity? caller = null, DateTimeOffset? expires = null) =>
        new(caller ?? Claude, "read", [new SecretPath("Infra", "tofu-state", key)], source, expires, Noon.AddSeconds(seconds));

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
