using System.Text.Json;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Storage;
using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class StorageTests : IDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("opwarden-storage-");

    public void Dispose() => _directory.Delete(recursive: true);

    private string File(string name) => Path.Combine(_directory.FullName, name);

    [Fact]
    public void A_missing_rule_store_opens_empty()
    {
        Assert.Empty(RuleStore.Open(File("rules.json")).Current.Rules);
    }

    [Fact]
    public void Rules_survive_a_reopen()
    {
        var rule = new Rule(CallerIdentity.Agent("claude-code"), OpAction.Read, "V", null, "K", Verdict.Allow, CacheTtl.OneHour);
        RuleStore.Open(File("rules.json")).Add([rule, new Rule(null, null, "Prod", null, null, Verdict.Deny)]);

        var reopened = RuleStore.Open(File("rules.json")).Current.Rules;

        Assert.Equal(2, reopened.Count);
        Assert.Equal(rule, reopened[0]);
    }

    [Fact]
    public void A_corrupt_rule_store_refuses_to_open_rather_than_start_empty()
    {
        System.IO.File.WriteAllText(File("rules.json"), "{ not json");

        Assert.ThrowsAny<JsonException>(() => RuleStore.Open(File("rules.json")));
    }

    [Fact]
    public void A_rule_store_of_another_version_refuses_to_open()
    {
        System.IO.File.WriteAllText(File("rules.json"), """{"version":99,"rules":[],"promptAlwaysVaults":[]}""");

        Assert.Throws<InvalidDataException>(() => RuleStore.Open(File("rules.json")));
    }

    [Fact]
    public void Alias_pairs_survive_a_reopen()
    {
        var store = new AliasStore();
        store.Add(new AliasPair(AliasKind.Vault, "Prod", "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
        new AliasFile(File("aliases.json")).Save(store);

        var loaded = new AliasFile(File("aliases.json")).Load();

        Assert.Equal(["Prod"], loaded.NamesFor(AliasKind.Vault, "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
    }

    [Fact]
    public void The_audit_log_appends_one_utc_json_line_per_entry_without_empty_fields()
    {
        var log = new AuditLog(File("audit.jsonl"));
        log.Append(new AuditEntry(new DateTimeOffset(2026, 10, 3, 14, 0, 0, TimeSpan.FromHours(2)), "invocation", CallerIdentity.InteractiveUser, Action: OpAction.Meta, Verdict: Verdict.Allow, Reason: VerdictReason.QueueFull));
        log.Append(new AuditEntry(DateTimeOffset.UtcNow, "rule-change", Source: RuleChangeSource.Prompt));

        var lines = System.IO.File.ReadAllLines(File("audit.jsonl"));

        Assert.Equal(2, lines.Length);
        Assert.Contains("\"timestamp\":\"2026-10-03T12:00:00+00:00\"", lines[0], StringComparison.Ordinal);
        Assert.Contains("\"reason\":\"queue-full\"", lines[0], StringComparison.Ordinal);
        Assert.DoesNotContain("null", lines[0], StringComparison.Ordinal);
        Assert.Contains("\"source\":\"prompt\"", lines[1], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(OpAction.Write, "item|create|password=hunter2|--title=T", "item|create|password=<redacted>|--title=T")]
    [InlineData(OpAction.Manage, "user|edit|name=Bob", "user|edit|name=<redacted>")]
    [InlineData(OpAction.Read, "item|get|I|--fields|label=password", "item|get|I|--fields|label=password")]
    [InlineData(OpAction.Read, "read|op://v/i/f|--session|t0k3n", "read|op://v/i/f|--session|<redacted>")]
    [InlineData(OpAction.Meta, "whoami|--session=t0k3n", "whoami|--session=<redacted>")]
    [InlineData(OpAction.Write, "item|edit|I|Login.password[password]=x", "item|edit|I|Login.password[password]=<redacted>")]
    public void Redacts_assignment_values_and_session_tokens(OpAction action, string arguments, string expected)
    {
        Assert.Equal(expected.Split('|'), AuditLog.RedactArguments(arguments.Split('|'), action));
    }
}
