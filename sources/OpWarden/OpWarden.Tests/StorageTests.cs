using System.Reflection;
using System.Text;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Integrity;
using OpWarden.Broker.Storage;
using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class StorageTests : IDisposable
{
    private static readonly Rule AllowRead = new(CallerIdentity.Agent("claude-code"), OpAction.Read, "V", null, "K", Verdict.Allow, CacheTtl.OneHour);
    private static readonly Rule DenyProd = new(null, null, "Prod", null, null, Verdict.Deny);

    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("opwarden-storage-");
    private readonly List<string> _alarms = [];

    public void Dispose() => _directory.Delete(recursive: true);

    private string File(string name) => Path.Combine(_directory.FullName, name);

    private IntegrityVault Vault() => IntegrityVault.Open(File("integrity.vault"));

    private RuleStore OpenRules(IntegrityVault? vault = null) => RuleStore.Open(File("rules.json"), vault ?? Vault(), _alarms.Add);

    // ---- rule store -------------------------------------------------------------

    [Fact]
    public void A_new_rule_store_opens_empty_and_quietly()
    {
        Assert.Empty(OpenRules().Current.Rules);
        Assert.Empty(_alarms);
    }

    [Fact]
    public void Rules_survive_a_reopen()
    {
        OpenRules().Add([AllowRead, DenyProd]);

        var reopened = OpenRules().Current.Rules;

        Assert.Equal([AllowRead, DenyProd], reopened);
        Assert.Empty(_alarms);
    }

    [Fact]
    public void A_hand_edited_rule_store_is_quarantined_and_the_broker_starts_with_no_rules()
    {
        OpenRules().Add([DenyProd]);
        var text = System.IO.File.ReadAllText(File("rules.json"));
        System.IO.File.WriteAllText(File("rules.json"), text.Replace("\"Deny\"", "\"Allow\"", StringComparison.Ordinal));

        var reopened = OpenRules();

        Assert.Empty(reopened.Current.Rules);
        Assert.Contains(_alarms, a => a.Contains("seal does not match", StringComparison.Ordinal));
        Assert.Single(_directory.GetFiles("rules.json.tampered-*"));
    }

    [Fact]
    public void An_older_copy_of_the_rule_store_put_back_is_refused()
    {
        var store = OpenRules();
        store.Add([AllowRead]);
        var older = System.IO.File.ReadAllBytes(File("rules.json"));
        store.Add([DenyProd]);
        System.IO.File.WriteAllBytes(File("rules.json"), older);

        Assert.Empty(OpenRules().Current.Rules);
        Assert.Contains(_alarms, a => a.Contains("earlier copy", StringComparison.Ordinal));
    }

    [Fact]
    public void A_deleted_rule_store_is_noticed()
    {
        OpenRules().Add([DenyProd]);
        System.IO.File.Delete(File("rules.json"));

        Assert.Empty(OpenRules().Current.Rules);
        Assert.Contains(_alarms, a => a.Contains("missing", StringComparison.Ordinal));
    }

    [Fact]
    public void A_crash_between_writing_the_file_and_the_vault_is_not_tampering()
    {
        var vault = Vault();
        OpenRules(vault).Add([DenyProd]);

        // Roll the vault back one generation, as if the broker died after replacing the
        // file and before recording the new generation.
        vault.SetGeneration("rules", vault.Generation("rules") - 1);

        Assert.Equal([DenyProd], OpenRules().Current.Rules);
        Assert.Empty(_alarms);
    }

    [Fact]
    public void Rules_changed_in_broker_memory_are_caught_and_reloaded_from_disk()
    {
        var store = OpenRules();
        store.Add([DenyProd]);

        // Play the attacker with the broker's memory: swap the live rule set for one that
        // allows everything, without going through the store.
        var field = typeof(RuleStore).GetField("_current", BindingFlags.NonPublic | BindingFlags.Instance)!;
        field.SetValue(store, new RuleSet([new Rule(null, null, null, null, null, Verdict.Allow)], []));

        Assert.Equal([DenyProd], store.Current.Rules);
        Assert.Contains(_alarms, a => a.Contains("broker memory", StringComparison.Ordinal));
    }

    // ---- alias file and vault ----------------------------------------------------

    [Fact]
    public void Alias_pairs_survive_a_reopen()
    {
        var vault = Vault();
        var store = new AliasStore();
        store.Add(new AliasPair(AliasKind.Vault, "Prod", "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
        new AliasFile(File("aliases.json"), vault, _alarms.Add).Save(store);

        var loaded = new AliasFile(File("aliases.json"), Vault(), _alarms.Add).Load();

        Assert.Equal(["Prod"], loaded.NamesFor(AliasKind.Vault, "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
    }

    [Fact]
    public void A_forged_alias_pair_is_quarantined()
    {
        var vault = Vault();
        var store = new AliasStore();
        store.Add(new AliasPair(AliasKind.Item, "GitHub", "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
        new AliasFile(File("aliases.json"), vault, _alarms.Add).Save(store);
        var text = System.IO.File.ReadAllText(File("aliases.json"));
        System.IO.File.WriteAllText(File("aliases.json"), text.Replace("GitHub", "Payroll", StringComparison.Ordinal));

        var loaded = new AliasFile(File("aliases.json"), Vault(), _alarms.Add).Load();

        Assert.Empty(loaded.Pairs());
        Assert.Single(_alarms);
    }

    [Fact]
    public void A_vault_that_cannot_be_decrypted_is_tampering()
    {
        Vault();
        var bytes = System.IO.File.ReadAllBytes(File("integrity.vault"));
        bytes[^5] ^= 0xFF;
        System.IO.File.WriteAllBytes(File("integrity.vault"), bytes);

        Assert.Throws<TamperedException>(() => IntegrityVault.Open(File("integrity.vault")));
    }

    [Fact]
    public void The_vault_is_not_stored_in_the_clear()
    {
        var vault = Vault();
        vault.SetGeneration("rules", 42);

        Assert.DoesNotContain("rules", Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(File("integrity.vault"))), StringComparison.Ordinal);
    }

    // ---- audit log ----------------------------------------------------------------

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
