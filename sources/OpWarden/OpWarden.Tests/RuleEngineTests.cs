using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class RuleEngineTests
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly CallerIdentity Codex = CallerIdentity.Agent("codex");
    private static readonly CallerIdentity User = CallerIdentity.InteractiveUser;

    private const string ProdId = "q1w2e3r4t5y6u7i8o9p0a1s2d3";
    private const string DevId = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string GitHubId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string GitHubId2 = "cccccccccccccccccccccccccc";

    private static Rule Allow(CallerIdentity? caller = null, OpAction? action = null, string? vault = null, string? item = null, string? key = null, CacheTtl? grant = null) =>
        new(caller, action, vault, item, key, Verdict.Allow, grant);

    private static Rule Deny(CallerIdentity? caller = null, OpAction? action = null, string? vault = null, string? item = null, string? key = null) =>
        new(caller, action, vault, item, key, Verdict.Deny);

    // One tuple at a time: what the rules alone decide (REQ-RULE-2, REQ-RULE-3, REQ-RULE-4),
    // including unknown fields and case. Expected: allow, deny, or prompt.
    public static TheoryData<string, Rule[], CallerIdentity, OpAction, SecretPath, string> SingleTuples => new()
    {
        { "no rules prompts", [], Claude, OpAction.Read, new("V", "I", "K"), "prompt" },
        { "a wildcard allow allows", [Allow()], Claude, OpAction.Read, new("V", "I", "K"), "allow" },
        { "a wildcard deny denies", [Deny()], Claude, OpAction.Read, new("V", "I", "K"), "deny" },
        { "specific deny beats general allow", [Allow(Claude), Deny(Claude, OpAction.Read, "V")], Claude, OpAction.Read, new("V", "I", "K"), "deny" },
        { "specific allow beats general deny", [Deny(Claude), Allow(Claude, OpAction.Read, "V")], Claude, OpAction.Read, new("V", "I", "K"), "allow" },
        { "a conflicting tie denies", [Allow(Claude, OpAction.Read, vault: "V"), Deny(Claude, OpAction.Read, item: "I")], Claude, OpAction.Read, new("V", "I", "K"), "deny" },
        { "a conflicting tie denies whatever the order", [Deny(Claude, OpAction.Read, item: "I"), Allow(Claude, OpAction.Read, vault: "V")], Claude, OpAction.Read, new("V", "I", "K"), "deny" },
        { "an agreeing tie allows", [Allow(Claude, vault: "V"), Allow(Claude, item: "I")], Claude, OpAction.Read, new("V", "I", "K"), "allow" },
        { "a mismatched pinned field does not apply", [Deny(vault: "Other")], Claude, OpAction.Read, new("V", "I", "K"), "prompt" },
        { "an agent rule does not cover the interactive user", [Allow(Claude)], User, OpAction.Read, new("V", "I", "K"), "prompt" },
        { "an agent rule does not cover another agent", [Allow(Claude)], Codex, OpAction.Read, new("V", "I", "K"), "prompt" },
        { "a read rule does not cover a write", [Allow(action: OpAction.Read)], Claude, OpAction.Write, new("V", "I", "K"), "prompt" },
        { "a fully pinned allow matches exactly", [Allow(Claude, OpAction.Read, "V", "I", "K")], Claude, OpAction.Read, new("V", "I", "K"), "allow" },
        { "a fully pinned allow misses on the key", [Allow(Claude, OpAction.Read, "V", "I", "K")], Claude, OpAction.Read, new("V", "I", "other"), "prompt" },

        // Unknown fields: a deny acts on "could be", an allow needs "is".
        { "deny on a vault covers an unknown vault", [Allow(), Deny(vault: "Prod")], Claude, OpAction.Read, new(null, "I", "K"), "deny" },
        { "allow on a vault does not cover an unknown vault", [Allow(vault: "Dev")], Claude, OpAction.Read, new(null, "I", "K"), "prompt" },
        { "a wildcard allow covers an unknown vault", [Allow(Claude, OpAction.Read)], Claude, OpAction.Read, new(null, null, null), "allow" },
        { "deny on an item covers an unknown item", [Allow(), Deny(item: "I")], Claude, OpAction.Read, new("V", null, null), "deny" },
        { "deny on a key covers an unknown key", [Allow(), Deny(key: "password")], Claude, OpAction.Read, new("V", "I", null), "deny" },
        { "deny on an action covers an unknown action", [Allow(), Deny(action: OpAction.Delete)], Claude, OpAction.Unknown, new("V", "I", "K"), "deny" },
        { "allow on an action does not cover an unknown action", [Allow(action: OpAction.Read)], Claude, OpAction.Unknown, new("V", "I", "K"), "prompt" },
        { "a wildcard action covers an unknown action", [Allow(Claude)], Claude, OpAction.Unknown, new("V", "I", "K"), "allow" },
        { "a possible deny loses to a more specific definite allow", [Deny(Claude, vault: "Prod"), Allow(Claude, OpAction.Read, item: "I", key: "K")], Claude, OpAction.Read, new(null, "I", "K"), "allow" },
        { "a possible allow does not shield from a general deny", [Deny(Claude), Allow(Claude, OpAction.Read, "Dev")], Claude, OpAction.Read, new(null, "I", "K"), "deny" },

        // Keys with and without their section.
        { "deny on a field covers the same field with its section", [Allow(), Deny(key: "password")], Claude, OpAction.Read, new("V", "I", "Login/password"), "deny" },
        { "deny on a sectioned field covers the bare field", [Allow(), Deny(key: "Login/password")], Claude, OpAction.Read, new("V", "I", "password"), "deny" },
        { "allow on a field does not cover it with a section", [Allow(key: "password")], Claude, OpAction.Read, new("V", "I", "Login/password"), "prompt" },
        { "a key that merely ends the same is a different key", [Allow(), Deny(key: "word")], Claude, OpAction.Read, new("V", "I", "password"), "allow" },

        // Names are case-insensitive, as the op CLI resolves them.
        { "deny on a vault ignores case", [Allow(), Deny(vault: "Prod")], Claude, OpAction.Read, new("PROD", "I", "K"), "deny" },
        { "allow on an item ignores case", [Allow(item: "GitHub")], Claude, OpAction.Read, new("V", "github", "K"), "allow" },
        { "deny on a key ignores case", [Allow(), Deny(key: "Password")], Claude, OpAction.Read, new("V", "I", "password"), "deny" },

        // IDs the broker has never seen could be any name.
        { "deny on a vault name covers an unseen vault ID", [Allow(), Deny(vault: "Prod")], Claude, OpAction.Read, new(ProdId, "I", "K"), "deny" },
        { "deny on a vault ID covers a name", [Allow(), Deny(vault: ProdId)], Claude, OpAction.Read, new("Prod", "I", "K"), "deny" },
        { "allow on a vault name does not cover an unseen ID", [Allow(vault: "Prod")], Claude, OpAction.Read, new(ProdId, "I", "K"), "prompt" },
        { "two different names never match", [Allow(), Deny(vault: "Prod")], Claude, OpAction.Read, new("Dev", "I", "K"), "allow" },
        { "two different IDs never match", [Allow(), Deny(vault: ProdId)], Claude, OpAction.Read, new(DevId, "I", "K"), "allow" },
        { "the same ID matches", [Allow(vault: ProdId)], Claude, OpAction.Read, new(ProdId, "I", "K"), "allow" },
    };

    [Theory]
    [MemberData(nameof(SingleTuples))]
    public void Decides_a_single_tuple(string because, Rule[] rules, CallerIdentity caller, OpAction action, SecretPath path, string expected)
    {
        var evaluation = Engine(rules).Evaluate(caller, action, path, [], false);

        Assert.True(Outcome(evaluation) == expected, $"{because}: expected {expected}, got {evaluation}");
    }

    [Fact]
    public void No_rule_prompts_with_every_decision_and_the_tuple()
    {
        var evaluation = Assert.IsType<PromptNeeded>(Engine([]).Evaluate(Claude, OpAction.Read, new("V", "I", "K"), [], false));

        Assert.Equal(PromptOptions.AllDecisions, evaluation.Options);
        Assert.Equal([new RequestTuple(Claude, OpAction.Read, new("V", "I", "K"))], evaluation.Tuples);
    }

    [Fact]
    public void A_rule_verdict_names_the_rule_that_decided()
    {
        var deny = Deny(Claude, OpAction.Read, "V");

        var evaluation = Assert.IsType<RuleVerdict>(Engine([Allow(), deny]).Evaluate(Claude, OpAction.Read, new("V", "I", "K"), [], false));

        Assert.Same(deny, Assert.Single(evaluation.Matches).Rule);
    }

    // ---- aliases (REQ-RULE-16) --------------------------------------------

    [Fact]
    public void A_known_alias_pair_lets_an_allow_by_name_cover_the_id()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Vault, "Prod", ProdId));

        Assert.Equal("allow", Outcome(Engine([Allow(vault: "Prod")], aliases).Evaluate(Claude, OpAction.Read, new(ProdId, "I", "K"), [], false)));
        Assert.Equal("allow", Outcome(Engine([Allow(vault: ProdId)], aliases).Evaluate(Claude, OpAction.Read, new("prod", "I", "K"), [], false)));
    }

    [Fact]
    public void An_id_known_under_another_name_is_a_different_value()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Vault, "Dev", DevId));

        Assert.Equal("allow", Outcome(Engine([Allow(), Deny(vault: "Prod")], aliases).Evaluate(Claude, OpAction.Read, new(DevId, "I", "K"), [], false)));
    }

    [Fact]
    public void A_name_with_two_ids_is_only_possibly_either()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Item, "GitHub", GitHubId1));
        aliases.Add(new AliasPair(AliasKind.Item, "GitHub", GitHubId2));

        Assert.Equal("prompt", Outcome(Engine([Allow(item: GitHubId1)], aliases).Evaluate(Claude, OpAction.Read, new("V", "GitHub", "K"), [], false)));
        Assert.Equal("deny", Outcome(Engine([Allow(), Deny(item: GitHubId1)], aliases).Evaluate(Claude, OpAction.Read, new("V", "GitHub", "K"), [], false)));
    }

    [Fact]
    public void A_rule_pinning_a_name_covers_every_id_known_to_carry_it()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Item, "GitHub", GitHubId1));
        aliases.Add(new AliasPair(AliasKind.Item, "GitHub", GitHubId2));

        Assert.Equal("allow", Outcome(Engine([Allow(item: "GitHub")], aliases).Evaluate(Claude, OpAction.Read, new("V", GitHubId2, "K"), [], false)));
    }

    private const string ApiKeyFieldId = "dddddddddddddddddddddddddd";

    [Fact]
    public void A_deny_on_a_field_label_covers_an_unseen_field_id()
    {
        Assert.Equal("deny", Outcome(Engine([Allow(), Deny(key: "API Key")]).Evaluate(Claude, OpAction.Read, new("V", "I", ApiKeyFieldId), [], false)));
    }

    [Fact]
    public void An_allow_on_a_field_label_covers_the_field_id_once_the_pair_is_known()
    {
        var rules = new[] { Allow(key: "API Key") };
        Assert.Equal("prompt", Outcome(Engine(rules).Evaluate(Claude, OpAction.Read, new("V", "I", ApiKeyFieldId), [], false)));

        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Field, "API Key", ApiKeyFieldId));

        Assert.Equal("allow", Outcome(Engine(rules, aliases).Evaluate(Claude, OpAction.Read, new("V", "I", ApiKeyFieldId), [], false)));
    }

    [Fact]
    public void A_field_alias_under_another_section_is_only_possible()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Field, "API Key", ApiKeyFieldId));

        Assert.Equal("allow", Outcome(Engine([Allow(key: "Login/API Key")], aliases).Evaluate(Claude, OpAction.Read, new("V", "I", "Login/" + ApiKeyFieldId), [], false)));
        Assert.Equal("prompt", Outcome(Engine([Allow(key: "Login/API Key")], aliases).Evaluate(Claude, OpAction.Read, new("V", "I", ApiKeyFieldId), [], false)));
        Assert.Equal("deny", Outcome(Engine([Allow(), Deny(key: "Login/API Key")], aliases).Evaluate(Claude, OpAction.Read, new("V", "I", ApiKeyFieldId), [], false)));
    }

    [Fact]
    public void Vault_and_item_aliases_do_not_mix()
    {
        var aliases = new AliasStore();
        aliases.Add(new AliasPair(AliasKind.Item, "Prod", ProdId));

        Assert.Equal("prompt", Outcome(Engine([Allow(vault: "Prod")], aliases).Evaluate(Claude, OpAction.Read, new(ProdId, "I", "K"), [], false)));
    }

    // ---- unknown caller (REQ-CALL-19) ---------------------------------------

    [Fact]
    public void An_unknown_caller_always_gets_a_once_only_prompt()
    {
        var evaluation = Assert.IsType<PromptNeeded>(Engine([Allow(), Deny(vault: "V")]).Evaluate(CallerIdentity.Unknown, OpAction.Read, new("V", "I", "K"), [], false));

        Assert.Equal(PromptOptions.OnceOnly, evaluation.Options);
    }

    // ---- prompt-always vaults (REQ-RULE-17, REQ-RULE-18) --------------------

    [Theory]
    [InlineData("Secrets", "once")]
    [InlineData("secrets", "once")]
    [InlineData(ProdId, "once")]
    [InlineData(null, "once")]
    [InlineData("Dev", "allow")]
    public void A_prompt_always_vault_prompts_once_only_over_an_allow(string? vault, string expected)
    {
        var engine = new RuleEngine(new RuleSet([Allow()], ["Secrets"]), new AliasStore());

        Assert.Equal(expected, Outcome(engine.Evaluate(Claude, OpAction.Read, new(vault, "I", "K"), [], false)));
    }

    [Fact]
    public void A_deny_rule_outranks_a_prompt_always_vault()
    {
        var engine = new RuleEngine(new RuleSet([Deny(item: "I")], ["Secrets"]), new AliasStore());

        Assert.Equal("deny", Outcome(engine.Evaluate(Claude, OpAction.Read, new("Secrets", "I", "K"), [], false)));
    }

    // ---- run: one tuple per reference (REQ-RULE-13, REQ-RULE-14) -----------

    private static readonly SecretPath DbUser = new("V", "db", "username");
    private static readonly SecretPath DbPassword = new("V", "db", "password");
    private static readonly SecretPath ApiToken = new("Prod", "api", "token");

    [Fact]
    public void A_run_is_allowed_when_every_reference_is()
    {
        var evaluation = Assert.IsType<RuleVerdict>(Engine([Allow(Claude, OpAction.Run, "V")]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser, DbPassword], false));

        Assert.Equal(Verdict.Allow, evaluation.Verdict);
        Assert.Equal([DbUser, DbPassword], evaluation.Matches.Select(m => m.Tuple.Path));
    }

    [Fact]
    public void One_denied_reference_denies_the_run()
    {
        var evaluation = Assert.IsType<RuleVerdict>(Engine([Allow(Claude, OpAction.Run), Deny(Claude, OpAction.Run, "Prod")]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser, ApiToken], false));

        Assert.Equal(Verdict.Deny, evaluation.Verdict);
        Assert.Equal(ApiToken, Assert.Single(evaluation.Matches).Tuple.Path);
    }

    [Fact]
    public void A_run_prompts_for_exactly_the_references_no_rule_settles()
    {
        var evaluation = Assert.IsType<PromptNeeded>(Engine([Allow(Claude, OpAction.Run, "V")]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser, ApiToken], false));

        Assert.Equal(PromptOptions.AllDecisions, evaluation.Options);
        Assert.Equal([ApiToken], evaluation.Tuples.Select(t => t.Path));
        Assert.False(evaluation.ReferencesUnknown);
    }

    [Fact]
    public void Unknown_references_keep_a_run_from_being_allowed()
    {
        var evaluation = Assert.IsType<PromptNeeded>(Engine([Allow(Claude, OpAction.Run)]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser], true));

        Assert.True(evaluation.ReferencesUnknown);
        Assert.Empty(evaluation.Tuples);
    }

    [Fact]
    public void Unknown_references_do_not_soften_a_deny()
    {
        Assert.Equal("deny", Outcome(Engine([Deny(Claude, OpAction.Run, item: "db")]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser], true)));
    }

    [Fact]
    public void A_run_with_only_unknown_references_prompts_even_under_a_wildcard_allow()
    {
        Assert.Equal("prompt", Outcome(Engine([Allow()]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [], true)));
    }

    [Fact]
    public void A_run_with_no_references_is_the_invocation_tuple()
    {
        Assert.Equal("allow", Outcome(Engine([Allow(Claude, OpAction.Run)]).Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [], false)));
    }

    [Fact]
    public void A_run_reference_in_a_prompt_always_vault_prompts_once_only_for_it()
    {
        var engine = new RuleEngine(new RuleSet([Allow()], ["Prod"]), new AliasStore());

        var evaluation = Assert.IsType<PromptNeeded>(engine.Evaluate(Claude, OpAction.Run, SecretPath.Unknown, [DbUser, ApiToken], false));

        Assert.Equal(PromptOptions.OnceOnly, evaluation.Options);
        Assert.Equal([ApiToken], evaluation.Tuples.Select(t => t.Path));
    }

    // ---- cache grants -------------------------------------------------------

    [Theory]
    [InlineData(CacheTtl.EightHours, CacheTtl.FifteenMinutes, CacheTtl.FifteenMinutes)]
    [InlineData(CacheTtl.FifteenMinutes, CacheTtl.EightHours, CacheTtl.FifteenMinutes)]
    [InlineData(CacheTtl.OneHour, null, null)]
    public void Between_equally_specific_allows_the_shorter_grant_wins(CacheTtl? first, CacheTtl? second, CacheTtl? expected)
    {
        var evaluation = Assert.IsType<RuleVerdict>(Engine([Allow(Claude, vault: "V", grant: first), Allow(Claude, item: "I", grant: second)]).Evaluate(Claude, OpAction.Read, new("V", "I", "K"), [], false));

        Assert.Equal(expected, Assert.Single(evaluation.Matches).Rule.CacheGrant);
    }

    [Fact]
    public void A_rule_cannot_pin_the_unknown_caller_or_cache_a_deny()
    {
        Assert.Throws<ArgumentException>(() => new Rule(CallerIdentity.Unknown, null, null, null, null, Verdict.Allow));
        Assert.Throws<ArgumentException>(() => new Rule(null, null, null, null, null, Verdict.Deny, CacheTtl.OneHour));
    }

    private static RuleEngine Engine(Rule[] rules, AliasStore? aliases = null) => new(new RuleSet(rules, []), aliases ?? new AliasStore());

    private static string Outcome(Evaluation evaluation) => evaluation switch
    {
        RuleVerdict { Verdict: Verdict.Allow } => "allow",
        RuleVerdict { Verdict: Verdict.Deny } => "deny",
        PromptNeeded { Options: PromptOptions.OnceOnly } => "once",
        PromptNeeded => "prompt",
        _ => throw new ArgumentOutOfRangeException(nameof(evaluation), evaluation, null),
    };
}
