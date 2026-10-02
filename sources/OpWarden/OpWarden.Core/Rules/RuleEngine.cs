namespace OpWarden.Core.Rules;

/// <summary>
/// Which decisions a prompt offers.
/// </summary>
public enum PromptOptions
{
    /// <summary>
    /// All four decisions (REQ-RULE-6).
    /// </summary>
    AllDecisions,

    /// <summary>
    /// <c>allow-once</c> and <c>disallow-once</c> only: an unknown caller (REQ-CALL-19)
    /// or a <c>prompt-always</c> vault (REQ-RULE-18).
    /// </summary>
    OnceOnly,
}

/// <summary>
/// The outcome of evaluating one invocation against the rules.
/// </summary>
public abstract record Evaluation;

/// <summary>
/// Rules decided the invocation without a prompt (REQ-RULE-3). An allow lists the rule
/// for every tuple; a deny lists the rule that denied.
/// </summary>
public sealed record RuleVerdict(Verdict Verdict, IReadOnlyList<RuleMatch> Matches) : Evaluation;

/// <summary>
/// The interactive user decides (REQ-RULE-4). <see cref="Tuples"/> are the tuples no
/// rule settled; for a <c>run</c> they are the secret references (REQ-RULE-14).
/// </summary>
public sealed record PromptNeeded(PromptOptions Options, IReadOnlyList<RequestTuple> Tuples, bool ReferencesUnknown) : Evaluation;

public sealed record RuleMatch(RequestTuple Tuple, Rule Rule);

/// <summary>
/// Evaluates invocations against a rule set (spec section 7). Pure: the same rules,
/// aliases and invocation always give the same evaluation.
/// </summary>
/// <remarks>
/// Order of precedence, first match wins:
/// <code>
///   unknown caller ............................ prompt, once-only   REQ-CALL-19
///   a tuple denied by a rule .................. deny                REQ-RULE-2, 13
///   a tuple in a prompt-always vault .......... prompt, once-only   REQ-RULE-18, 26
///   a tuple no rule settles, or unknown refs .. prompt              REQ-RULE-4, 14, 27
///   every tuple allowed ....................... allow               REQ-RULE-3
/// </code>
/// A deny rule outranks a <c>prompt-always</c> vault: the prompt could only offer an
/// <c>allow-once</c> that the standing deny already refuses.
/// </remarks>
public sealed class RuleEngine(RuleSet rules, AliasStore aliases)
{
    public Evaluation Evaluate(CallerIdentity caller, OpAction action, SecretPath path, IReadOnlyList<SecretPath> references, bool referencesUnknown)
    {
        // REQ-RULE-13: a run is one tuple per secret reference. A run with no references
        // at all resolves nothing and is the one tuple of the invocation itself.
        var perReference = action == OpAction.Run && (references.Count > 0 || referencesUnknown);
        IReadOnlyList<RequestTuple> tuples = perReference
            ? [.. references.Select(reference => new RequestTuple(caller, action, reference))]
            : [new RequestTuple(caller, action, path)];
        var openReferences = perReference && referencesUnknown;

        if (caller.IsUnknown) return new PromptNeeded(PromptOptions.OnceOnly, tuples, openReferences);

        var outcomes = tuples.Select(tuple => (Tuple: tuple, Rule: Match(tuple), PromptAlways: InPromptAlwaysVault(tuple))).ToList();

        var denied = outcomes.FirstOrDefault(o => o.Rule?.Verdict == Verdict.Deny);
        if (denied.Rule is not null) return new RuleVerdict(Verdict.Deny, [new RuleMatch(denied.Tuple, denied.Rule)]);

        var promptAlways = outcomes.Where(o => o.PromptAlways).Select(o => o.Tuple).ToList();
        if (promptAlways.Count > 0) return new PromptNeeded(PromptOptions.OnceOnly, promptAlways, openReferences);

        var unsettled = outcomes.Where(o => o.Rule is null).Select(o => o.Tuple).ToList();
        if (unsettled.Count > 0 || openReferences) return new PromptNeeded(PromptOptions.AllDecisions, unsettled, openReferences);

        return new RuleVerdict(Verdict.Allow, [.. outcomes.Select(o => new RuleMatch(o.Tuple, o.Rule!))]);
    }

    /// <summary>
    /// The rule that decides one tuple, or null when none does (REQ-RULE-2). A deny
    /// rule applies when every field could match; an allow rule only when every field
    /// does. The most specific applicable rule wins, and deny wins a tie.
    /// </summary>
    internal Rule? Match(RequestTuple tuple)
    {
        Rule? best = null;
        foreach (var rule in rules.Rules)
        {
            var match = MatchRule(rule, tuple);
            var applies = rule.Verdict == Verdict.Deny ? match != FieldMatch.No : match == FieldMatch.Definite;
            if (!applies) continue;

            if (best is null || Outranks(rule, best)) best = rule;
        }

        return best;
    }

    /// <summary>
    /// Specificity first, then deny over allow (REQ-RULE-2). Between two equally
    /// specific allows, the shorter cache grant wins, so a tie never caches longer
    /// than one of the user's rules said (REQ-RULE-28).
    /// </summary>
    private static bool Outranks(Rule candidate, Rule best)
    {
        if (candidate.Specificity != best.Specificity) return candidate.Specificity > best.Specificity;
        if (candidate.Verdict != best.Verdict) return candidate.Verdict == Verdict.Deny;
        return GrantRank(candidate.CacheGrant) < GrantRank(best.CacheGrant);
    }

    private static int GrantRank(CacheTtl? grant) => grant is { } ttl ? (int)ttl + 1 : 0;

    private FieldMatch MatchRule(Rule rule, RequestTuple tuple) => FieldMatcher.Combine(
        FieldMatcher.Caller(rule.Caller, tuple.Caller),
        FieldMatcher.Action(rule.Action, tuple.Action),
        FieldMatcher.Named(rule.Vault, tuple.Path.Vault, AliasKind.Vault, aliases),
        FieldMatcher.Named(rule.Item, tuple.Path.Item, AliasKind.Item, aliases),
        FieldMatcher.Key(rule.Key, tuple.Path.Key));

    /// <summary>
    /// True when the tuple's vault is, or could be, a <c>prompt-always</c> vault. An
    /// unknown vault could be one, so it counts.
    /// </summary>
    private bool InPromptAlwaysVault(RequestTuple tuple) =>
        rules.PromptAlwaysVaults.Any(vault => FieldMatcher.Named(vault, tuple.Path.Vault, AliasKind.Vault, aliases) != FieldMatch.No);
}
