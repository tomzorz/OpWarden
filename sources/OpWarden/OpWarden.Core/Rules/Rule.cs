namespace OpWarden.Core.Rules;

/// <summary>
/// How long a cache grant keeps an output (REQ-CACHE-4).
/// </summary>
public enum CacheTtl
{
    FifteenMinutes,
    OneHour,
    EightHours,
}

/// <summary>
/// A stored pattern over the request tuple (REQ-RULE-1). A null field is a wildcard;
/// every other field is pinned to its value.
/// </summary>
public sealed record Rule
{
    public Rule(CallerIdentity? caller, OpAction? action, string? vault, string? item, string? key, Verdict verdict, CacheTtl? cacheGrant = null)
    {
        if (caller is { IsUnknown: true }) throw new ArgumentException("A rule cannot pin the unknown caller: REQ-CALL-19 prompts for it on every invocation.", nameof(caller));
        if (cacheGrant is not null && verdict == Verdict.Deny) throw new ArgumentException("A cache grant rides only on an allow rule (REQ-RULE-19).", nameof(cacheGrant));

        (Caller, Action, Vault, Item, Key, Verdict, CacheGrant) = (caller, action, vault, item, key, verdict, cacheGrant);
    }

    public CallerIdentity? Caller { get; }

    public OpAction? Action { get; }

    public string? Vault { get; }

    public string? Item { get; }

    public string? Key { get; }

    public Verdict Verdict { get; }

    public CacheTtl? CacheGrant { get; }

    /// <summary>
    /// The number of pinned fields. REQ-RULE-2 ranks a pinned field above a wildcard.
    /// </summary>
    public int Specificity => (Caller is null ? 0 : 1) + (Action is null ? 0 : 1) + (Vault is null ? 0 : 1) + (Item is null ? 0 : 1) + (Key is null ? 0 : 1);
}

/// <summary>
/// The rules and the vaults marked <c>prompt-always</c> (REQ-RULE-17).
/// </summary>
public sealed record RuleSet(IReadOnlyList<Rule> Rules, IReadOnlyList<string> PromptAlwaysVaults)
{
    public static RuleSet Empty { get; } = new([], []);
}

/// <summary>
/// The five values a rule matches against (REQ-RULE-1). A null path field is unknown.
/// </summary>
public sealed record RequestTuple(CallerIdentity Caller, OpAction Action, SecretPath Path);
