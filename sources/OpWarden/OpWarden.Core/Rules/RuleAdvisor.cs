namespace OpWarden.Core.Rules;

public enum NoticeKind
{
    /// <summary>
    /// An allow rule pins one form and the broker has never seen the other, so a request
    /// naming the value the other way prompts instead of being allowed.
    /// </summary>
    OtherFormUnknown,

    /// <summary>
    /// The broker knows exactly one other form and no rule pins it yet; the notice
    /// carries the rule that would.
    /// </summary>
    OtherFormKnown,

    /// <summary>
    /// The pinned value has several other forms, such as one item name in two vaults,
    /// so no single counterpart rule can be offered.
    /// </summary>
    OtherFormAmbiguous,
}

/// <summary>
/// A note about one pinned field of one rule (REQ-RULE-29, REQ-RULE-30).
/// </summary>
/// <param name="Field">Which field: vault, item, or key (as <see cref="AliasKind.Field"/>).</param>
/// <param name="PinnedValue">The name, label or ID the rule pins; for a key, the field part without its section.</param>
/// <param name="OtherForms">The IDs of a pinned name, or the names of a pinned ID, as far as the broker has seen them.</param>
/// <param name="Suggestion">For <see cref="NoticeKind.OtherFormKnown"/>, the rule to offer: the same rule with the other form pinned.</param>
public sealed record RuleNotice(Rule Rule, AliasKind Field, string PinnedValue, NoticeKind Kind, IReadOnlyList<string> OtherForms, Rule? Suggestion);

/// <summary>
/// Reviews stored rules for fields pinned by only one of their two forms, name or ID.
/// </summary>
/// <remarks>
/// Matching already treats a known pair as one value (REQ-RULE-16), so these notices are
/// about rules that stand on their own. A pair the broker learned only lives as long as
/// the alias store keeps it, and an allow rule that pins only one form prompts for the
/// other until the pair turns up. A deny rule needs no notice for an unseen other form:
/// an unseen ID is a possible match for every name, and a deny acts on that
/// (REQ-RULE-23).
/// </remarks>
public static class RuleAdvisor
{
    public static IReadOnlyList<RuleNotice> Review(RuleSet rules, AliasStore aliases)
    {
        var notices = new List<RuleNotice>();
        foreach (var rule in rules.Rules)
        {
            if (rule.Vault is { } vault) Add(notices, rules, aliases, rule, AliasKind.Vault, null, vault);
            if (rule.Item is { } item) Add(notices, rules, aliases, rule, AliasKind.Item, null, item);
            if (rule.Key is { } key)
            {
                var slash = key.LastIndexOf('/');
                Add(notices, rules, aliases, rule, AliasKind.Field, slash < 0 ? null : key[..(slash + 1)], slash < 0 ? key : key[(slash + 1)..]);
            }
        }

        return notices;
    }

    private static void Add(List<RuleNotice> notices, RuleSet rules, AliasStore aliases, Rule rule, AliasKind kind, string? section, string pinned)
    {
        var pinsId = AliasStore.IsIdForm(kind, pinned);

        // The password and notes fields carry their ID as their label, so they have no
        // other form unless the store has seen one. (The username field is often labelled
        // "email", so it does get a notice.)
        if (kind == AliasKind.Field && pinned is "password" or "notesPlain" && aliases.NamesFor(kind, pinned).Count == 0) return;

        IReadOnlyList<string> others = [.. (pinsId ? aliases.NamesFor(kind, pinned) : aliases.IdsFor(kind, pinned)).Order(StringComparer.Ordinal)];
        if (others.Count == 0)
        {
            if (rule.Verdict == Verdict.Allow) notices.Add(new RuleNotice(rule, kind, pinned, NoticeKind.OtherFormUnknown, others, null));
            return;
        }

        if (others.Count > 1)
        {
            notices.Add(new RuleNotice(rule, kind, pinned, NoticeKind.OtherFormAmbiguous, others, null));
            return;
        }

        var counterpart = others[0];
        var suggestion = kind switch
        {
            AliasKind.Vault => With(rule, vault: counterpart),
            AliasKind.Item => With(rule, item: counterpart),
            _ => With(rule, key: section + counterpart),
        };
        if (!rules.Rules.Contains(suggestion, RuleShape.Comparer)) notices.Add(new RuleNotice(rule, kind, pinned, NoticeKind.OtherFormKnown, others, suggestion));
    }

    private static Rule With(Rule rule, string? vault = null, string? item = null, string? key = null) =>
        new(rule.Caller, rule.Action, vault ?? rule.Vault, item ?? rule.Item, key ?? rule.Key, rule.Verdict, rule.CacheGrant);

    /// <summary>
    /// Compares rules by what they match and decide, ignoring letter case in names, so
    /// an existing counterpart rule is recognised however it was typed.
    /// </summary>
    private sealed class RuleShape : IEqualityComparer<Rule>
    {
        public static RuleShape Comparer { get; } = new();

        public bool Equals(Rule? x, Rule? y) =>
            x is not null && y is not null
            && x.Caller == y.Caller && x.Action == y.Action && x.Verdict == y.Verdict
            && string.Equals(x.Vault, y.Vault, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Item, y.Item, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Key, y.Key, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(Rule obj) => HashCode.Combine(obj.Caller, obj.Action, obj.Verdict);
    }
}
