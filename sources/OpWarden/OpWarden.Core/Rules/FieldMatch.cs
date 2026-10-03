namespace OpWarden.Core.Rules;

/// <summary>
/// How one rule field relates to one request field.
/// </summary>
/// <remarks>
/// Matching is three-valued because a request field can be unknown, and an ID can
/// stand for a name the broker has not seen yet. <see cref="Possible"/> is the "could
/// be": a deny rule acts on it, an allow rule does not (REQ-RULE-20, REQ-RULE-21).
/// Without it, leaving out <c>--vault</c> or swapping a name for its ID would walk past
/// every pinned deny.
/// </remarks>
internal enum FieldMatch
{
    No,
    Possible,
    Definite,
}

internal static class FieldMatcher
{
    public static FieldMatch Caller(CallerIdentity? rule, CallerIdentity request) =>
        rule is null || rule == request ? FieldMatch.Definite : FieldMatch.No;

    public static FieldMatch Action(OpAction? rule, OpAction request) =>
        rule is null || rule == request ? FieldMatch.Definite
        : request == OpAction.Unknown ? FieldMatch.Possible
        : FieldMatch.No;

    /// <summary>
    /// Compares a vault, an item or a field, treating a name and its ID as one value
    /// (REQ-RULE-16, REQ-RULE-22 to REQ-RULE-24).
    /// </summary>
    public static FieldMatch Named(string? rule, string? request, AliasKind kind, AliasStore aliases)
    {
        if (rule is null) return FieldMatch.Definite;
        if (request is null) return FieldMatch.Possible;
        if (string.Equals(rule, request, StringComparison.OrdinalIgnoreCase)) return FieldMatch.Definite;

        var ruleIsId = AliasStore.LooksLikeId(rule);
        var requestIsId = AliasStore.LooksLikeId(request);
        if (ruleIsId == requestIsId) return FieldMatch.No;

        var (id, name) = ruleIsId ? (rule, request) : (request, rule);
        var namesOfId = aliases.NamesFor(kind, id);

        // An ID the broker has never seen could be anything, the name included.
        if (namesOfId.Count == 0) return FieldMatch.Possible;
        if (!namesOfId.Contains(name)) return FieldMatch.No;

        // The pair is known. A rule that pins the name covers everything carrying that
        // name. A rule that pins the ID covers the name only when no other ID carries it.
        return !ruleIsId || aliases.IdsFor(kind, name).Count == 1 ? FieldMatch.Definite : FieldMatch.Possible;
    }

    /// <summary>
    /// Compares a key: by label or ID like <see cref="Named"/>, and with or without its
    /// section. A reference may name a field as <c>password</c> or <c>Login/password</c>,
    /// so the same field under a different or missing section is only a possible match
    /// (REQ-RULE-25).
    /// </summary>
    public static FieldMatch Key(string? rule, string? request, AliasStore aliases)
    {
        if (rule is null) return FieldMatch.Definite;
        if (request is null) return FieldMatch.Possible;
        if (string.Equals(rule, request, StringComparison.OrdinalIgnoreCase)) return FieldMatch.Definite;

        var (ruleSection, ruleField) = SplitKey(rule);
        var (requestSection, requestField) = SplitKey(request);
        var field = Named(ruleField, requestField, AliasKind.Field, aliases);
        var sameSection = string.Equals(ruleSection, requestSection, StringComparison.OrdinalIgnoreCase);
        return field == FieldMatch.Definite && !sameSection ? FieldMatch.Possible : field;
    }

    private static (string? Section, string Field) SplitKey(string key)
    {
        var slash = key.LastIndexOf('/');
        return slash < 0 ? (null, key) : (key[..slash], key[(slash + 1)..]);
    }

    public static FieldMatch Combine(params ReadOnlySpan<FieldMatch> matches)
    {
        var result = FieldMatch.Definite;
        foreach (var match in matches)
        {
            if (match < result) result = match;
        }

        return result;
    }
}
