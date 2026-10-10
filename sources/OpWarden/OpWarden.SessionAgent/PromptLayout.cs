using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.SessionAgent;

/// <summary>
/// One request-tuple field as the prompt shows it, with whether the user may pin it.
/// </summary>
internal sealed record FieldRow(string Label, string Value, bool Pinnable);

/// <summary>
/// What a prompt window shows, worked out from the broker's <see cref="ShowPrompt"/> with
/// no window in sight, so it can be tested without a desktop.
/// </summary>
internal sealed record PromptLayout(
    string Title,
    string Command,
    IReadOnlyList<FieldRow> Fields,
    IReadOnlyList<string> References,
    string? ReferencesNote,
    bool OffersAlways,
    bool OffersCacheGrant)
{
    public const string Unknown = "(unknown)";

    public const string Varies = "(per reference)";

    /// <summary>
    /// The field order of the request tuple, which is also the order of <see cref="RuleScope"/>.
    /// </summary>
    public static readonly string[] FieldLabels = ["Caller", "Action", "Vault", "Item", "Key"];

    public static readonly (string Label, CacheTtl? Ttl)[] CacheChoices =
    [
        ("Don't cache", null),
        ("15 minutes", CacheTtl.FifteenMinutes),
        ("1 hour", CacheTtl.OneHour),
        ("8 hours", CacheTtl.EightHours),
    ];

    public static PromptLayout From(ShowPrompt prompt)
    {
        var action = prompt.Action == OpAction.Unknown ? "run an unrecognised op command" : prompt.Action.ToString().ToLowerInvariant();
        var who = prompt.Caller.IsUnknown ? "An unidentified caller" : prompt.Caller.Name;
        var title = $"{who} wants to {action}";

        // REQ-RULE-5 for one tuple; for several (a run), each reference is listed and the
        // path fields read "per reference", pinnable only when every reference knows them.
        var single = prompt.Paths.Count == 1 ? prompt.Paths[0] : null;
        string Show(Func<SecretPath, string?> field) =>
            single is not null ? field(single) ?? Unknown
            : prompt.Paths.Count == 0 ? Unknown
            : Varies;
        bool Known(Func<SecretPath, string?> field) => prompt.Paths.Count > 0 && prompt.Paths.All(p => field(p) is not null);

        FieldRow[] fields =
        [
            new("Caller", prompt.Caller.Name, true),
            new("Action", prompt.Action.ToString().ToLowerInvariant(), true),
            new("Vault", Show(p => p.Vault), Known(p => p.Vault)),
            new("Item", Show(p => p.Item), Known(p => p.Item)),
            new("Key", Show(p => p.Key), Known(p => p.Key)),
        ];

        var references = single is null ? prompt.Paths.Select(Describe).ToList() : [];
        var note = prompt.ReferencesUnknown
            ? references.Count > 0 ? "Some secret references could not be read; this run may use more than the ones listed." : "The secret references this invocation uses could not be read."
            : null;

        // An always- decision stores one rule per listed tuple (REQ-RULE-33); with none
        // listed there is nothing to store, and the broker refuses it (REQ-RULE-34).
        var offersAlways = prompt.Options == PromptOptions.AllDecisions && prompt.Paths.Count > 0;
        return new PromptLayout(title, prompt.Command is { } command ? "op " + command : "op (unrecognised command)", fields, references, note, offersAlways, prompt.OffersCacheGrant);
    }

    private static string Describe(SecretPath path) => $"{path.Vault ?? Unknown} / {path.Item ?? Unknown} / {path.Key ?? Unknown}";
}

internal static class DecisionBuilder
{
    /// <summary>
    /// The decision to send for a button press: the pins become the scope of an
    /// <c>always-</c> decision, and the cache choice rides only on an allowing decision
    /// of a prompt that offered it.
    /// </summary>
    public static DecisionMade Build(ShowPrompt prompt, PromptDecision decision, IReadOnlyList<bool> pins, int cacheChoice)
    {
        var always = decision is PromptDecision.AlwaysAllow or PromptDecision.AlwaysDisallow;
        var allows = decision is PromptDecision.AlwaysAllow or PromptDecision.AllowOnce;
        var scope = always ? new RuleScope(pins[0], pins[1], pins[2], pins[3], pins[4]) : null;
        var grant = allows && prompt.OffersCacheGrant ? PromptLayout.CacheChoices[cacheChoice].Ttl : null;
        return new DecisionMade(prompt.PromptId, decision, scope, grant);
    }
}
