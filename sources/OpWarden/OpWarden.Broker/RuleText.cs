using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <summary>
/// Rules and notices as one line of text, for deny messages and notifications.
/// </summary>
internal static class RuleText
{
    /// <summary>
    /// <c>deny claude-code read Prod * *</c>: verdict, then caller, action, vault, item and
    /// key, with <c>*</c> for a wildcard.
    /// </summary>
    public static string Describe(Rule rule) =>
        string.Join(' ', rule.Verdict.ToString().ToLowerInvariant(), rule.Caller?.Name ?? "*", rule.Action?.ToString().ToLowerInvariant() ?? "*", rule.Vault ?? "*", rule.Item ?? "*", rule.Key ?? "*");

    public static string Describe(RuleNotice notice)
    {
        var field = notice.Field.ToString().ToLowerInvariant();
        return notice.Kind switch
        {
            NoticeKind.OtherFormUnknown => $"The rule \"{Describe(notice.Rule)}\" names the {field} \"{notice.PinnedValue}\" one way only. A request naming it by its other form will prompt until OpWarden has seen both.",
            NoticeKind.OtherFormKnown => $"The rule \"{Describe(notice.Rule)}\" names the {field} \"{notice.PinnedValue}\", also known as \"{notice.OtherForms[0]}\". Add \"{Describe(notice.Suggestion!)}\" in the management window to cover both forms on their own.",
            NoticeKind.OtherFormAmbiguous => $"The rule \"{Describe(notice.Rule)}\" names the {field} \"{notice.PinnedValue}\", which has several other forms: {string.Join(", ", notice.OtherForms)}.",
            _ => throw new ArgumentOutOfRangeException(nameof(notice), notice.Kind, null),
        };
    }
}
