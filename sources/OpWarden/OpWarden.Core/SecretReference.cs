using System.Text;

namespace OpWarden.Core;

/// <summary>
/// Secret references: <c>op://vault/item/[section/]field[?query]</c>.
/// </summary>
/// <remarks>
/// 1Password documents the allowed characters as ASCII letters and digits, <c>-</c>,
/// <c>_</c>, <c>.</c> and the space, and says any part with another character must be
/// named by its ID. A reference outside that alphabet is one the op CLI rejects, so it
/// parses as malformed here rather than as a path a rule could match.
/// </remarks>
public static class SecretReference
{
    public const string Scheme = "op://";

    /// <summary>
    /// Parses a reference into a secret path, or returns null when it is malformed.
    /// The key keeps the section, as <c>section/field</c>, because that is how the
    /// reference names the field; the query part selects an attribute of the same
    /// field and is dropped.
    /// </summary>
    public static SecretPath? TryParse(string reference)
    {
        if (!reference.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase)) return null;

        var body = reference[Scheme.Length..];
        var query = body.IndexOf('?');
        if (query >= 0) body = body[..query];

        var segments = body.Split('/');
        if (segments.Length is < 3 or > 4) return null;
        foreach (var segment in segments)
        {
            if (segment.Length == 0 || !segment.All(IsReferenceChar)) return null;
        }

        return new SecretPath(segments[0], segments[1], string.Join('/', segments[2..]));
    }

    /// <summary>
    /// Parses a reference after expanding its <c>$NAME</c> and <c>${NAME}</c> variables
    /// from the environment, which is how the op CLI reads references in environment
    /// files and templates. Returns null when a variable is unset or the result is
    /// malformed: guessing at what the op CLI would substitute is how a rule gets evaded.
    /// </summary>
    public static SecretPath? TryParseExpanded(string reference, IReadOnlyDictionary<string, string> environment)
    {
        var expanded = ExpandVariables(reference, environment);
        return expanded is null ? null : TryParse(expanded);
    }

    internal static bool IsReferenceChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ' ';

    internal static string? ExpandVariables(string text, IReadOnlyDictionary<string, string> environment)
    {
        if (!text.Contains('$')) return text;

        var result = new StringBuilder(text.Length);
        var i = 0;
        while (i < text.Length)
        {
            if (text[i] != '$')
            {
                result.Append(text[i++]);
                continue;
            }

            string name;
            if (i + 1 < text.Length && text[i + 1] == '{')
            {
                var close = text.IndexOf('}', i + 2);
                if (close < 0) return null;
                name = text[(i + 2)..close];
                i = close + 1;
            }
            else
            {
                var start = i + 1;
                var end = start;
                while (end < text.Length && IsVariableChar(text[end], end == start)) end++;
                name = text[start..end];
                i = end;
            }

            if (!IsVariableName(name) || !environment.TryGetValue(name, out var value)) return null;

            // A value with a separator in it moves the segment boundaries, and whether the
            // op CLI expands before or after it splits the reference is undocumented (REQ-CLAS-15).
            if (value.IndexOfAny(['/', '?']) >= 0) return null;
            result.Append(value);
        }

        return result.ToString();
    }

    private static bool IsVariableChar(char c, bool first) => c == '_' || (first ? char.IsAsciiLetter(c) : char.IsAsciiLetterOrDigit(c));

    private static bool IsVariableName(string name) =>
        name.Length > 0 && IsVariableChar(name[0], true) && name.Skip(1).All(c => IsVariableChar(c, false));
}
