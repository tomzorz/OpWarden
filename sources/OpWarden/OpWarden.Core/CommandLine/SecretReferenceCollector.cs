using System.Text.RegularExpressions;

namespace OpWarden.Core.CommandLine;

/// <summary>
/// The secret references an invocation uses, and whether that list is complete.
/// </summary>
public sealed record CollectedReferences(IReadOnlyList<SecretPath> References, bool Unknown);

/// <summary>
/// Collects the secret references of a <c>run</c> invocation (REQ-CLAS-11 to REQ-CLAS-17)
/// from the places the op CLI reads them.
/// </summary>
/// <remarks>
/// <c>op run</c> resolves references held in environment variables, both the inherited
/// environment and the <c>--env-file</c> files, with a file overriding the environment
/// and a later file overriding an earlier one. <c>op inject</c> resolves references in
/// its template, both <c>{{ op://… }}</c> and bare. Both expand <c>$NAME</c> variables
/// inside a reference.
/// </remarks>
public static partial class SecretReferenceCollector
{
    public static CollectedReferences Collect(ParsedInvocation invocation, IReadOnlyDictionary<string, string> environment)
    {
        if (invocation.ReferencesUnknown) return new(invocation.ArgumentReferences, true);

        return invocation.Command switch
        {
            "run" => FromRun(invocation.EnvFiles, environment),
            "inject" when invocation.TemplateFile is null => new([], true),
            "inject" => FromTemplate(invocation.TemplateFile, environment),
            _ => new(invocation.ArgumentReferences, false),
        };
    }

    private static CollectedReferences FromRun(IReadOnlyList<string> envFiles, IReadOnlyDictionary<string, string> environment)
    {
        var variables = new Dictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase);
        foreach (var path in envFiles)
        {
            var text = TryReadFile(path);
            if (text is null) return new([], true);
            foreach (var (name, value) in ParseEnvFile(text)) variables[name] = value;
        }

        var references = new List<SecretPath>();
        var unknown = false;
        foreach (var value in variables.Values)
        {
            var at = value.IndexOf(SecretReference.Scheme, StringComparison.OrdinalIgnoreCase);
            if (at < 0) continue;

            // The op CLI resolves a variable whose whole value is a reference. A reference
            // further in is not documented either way, so it makes the list unknown.
            var reference = at == 0 ? SecretReference.TryParseExpanded(value, environment) : null;
            if (reference is null) unknown = true;
            else references.Add(reference);
        }

        return new(references.Distinct().ToList(), unknown);
    }

    private static CollectedReferences FromTemplate(string path, IReadOnlyDictionary<string, string> environment)
    {
        var text = TryReadFile(path);
        if (text is null) return new([], true);

        var references = new List<SecretPath>();
        var unknown = false;

        void Add(string candidate)
        {
            var reference = SecretReference.TryParseExpanded(candidate, environment);
            if (reference is null) unknown = true;
            else references.Add(reference);
        }

        foreach (Match match in BracedReference().Matches(text)) Add(match.Groups[1].Value.Trim());

        var outsideBraces = BracedReference().Replace(text, " ");
        foreach (Match match in BareReference().Matches(outsideBraces))
        {
            // A reference may contain spaces, so a bare one followed by a space and more
            // reference characters has no visible end. Which end the op CLI picks is
            // undocumented; the key would be a guess (REQ-CLAS-16).
            var after = match.Index + match.Length;
            var ambiguous = after + 1 < outsideBraces.Length && outsideBraces[after] == ' ' && SecretReference.IsReferenceChar(outsideBraces[after + 1]) && outsideBraces[after + 1] != ' ';
            if (ambiguous) unknown = true;
            else Add(match.Value);
        }

        return new(references.Distinct().ToList(), unknown);
    }

    /// <summary>
    /// Reads <c>NAME=value</c> lines the way dotenv files are written: blank lines and
    /// <c>#</c> comments skipped, an optional <c>export</c>, spaces around <c>=</c>, and
    /// one layer of matching quotes stripped from the value.
    /// </summary>
    internal static IEnumerable<(string Name, string Value)> ParseEnvFile(string text)
    {
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith("export ", StringComparison.Ordinal)) line = line["export ".Length..].TrimStart();

            var equals = line.IndexOf('=');
            if (equals <= 0) continue;

            var name = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            if (value.Length >= 2 && (value[0] == '"' || value[0] == '\'') && value[^1] == value[0]) value = value[1..^1];
            yield return (name, value);
        }
    }

    private static string? TryReadFile(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // REQ-CLAS-12: an unreadable file makes the references unknown. The op CLI
            // reports the read failure itself if it runs.
            return null;
        }
    }

    [GeneratedRegex(@"\{\{\s*(op://[^}]*?)\s*\}\}", RegexOptions.IgnoreCase)]
    private static partial Regex BracedReference();

    [GeneratedRegex(@"op://[A-Za-z0-9\-_./$?=&{}]+", RegexOptions.IgnoreCase)]
    private static partial Regex BareReference();
}
