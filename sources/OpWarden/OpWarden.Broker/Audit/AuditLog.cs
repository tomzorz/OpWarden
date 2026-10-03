using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Broker.Audit;

/// <summary>
/// Why the broker returned its verdict (REQ-FAIL-4).
/// </summary>
public enum VerdictReason
{
    [JsonStringEnumMemberName("rule")] Rule,
    [JsonStringEnumMemberName("user")] User,
    [JsonStringEnumMemberName("timeout")] Timeout,
    [JsonStringEnumMemberName("abandoned")] Abandoned,
    [JsonStringEnumMemberName("cache")] Cache,
    [JsonStringEnumMemberName("queue-full")] QueueFull,
}

/// <summary>
/// Where a rule change came from (REQ-TRUST-7).
/// </summary>
public enum RuleChangeSource
{
    [JsonStringEnumMemberName("prompt")] Prompt,
    [JsonStringEnumMemberName("management")] Management,
}

/// <summary>
/// One line of the audit log (REQ-AUD-2). Absent fields are left out of the line.
/// </summary>
/// <param name="Event">What happened: <c>invocation</c>, <c>rule-change</c>, <c>cache-flush</c> or <c>integrity-failure</c>.</param>
/// <param name="Detail">A sentence for events that need one, such as what failed its integrity check.</param>
/// <param name="CallerChain">The resolved ancestor chain (REQ-CALL-17).</param>
/// <param name="Arguments">The invocation arguments, redacted per REQ-AUD-5.</param>
public sealed record AuditEntry(
    DateTimeOffset Timestamp,
    string Event,
    CallerIdentity? Caller = null,
    IReadOnlyList<string>? CallerChain = null,
    OpAction? Action = null,
    string? Command = null,
    IReadOnlyList<string>? Arguments = null,
    SecretPath? Path = null,
    IReadOnlyList<SecretPath>? SecretReferences = null,
    bool? SecretReferencesUnknown = null,
    Verdict? Verdict = null,
    VerdictReason? Reason = null,
    RuleChangeSource? Source = null,
    Rule? Rule = null,
    string? Detail = null);

/// <summary>
/// The append-only audit log: one JSON object per line, UTC timestamps (spec section 12).
/// </summary>
public sealed class AuditLog
{
    private readonly string _path;
    private readonly Lock _lock = new();

    public AuditLog(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    }

    /// <summary>
    /// Appends one entry and flushes it to disk before returning, so a verdict is never
    /// handed out ahead of its record.
    /// </summary>
    public void Append(AuditEntry entry)
    {
        var line = JsonSerializer.SerializeToUtf8Bytes(entry with { Timestamp = entry.Timestamp.ToUniversalTime() }, AuditJsonContext.Default.AuditEntry);
        lock (_lock)
        {
            using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
            stream.Write(line);
            stream.WriteByte((byte)'\n');
            stream.Flush(flushToDisk: true);
        }
    }

    /// <summary>
    /// Redacts the arguments of a <c>write</c> or <c>manage</c> invocation (REQ-AUD-5): the
    /// value part of each <c>field=value</c> assignment becomes <c>&lt;redacted&gt;</c>. A
    /// session token is a credential whatever the action, so <c>--session</c> values are
    /// redacted everywhere (REQ-AUD-6).
    /// </summary>
    public static IReadOnlyList<string> RedactArguments(IReadOnlyList<string> arguments, OpAction action)
    {
        var redactAssignments = action is OpAction.Write or OpAction.Manage;
        var result = new List<string>(arguments.Count);
        for (var i = 0; i < arguments.Count; i++)
        {
            var argument = arguments[i];
            if (argument == "--session" && i + 1 < arguments.Count)
            {
                result.Add(argument);
                result.Add(Redacted);
                i++;
            }
            else if (argument.StartsWith("--session=", StringComparison.Ordinal))
            {
                result.Add("--session=" + Redacted);
            }
            else if (redactAssignments && !argument.StartsWith('-') && argument.IndexOf('=') is > 0 and var equals)
            {
                result.Add(argument[..(equals + 1)] + Redacted);
            }
            else
            {
                result.Add(argument);
            }
        }

        return result;
    }

    private const string Redacted = "<redacted>";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AuditEntry))]
internal sealed partial class AuditJsonContext : JsonSerializerContext;
