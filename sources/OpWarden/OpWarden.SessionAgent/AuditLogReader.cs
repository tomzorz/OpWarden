using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace OpWarden.SessionAgent;

/// <summary>
/// One audit-log entry as the audit window shows it.
/// </summary>
public sealed record AuditRow(
    DateTimeOffset Timestamp,
    string Event,
    string Caller,
    string Command,
    string Secret,
    string Verdict,
    string Reason,
    IReadOnlyList<string> Chain,
    IReadOnlyList<string> Arguments,
    string Detail)
{
    public string Time => Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);

    public string ChainText => string.Join(Environment.NewLine, Chain);

    public string ArgumentsText => Arguments.Count == 0 ? "" : "op " + string.Join(' ', Arguments);

    /// <summary>
    /// Worth a second look: a refusal, an unidentified caller, or something the broker
    /// reported as wrong.
    /// </summary>
    public bool IsProblem =>
        Verdict == "Deny"
        || Caller == "unknown"
        || Event is "integrity-failure" or "agent-refused" or "management-refused" or "process-events-unavailable" or "process-events-lost" or "process-map-full";

    public bool Matches(string filter) =>
        filter.Length == 0
        || new[] { Event, Caller, Command, Secret, Verdict, Reason, Detail, ArgumentsText }.Any(field => field.Contains(filter, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Follows the audit log the interactive user may read (REQ-TRUST-2): each call returns the
/// entries appended since the last one.
/// </summary>
/// <remarks>
/// The broker appends whole lines, but a read can still land mid-write, so the bytes after
/// the last newline wait for the next call. A log shorter than what was already read was
/// moved aside and begun anew (REQ-AUD-10), and reading starts over.
/// </remarks>
internal sealed class AuditLogReader(string path)
{
    private long _offset;
    private byte[] _pending = [];

    public string FilePath => path;

    public IReadOnlyList<AuditRow> ReadNew()
    {
        if (!File.Exists(path)) return [];

        byte[] appended;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            if (stream.Length < _offset)
            {
                _offset = 0;
                _pending = [];
            }

            stream.Seek(_offset, SeekOrigin.Begin);
            appended = new byte[stream.Length - _offset];
            stream.ReadExactly(appended);
            _offset += appended.Length;
        }

        var bytes = _pending.Length == 0 ? appended : [.. _pending, .. appended];
        var end = Array.LastIndexOf(bytes, (byte)'\n');
        if (end < 0)
        {
            _pending = bytes;
            return [];
        }

        _pending = bytes[(end + 1)..];
        var rows = new List<AuditRow>();
        foreach (var line in Encoding.UTF8.GetString(bytes, 0, end).Split('\n'))
        {
            if (Parse(line) is { } row) rows.Add(row);
        }

        return rows;
    }

    /// <summary>
    /// One line of the log, or null for a line that is not an entry.
    /// </summary>
    public static AuditRow? Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try
        {
            using var document = JsonDocument.Parse(line);
            var entry = document.RootElement;
            return new AuditRow(
                entry.TryGetProperty("timestamp", out var timestamp) && timestamp.TryGetDateTimeOffset(out var at) ? at : DateTimeOffset.MinValue,
                Text(entry, "event"),
                entry.TryGetProperty("caller", out var caller) ? Text(caller, "name") : "",
                Text(entry, "command"),
                Secret(entry),
                Text(entry, "verdict"),
                Text(entry, "reason"),
                Strings(entry, "callerChain"),
                Strings(entry, "arguments"),
                Detail(entry));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

    private static IReadOnlyList<string> Strings(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? [.. value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString() ?? "")]
            : [];

    /// <summary>
    /// The secrets an invocation names: every reference of a run, else its one path.
    /// </summary>
    private static string Secret(JsonElement entry)
    {
        if (entry.TryGetProperty("secretReferences", out var references) && references.ValueKind == JsonValueKind.Array && references.GetArrayLength() > 1)
        {
            return string.Join("; ", references.EnumerateArray().Select(DescribePath));
        }

        return entry.TryGetProperty("path", out var path) ? DescribePath(path) : "";
    }

    private static string DescribePath(JsonElement path)
    {
        var parts = new[] { Text(path, "vault"), Text(path, "item"), Text(path, "key") };
        return parts.All(p => p.Length == 0) ? "" : string.Join(" / ", parts.Select(p => p.Length == 0 ? "?" : p));
    }

    /// <summary>
    /// The entry's own sentence, or for a rule change, the rule it is about.
    /// </summary>
    private static string Detail(JsonElement entry)
    {
        var detail = Text(entry, "detail");
        if (!entry.TryGetProperty("rule", out var rule)) return detail;

        var fields = new[] { ("caller", rule.TryGetProperty("caller", out var c) ? Text(c, "name") : ""), ("action", Text(rule, "action")), ("vault", Text(rule, "vault")), ("item", Text(rule, "item")), ("key", Text(rule, "key")) };
        var pinned = string.Join(", ", fields.Where(f => f.Item2.Length > 0).Select(f => $"{f.Item1} {f.Item2}"));
        var described = $"{Text(rule, "verdict").ToLowerInvariant()} {(pinned.Length == 0 ? "everything" : pinned)}";
        return detail.Length == 0 ? described : $"{detail} ({described})";
    }
}
