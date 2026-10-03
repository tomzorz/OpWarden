using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Broker.Integrity;
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
/// The append-only audit log: one JSON object per line, UTC timestamps (spec section 12),
/// each line chained to the one before it (REQ-AUD-8).
/// </summary>
/// <remarks>
/// <code>
///   line n = { …entry… , "chain": HMAC(key, chain(n-1) ‖ entry bytes) }
/// </code>
/// Editing, inserting or deleting a line breaks every chain value after it, and only
/// the holder of the vault key can compute a new one. Deleting lines at the end leaves
/// a valid chain, so the vault also records how many lines the log had; that anchor is
/// written every 30 seconds and at shutdown rather than per line, because a vault write
/// costs a DPAPI round and a flush, and REQ-SHIM-8 leaves no room for that per call
/// (REQ-AUD-9).
///
/// ceiling: the whole log is verified at start; rotate the log once start-up verification
/// gets slow.
/// </remarks>
public sealed class AuditLog : IDisposable
{
    private const string AnchorName = "audit";
    private static readonly byte[] Genesis = new byte[32];
    private static readonly byte[] ChainProperty = Encoding.UTF8.GetBytes(",\"chain\":\"");

    private readonly string _path;
    private readonly IntegrityVault _vault;
    private readonly Lock _lock = new();
    private readonly Timer _anchor;
    private byte[] _chain;
    private long _lines;
    private long _anchoredLines;

    private AuditLog(string path, IntegrityVault vault, byte[] chain, long lines)
    {
        (_path, _vault, _chain, _lines, _anchoredLines) = (path, vault, chain, lines, lines);
        _anchor = new Timer(_ => Anchor(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Opens the log and verifies its chain and its anchor. A log that fails is moved aside
    /// and a new one begins; <paramref name="problem"/> then says what failed, for the
    /// caller to raise once the integrity alarm exists (REQ-AUD-10).
    /// </summary>
    public static AuditLog Open(string path, IntegrityVault vault, out string? problem)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        problem = null;
        var anchored = vault.Generation(AnchorName);

        if (!File.Exists(path))
        {
            if (anchored > 0) problem = $"The audit log {path} is missing, although the broker had written {anchored} lines to it. A new log begins.";
            return Fresh(path, vault);
        }

        var (chain, lines, failure) = Verify(path, vault);
        if (failure is null && lines < anchored) failure = $"it has {lines} lines, but the broker had written at least {anchored}: lines were deleted from its end";
        if (failure is null) return new AuditLog(path, vault, chain, lines);

        var quarantined = $"{path}.tampered-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}";
        File.Move(path, quarantined, overwrite: true);
        problem = $"The audit log failed its check: {failure}. It was moved to {quarantined}, and a new log begins.";
        return Fresh(path, vault);
    }

    /// <summary>
    /// Appends one entry and flushes it to disk before returning, so a verdict is never
    /// handed out ahead of its record.
    /// </summary>
    public void Append(AuditEntry entry)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(entry with { Timestamp = entry.Timestamp.ToUniversalTime() }, AuditJsonContext.Default.AuditEntry);
        lock (_lock)
        {
            var chain = Link(_vault, _chain, body);
            using (var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                stream.Write(body.AsSpan(0, body.Length - 1));
                stream.Write(ChainProperty);
                stream.Write(Encoding.ASCII.GetBytes(Convert.ToBase64String(chain)));
                stream.Write("\"}\n"u8);
                stream.Flush(flushToDisk: true);
            }

            _chain = chain;
            _lines++;
        }
    }

    public void Dispose()
    {
        _anchor.Dispose();
        Anchor();
    }

    private void Anchor()
    {
        long lines;
        lock (_lock)
        {
            if (_lines == _anchoredLines) return;
            lines = _lines;
        }

        _vault.SetGeneration(AnchorName, lines);
        lock (_lock) _anchoredLines = lines;
    }

    private static AuditLog Fresh(string path, IntegrityVault vault)
    {
        vault.SetGeneration(AnchorName, 0);
        return new AuditLog(path, vault, Genesis, 0);
    }

    private static (byte[] Chain, long Lines, string? Failure) Verify(string path, IntegrityVault vault)
    {
        var chain = Genesis;
        long lines = 0;
        using var reader = new StreamReader(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite), Encoding.UTF8);
        while (reader.ReadLine() is { } text)
        {
            var line = Encoding.UTF8.GetBytes(text);
            var at = line.AsSpan().LastIndexOf(ChainProperty);
            if (at < 0 || !text.EndsWith("\"}", StringComparison.Ordinal)) return (chain, lines, $"line {lines + 1} carries no chain value");

            byte[] recorded;
            try
            {
                recorded = Convert.FromBase64String(Encoding.ASCII.GetString(line, at + ChainProperty.Length, line.Length - at - ChainProperty.Length - 2));
            }
            catch (FormatException)
            {
                return (chain, lines, $"line {lines + 1} carries a malformed chain value");
            }

            byte[] body = [.. line.AsSpan(0, at), (byte)'}'];
            var expected = Link(vault, chain, body);
            if (!CryptographicOperations.FixedTimeEquals(recorded, expected)) return (chain, lines, $"the chain breaks at line {lines + 1}: that line, or one before it, was changed, inserted or deleted");

            chain = expected;
            lines++;
        }

        return (chain, lines, null);
    }

    private static byte[] Link(IntegrityVault vault, byte[] previous, byte[] body) => vault.Mac([.. previous, .. body]);

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
