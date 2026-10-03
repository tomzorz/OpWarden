using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Broker.Integrity;
using OpWarden.Core.Rules;

namespace OpWarden.Broker.Storage;

/// <summary>
/// The rule store: the rules and the <c>prompt-always</c> vaults, sealed on disk and
/// sealed in memory. Only the broker writes it (REQ-TRUST-2); a human edits rules
/// through the management window, not the file.
/// </summary>
/// <remarks>
/// A file that fails its seal is moved aside and the broker starts with no rules, so
/// every invocation prompts; a tampered allow never takes effect, and the user hears
/// about it (REQ-INT-3). The in-memory copy carries its own seal under a key that lives
/// only in this process, checked on every read: memory edited from outside the broker
/// is caught at the next evaluation, and the store reloads from disk (REQ-INT-6).
/// </remarks>
public sealed class RuleStore
{
    private const string SealName = "rules";

    private readonly string _path;
    private readonly IntegrityVault _vault;
    private readonly Action<string> _tampered;
    private readonly Lock _lock = new();
    private RuleSet _current = RuleSet.Empty;
    private byte[] _memorySeal = [];

    private RuleStore(string path, IntegrityVault vault, Action<string> tampered) => (_path, _vault, _tampered) = (path, vault, tampered);

    /// <summary>
    /// The rules as of now, verified against their in-memory seal.
    /// </summary>
    public RuleSet Current
    {
        get
        {
            lock (_lock) return Verified();
        }
    }

    public static RuleStore Open(string path, IntegrityVault vault, Action<string> tampered)
    {
        var store = new RuleStore(path, vault, tampered);
        lock (store._lock) store.Load();
        return store;
    }

    public void Add(IEnumerable<Rule> rules)
    {
        lock (_lock)
        {
            var current = Verified();
            var next = current with { Rules = [.. current.Rules, .. rules] };
            var content = Serialize(next);
            SealedFile.Write(_path, SealName, content, _vault);
            Remember(next, content);
        }
    }

    // ceiling: re-serialises every rule on every read; fine for hundreds of rules, cache
    // the serialised form if rule sets grow to many thousands.
    private RuleSet Verified()
    {
        if (CryptographicOperations.FixedTimeEquals(_memorySeal, MemorySeal.Of(Serialize(_current)))) return _current;

        _tampered("The rules in broker memory no longer match their seal: something outside OpWarden changed the broker's memory. The rules were reloaded from disk.");
        Load();
        return _current;
    }

    /// <summary>
    /// Marks a vault <c>prompt-always</c> (REQ-RULE-17).
    /// </summary>
    public void MarkPromptAlways(string vault)
    {
        lock (_lock)
        {
            var current = Verified();
            if (current.PromptAlwaysVaults.Contains(vault, StringComparer.OrdinalIgnoreCase)) return;
            var next = current with { PromptAlwaysVaults = [.. current.PromptAlwaysVaults, vault] };
            var content = Serialize(next);
            SealedFile.Write(_path, SealName, content, _vault);
            Remember(next, content);
        }
    }

    private void Load()
    {
        RuleSet loaded;
        try
        {
            var content = SealedFile.Read(_path, SealName, _vault);
            loaded = content is null ? RuleSet.Empty : Parse(content);
        }
        catch (TamperedException e)
        {
            var quarantined = Quarantine(_path);
            _tampered($"{e.Message} It was moved to {quarantined}, and OpWarden started with no rules, so every invocation prompts until rules are stored again.");
            SealedFile.Write(_path, SealName, Serialize(RuleSet.Empty), _vault);
            loaded = RuleSet.Empty;
        }

        Remember(loaded, Serialize(loaded));
    }

    private void Remember(RuleSet rules, byte[] content)
    {
        _current = rules;
        _memorySeal = MemorySeal.Of(content);
    }

    private static RuleSet Parse(byte[] content)
    {
        var file = JsonSerializer.Deserialize(content, StorageJsonContext.Default.RuleFile) ?? throw new TamperedException("The sealed rule store holds no content.");
        return file.Version == RuleFile.CurrentVersion
            ? new RuleSet(file.Rules, file.PromptAlwaysVaults)
            : throw new InvalidDataException($"The rule store has version {file.Version}; this broker reads version {RuleFile.CurrentVersion}.");
    }

    private static byte[] Serialize(RuleSet rules) =>
        JsonSerializer.SerializeToUtf8Bytes(new RuleFile(RuleFile.CurrentVersion, rules.Rules, rules.PromptAlwaysVaults), StorageJsonContext.Default.RuleFile);

    /// <summary>
    /// Moves a file that failed its check out of the way, keeping it for whoever
    /// investigates, and returns where it went.
    /// </summary>
    internal static string Quarantine(string path)
    {
        var target = $"{path}.tampered-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}";
        if (File.Exists(path)) File.Move(path, target, overwrite: true);
        return target;
    }
}

/// <summary>
/// The rule store's content format, inside the seal.
/// </summary>
public sealed record RuleFile(int Version, IReadOnlyList<Rule> Rules, IReadOnlyList<string> PromptAlwaysVaults)
{
    public const int CurrentVersion = 1;
}

/// <summary>
/// The alias pairs the broker has learned (REQ-RULE-15), sealed on disk. A pair decides
/// whether an allow rule covers a request (REQ-RULE-24), so a forged pair is as
/// dangerous as a forged rule.
/// </summary>
public sealed class AliasFile(string path, IntegrityVault vault, Action<string> tampered)
{
    private const string SealName = "aliases";

    public AliasStore Load()
    {
        var store = new AliasStore();
        try
        {
            var content = SealedFile.Read(path, SealName, vault);
            if (content is not null) store.AddRange(JsonSerializer.Deserialize(content, StorageJsonContext.Default.IReadOnlyListAliasPair) ?? []);
        }
        catch (TamperedException e)
        {
            var quarantined = RuleStore.Quarantine(path);
            tampered($"{e.Message} It was moved to {quarantined}, and OpWarden starts learning alias pairs afresh.");
        }

        return store;
    }

    public void Save(AliasStore store) => SealedFile.Write(path, SealName, JsonSerializer.SerializeToUtf8Bytes(store.Pairs(), StorageJsonContext.Default.IReadOnlyListAliasPair), vault);
}

/// <summary>
/// Seals for state held in broker memory, under a key generated at start and never
/// written anywhere.
/// </summary>
internal static class MemorySeal
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    public static byte[] Of(ReadOnlySpan<byte> data) => HMACSHA256.HashData(Key, data);
}

internal static class AtomicFile
{
    /// <summary>
    /// Writes beside the target and then replaces it, so a crash mid-write leaves the
    /// previous file intact rather than half a file.
    /// </summary>
    public static void Write(string path, byte[] content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temporary = path + ".tmp";
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(RuleFile))]
[JsonSerializable(typeof(IReadOnlyList<AliasPair>))]
internal sealed partial class StorageJsonContext : JsonSerializerContext;
