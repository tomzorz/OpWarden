using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Core.Rules;

namespace OpWarden.Broker.Storage;

/// <summary>
/// The rule store on disk: the rules and the <c>prompt-always</c> vaults, as one JSON file
/// that every change rewrites whole. Only the broker writes it (REQ-TRUST-2); a human
/// edits rules through the management window, not the file.
/// </summary>
public sealed class RuleStore
{
    private readonly string _path;
    private readonly Lock _lock = new();
    private RuleSet _current;

    private RuleStore(string path, RuleSet current) => (_path, _current) = (path, current);

    /// <summary>
    /// The rules as of now. A snapshot: later changes produce a new set.
    /// </summary>
    public RuleSet Current
    {
        get
        {
            lock (_lock) return _current;
        }
    }

    /// <summary>
    /// Opens the store, or starts an empty one when the file does not exist yet. A file
    /// that exists but does not parse is an error, not an empty rule set: silently
    /// dropping every stored deny would be the worst way to recover.
    /// </summary>
    public static RuleStore Open(string path)
    {
        if (!File.Exists(path)) return new RuleStore(path, RuleSet.Empty);

        var file = JsonSerializer.Deserialize(File.ReadAllBytes(path), StorageJsonContext.Default.RuleFile)
                   ?? throw new InvalidDataException($"The rule store {path} is empty or null.");
        if (file.Version != RuleFile.CurrentVersion) throw new InvalidDataException($"The rule store {path} has version {file.Version}; this broker reads version {RuleFile.CurrentVersion}.");
        return new RuleStore(path, new RuleSet(file.Rules, file.PromptAlwaysVaults));
    }

    public void Add(IEnumerable<Rule> rules)
    {
        lock (_lock)
        {
            var next = _current with { Rules = [.. _current.Rules, .. rules] };
            Save(next);
            _current = next;
        }
    }

    private void Save(RuleSet rules) =>
        AtomicFile.Write(_path, JsonSerializer.SerializeToUtf8Bytes(new RuleFile(RuleFile.CurrentVersion, rules.Rules, rules.PromptAlwaysVaults), StorageJsonContext.Default.RuleFile));
}

/// <summary>
/// The rule store's file format.
/// </summary>
public sealed record RuleFile(int Version, IReadOnlyList<Rule> Rules, IReadOnlyList<string> PromptAlwaysVaults)
{
    public const int CurrentVersion = 1;
}

/// <summary>
/// The alias pairs the broker has learned (REQ-RULE-15), kept across broker restarts.
/// </summary>
public sealed class AliasFile(string path)
{
    public AliasStore Load()
    {
        var store = new AliasStore();
        if (File.Exists(path)) store.AddRange(JsonSerializer.Deserialize(File.ReadAllBytes(path), StorageJsonContext.Default.IReadOnlyListAliasPair) ?? []);
        return store;
    }

    public void Save(AliasStore store) => AtomicFile.Write(path, JsonSerializer.SerializeToUtf8Bytes(store.Pairs(), StorageJsonContext.Default.IReadOnlyListAliasPair));
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

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, WriteIndented = true)]
[JsonSerializable(typeof(RuleFile))]
[JsonSerializable(typeof(IReadOnlyList<AliasPair>))]
internal sealed partial class StorageJsonContext : JsonSerializerContext;
