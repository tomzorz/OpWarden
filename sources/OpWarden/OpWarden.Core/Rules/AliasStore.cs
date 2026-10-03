using System.Security.Cryptography;
using System.Text;

namespace OpWarden.Core.Rules;

public enum AliasKind
{
    Vault,
    Item,
    Field,
}

/// <summary>
/// A vault name, item name or field label together with the ID that names the same
/// vault, item or field (spec glossary: alias pair).
/// </summary>
public sealed record AliasPair(AliasKind Kind, string Name, string Id);

/// <summary>
/// The alias pairs the broker has seen in captured read output (REQ-RULE-15).
/// </summary>
/// <remarks>
/// Names compare case-insensitively, as the op CLI resolves them. One name can map to
/// several IDs (two vaults each holding an item called "GitHub"), so the store keeps
/// every ID it has seen per name rather than the latest one.
///
/// ceiling: item pairs are not scoped by vault, nor field pairs by item, so a name that
/// is ambiguous across vaults stays ambiguous everywhere, even where the vault would
/// settle it. That only costs prompts, never a wrong allow.
///
/// Given a sealer, the store keeps a seal over both of its indexes, renewed under the
/// same lock as each change, so <see cref="IsIntact"/> tells whether anything changed the
/// pairs without going through the store (spec REQ-INT-9). The sealer comes from the
/// broker, which owns the key.
/// </remarks>
public sealed class AliasStore
{
    private readonly Lock _lock = new();
    private readonly Dictionary<(AliasKind, string), HashSet<string>> _idsByName = [];
    private readonly Dictionary<(AliasKind, string), HashSet<string>> _namesById = [];
    private readonly Func<byte[], byte[]>? _sealer;
    private byte[] _seal = [];

    public AliasStore()
        : this(null)
    {
    }

    public AliasStore(Func<byte[], byte[]>? sealer)
    {
        _sealer = sealer;
        Reseal();
    }

    /// <summary>
    /// Adds a pair and reports whether it was new.
    /// </summary>
    public bool Add(AliasPair pair)
    {
        lock (_lock)
        {
            var changed = AddUnlocked(pair);
            if (changed) Reseal();
            return changed;
        }
    }

    /// <summary>
    /// True when the pairs still match their seal, or when the store has no sealer.
    /// </summary>
    public bool IsIntact()
    {
        lock (_lock) return _sealer is null || CryptographicOperations.FixedTimeEquals(_seal, _sealer(Canonical()));
    }

    /// <summary>
    /// Replaces every pair, such as with the pairs reloaded from disk after a failed seal.
    /// </summary>
    public void Reset(IEnumerable<AliasPair> pairs)
    {
        lock (_lock)
        {
            _idsByName.Clear();
            _namesById.Clear();
            foreach (var pair in pairs) AddUnlocked(pair);
            Reseal();
        }
    }

    /// <summary>
    /// Adds pairs and reports whether at least one was new.
    /// </summary>
    public bool AddRange(IEnumerable<AliasPair> pairs)
    {
        var added = false;
        foreach (var pair in pairs) added |= Add(pair);
        return added;
    }

    /// <summary>
    /// Every pair in the store.
    /// </summary>
    public IReadOnlyList<AliasPair> Pairs()
    {
        lock (_lock)
        {
            return [.. _namesById.SelectMany(entry => entry.Value.Select(name => new AliasPair(entry.Key.Item1, name, entry.Key.Item2)))];
        }
    }

    /// <summary>
    /// The IDs the store has seen for a name.
    /// </summary>
    public IReadOnlySet<string> IdsFor(AliasKind kind, string name)
    {
        lock (_lock)
        {
            return _idsByName.TryGetValue((kind, Normalize(name)), out var ids) ? ids.ToHashSet() : [];
        }
    }

    /// <summary>
    /// The names the store has seen for an ID, spelled as first seen and compared
    /// without regard to case.
    /// </summary>
    public IReadOnlySet<string> NamesFor(AliasKind kind, string id)
    {
        lock (_lock)
        {
            return _namesById.TryGetValue((kind, id), out var names) ? names.ToHashSet(StringComparer.OrdinalIgnoreCase) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// True for a value shaped like an op CLI ID: 26 lowercase letters and digits, as in
    /// <c>q1w2e3r4t5y6u7i8o9p0a1s2d3</c>.
    /// </summary>
    public static bool LooksLikeId(string value) => value.Length == 26 && value.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c));

    private static string Normalize(string name) => name.ToUpperInvariant();

    private bool AddUnlocked(AliasPair pair)
    {
        var newId = Get(_idsByName, (pair.Kind, Normalize(pair.Name)), StringComparer.Ordinal).Add(pair.Id);
        var newName = Get(_namesById, (pair.Kind, pair.Id), StringComparer.OrdinalIgnoreCase).Add(pair.Name);
        return newId | newName;
    }

    private void Reseal()
    {
        if (_sealer is not null) _seal = _sealer(Canonical());
    }

    /// <summary>
    /// Both indexes as sorted lines, so the same pairs always seal the same way. Both are
    /// sealed because matching reads both: removing one ID from a name's set could turn a
    /// possible match into a definite one.
    /// </summary>
    // ceiling: rebuilt on every check and change; fine for thousands of pairs.
    private byte[] Canonical()
    {
        var lines = new List<string>();
        foreach (var ((kind, id), names) in _namesById)
        {
            foreach (var name in names) lines.Add($"N\t{kind}\t{id}\t{name}");
        }

        foreach (var ((kind, name), ids) in _idsByName)
        {
            foreach (var id in ids) lines.Add($"I\t{kind}\t{name}\t{id}");
        }

        lines.Sort(StringComparer.Ordinal);
        return Encoding.UTF8.GetBytes(string.Join('\n', lines));
    }

    private static HashSet<string> Get(Dictionary<(AliasKind, string), HashSet<string>> map, (AliasKind, string) key, StringComparer comparer)
    {
        if (!map.TryGetValue(key, out var set)) map[key] = set = new HashSet<string>(comparer);
        return set;
    }
}
