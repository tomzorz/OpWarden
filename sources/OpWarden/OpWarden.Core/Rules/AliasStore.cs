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
/// </remarks>
public sealed class AliasStore
{
    private readonly Lock _lock = new();
    private readonly Dictionary<(AliasKind, string), HashSet<string>> _idsByName = [];
    private readonly Dictionary<(AliasKind, string), HashSet<string>> _namesById = [];

    public void Add(AliasPair pair)
    {
        lock (_lock)
        {
            Get(_idsByName, (pair.Kind, Normalize(pair.Name)), StringComparer.Ordinal).Add(pair.Id);
            Get(_namesById, (pair.Kind, pair.Id), StringComparer.OrdinalIgnoreCase).Add(pair.Name);
        }
    }

    public void AddRange(IEnumerable<AliasPair> pairs)
    {
        foreach (var pair in pairs) Add(pair);
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

    private static HashSet<string> Get(Dictionary<(AliasKind, string), HashSet<string>> map, (AliasKind, string) key, StringComparer comparer)
    {
        if (!map.TryGetValue(key, out var set)) map[key] = set = new HashSet<string>(comparer);
        return set;
    }
}
