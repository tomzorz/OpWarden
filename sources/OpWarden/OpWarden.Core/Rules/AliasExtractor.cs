using System.Text.Json;

namespace OpWarden.Core.Rules;

/// <summary>
/// Pulls alias pairs out of captured <c>read</c> output (REQ-RULE-15).
/// </summary>
/// <remarks>
/// Reads the op CLI's JSON item shape, from <c>op item get --format json</c> (one item)
/// or <c>op item list --format json</c> (an array): an item carries <c>id</c> and
/// <c>title</c>, and a nested <c>vault</c> object carries <c>id</c> and <c>name</c>.
/// That shape is taken from the op CLI's JSON as commonly seen, not from a documented
/// schema; output in any other shape, human-readable included, yields no pairs. Missing
/// pairs cost precision only: <see cref="FieldMatcher"/> treats an unseen ID as possibly
/// equal to any name, so deny rules do not depend on this.
/// </remarks>
public static class AliasExtractor
{
    public static IReadOnlyList<AliasPair> FromReadOutput(ReadOnlySpan<byte> output)
    {
        var pairs = new List<AliasPair>();
        try
        {
            var reader = new Utf8JsonReader(output, new JsonReaderOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
            using var document = JsonDocument.ParseValue(ref reader);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in root.EnumerateArray()) FromItem(element, pairs);
            }
            else
            {
                FromItem(root, pairs);
            }
        }
        catch (JsonException)
        {
            // Not JSON: a secret value from `op read`, or human-readable output.
        }

        return pairs;
    }

    private static void FromItem(JsonElement item, List<AliasPair> pairs)
    {
        if (item.ValueKind != JsonValueKind.Object) return;

        if (Pair(item, "title", AliasKind.Item) is { } itemPair) pairs.Add(itemPair);
        if (item.TryGetProperty("vault", out var vault) && Pair(vault, "name", AliasKind.Vault) is { } vaultPair) pairs.Add(vaultPair);
    }

    private static AliasPair? Pair(JsonElement element, string nameProperty, AliasKind kind)
    {
        if (element.ValueKind != JsonValueKind.Object) return null;
        if (!element.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) return null;
        if (!element.TryGetProperty(nameProperty, out var name) || name.ValueKind != JsonValueKind.String) return null;

        var idValue = id.GetString()!;
        var nameValue = name.GetString()!;
        return AliasStore.LooksLikeId(idValue) && nameValue.Length > 0 ? new AliasPair(kind, nameValue, idValue) : null;
    }
}
