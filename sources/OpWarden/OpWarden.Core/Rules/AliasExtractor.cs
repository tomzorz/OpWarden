using System.Text.Json;

namespace OpWarden.Core.Rules;

/// <summary>
/// Pulls alias pairs out of captured <c>read</c> output (REQ-RULE-15).
/// </summary>
/// <remarks>
/// Reads the op CLI's JSON item shape, from <c>op item get --format json</c> (one item)
/// or <c>op item list --format json</c> (an array): an item carries <c>id</c> and
/// <c>title</c>, a nested <c>vault</c> object carries <c>id</c> and <c>name</c>, each
/// entry of <c>sections</c> carries <c>id</c> and <c>label</c>, and each entry of
/// <c>fields</c> carries <c>id</c>, <c>label</c> and an optional <c>section</c>. Field
/// values sit beside them in the same objects and are never read. The shape is the op
/// CLI's own output, checked against op 2.38; output in any other shape, human-readable
/// included, yields no pairs. Missing
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
        if (item.TryGetProperty("sections", out var sections) && sections.ValueKind == JsonValueKind.Array)
        {
            foreach (var section in sections.EnumerateArray())
            {
                if (Pair(section, "label", AliasKind.Section) is { } sectionPair) pairs.Add(sectionPair);
            }
        }

        if (item.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
        {
            foreach (var field in fields.EnumerateArray())
            {
                if (Pair(field, "label", AliasKind.Field) is { } fieldPair) pairs.Add(fieldPair);
            }
        }
    }

    private static AliasPair? Pair(JsonElement element, string nameProperty, AliasKind kind)
    {
        if (element.ValueKind != JsonValueKind.Object) return null;
        if (!element.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String) return null;
        if (!element.TryGetProperty(nameProperty, out var name) || name.ValueKind != JsonValueKind.String) return null;

        var idValue = id.GetString()!;
        var nameValue = name.GetString()!;
        // A built-in field whose label equals its ID ("password") has no second form.
        var distinct = !string.Equals(idValue, nameValue, StringComparison.OrdinalIgnoreCase);
        return AliasStore.IsIdForm(kind, idValue) && nameValue.Length > 0 && distinct ? new AliasPair(kind, nameValue, idValue) : null;
    }
}
