using System.Text;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class AliasExtractorTests
{
    private const string ItemId = "q1w2e3r4t5y6u7i8o9p0a1s2d3";
    private const string VaultId = "aaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void Reads_the_item_and_its_vault_from_one_item()
    {
        var pairs = Extract($$"""{"id":"{{ItemId}}","title":"GitHub","vault":{"id":"{{VaultId}}","name":"Private"},"category":"LOGIN"}""");

        Assert.Equal([new AliasPair(AliasKind.Item, "GitHub", ItemId), new AliasPair(AliasKind.Vault, "Private", VaultId)], pairs);
    }

    [Fact]
    public void Reads_every_item_of_a_list()
    {
        var pairs = Extract($$$"""[{"id":"{{{ItemId}}}","title":"A","vault":{"id":"{{{VaultId}}}","name":"V"}},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","title":"B"}]""");

        Assert.Equal(3, pairs.Count);
        Assert.Contains(new AliasPair(AliasKind.Item, "B", "bbbbbbbbbbbbbbbbbbbbbbbbbb"), pairs);
    }

    [Fact]
    public void Reads_custom_field_labels_and_never_their_values()
    {
        var pairs = Extract($$$"""{"id":"{{{ItemId}}}","title":"API","fields":[{"id":"password","label":"password","value":"hunter2"},{"id":"dddddddddddddddddddddddddd","label":"API Key","value":"s3cret"}]}""");

        Assert.Equal([new AliasPair(AliasKind.Item, "API", ItemId), new AliasPair(AliasKind.Field, "API Key", "dddddddddddddddddddddddddd")], pairs);
    }

    // The op CLI's real item JSON (op 2.38), anonymised: IDs, names and values replaced,
    // shape and quirks kept. The username field's label is "email"; the vault ID also
    // appears under another name in `op item list`.
    private const string RealItemJson = """
        {
          "id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
          "title": "Example Login",
          "version": 1,
          "vault": { "id": "bbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Personal" },
          "category": "LOGIN",
          "urls": [ { "label": "website", "primary": true, "href": "https://example.com" } ],
          "sections": [ { "id": "Section_cccccccccccccccccccccccccc", "label": "Saved on example.com" } ],
          "fields": [
            { "id": "username", "type": "STRING", "purpose": "USERNAME", "label": "email", "value": "someone@example.com", "reference": "op://Personal/Example Login/email" },
            { "id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "hunter2", "reference": "op://Personal/Example Login/password" },
            { "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "reference": "op://Personal/Example Login/notesPlain" },
            { "id": "dddddddddddddddddddddddddd", "section": { "id": "Section_cccccccccccccccccccccccccc", "label": "Saved on example.com" }, "type": "STRING", "label": "First name", "value": "Someone", "reference": "op://Personal/Example Login/Saved on example.com/First name" }
          ]
        }
        """;

    [Fact]
    public void Reads_every_pair_from_real_item_json_and_no_value()
    {
        var pairs = Extract(RealItemJson);

        Assert.Equal(
            [
                new AliasPair(AliasKind.Item, "Example Login", "aaaaaaaaaaaaaaaaaaaaaaaaaa"),
                new AliasPair(AliasKind.Vault, "Personal", "bbbbbbbbbbbbbbbbbbbbbbbbbb"),
                new AliasPair(AliasKind.Section, "Saved on example.com", "Section_cccccccccccccccccccccccccc"),
                new AliasPair(AliasKind.Field, "email", "username"),
                new AliasPair(AliasKind.Field, "First name", "dddddddddddddddddddddddddd"),
            ],
            pairs);
        Assert.DoesNotContain(pairs, p => p.Name.Contains("hunter2", StringComparison.Ordinal) || p.Name.Contains("someone@", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("hunter2\n")]
    [InlineData("ID:          q1w2e3r4t5y6u7i8o9p0a1s2d3\nTitle:       GitHub\n")]
    [InlineData("""{"id":"not-an-op-id","title":"GitHub"}""")]
    [InlineData("""{"id":"q1w2e3r4t5y6u7i8o9p0a1s2d3","title":""}""")]
    [InlineData("""{"id":42,"title":"GitHub"}""")]
    [InlineData("""["a","b"]""")]
    [InlineData("")]
    public void Yields_nothing_from_anything_else(string output)
    {
        Assert.Empty(Extract(output));
    }

    private static IReadOnlyList<AliasPair> Extract(string output) => AliasExtractor.FromReadOutput(Encoding.UTF8.GetBytes(output));
}
