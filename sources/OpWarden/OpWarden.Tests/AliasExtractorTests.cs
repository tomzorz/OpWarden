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
