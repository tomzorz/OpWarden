using OpWarden.Core;

namespace OpWarden.Tests;

public sealed class SecretReferenceTests
{
    [Theory]
    [InlineData("op://v/i/f", "v", "i", "f")]
    [InlineData("OP://v/i/f", "v", "i", "f")]
    [InlineData("op://v/i/section/field", "v", "i", "section/field")]
    [InlineData("op://v/i/f?attribute=otp", "v", "i", "f")]
    [InlineData("op://v/i/s/f?ssh-format=openssh", "v", "i", "s/f")]
    [InlineData("op://dev-1/my_item.v2/Access Keys", "dev-1", "my_item.v2", "Access Keys")]
    public void Parses_well_formed_references(string reference, string vault, string item, string key)
    {
        Assert.Equal(new SecretPath(vault, item, key), SecretReference.TryParse(reference));
    }

    [Theory]
    [InlineData("op://v/i")]
    [InlineData("op://v/i/s/f/extra")]
    [InlineData("op://v//f")]
    [InlineData("op:///i/f")]
    [InlineData("op://v/i/f#")]
    [InlineData("op://v/i/fé")]
    [InlineData("https://v/i/f")]
    [InlineData("v/i/f")]
    [InlineData("op://$X/i/f")]
    public void Rejects_malformed_references(string reference)
    {
        Assert.Null(SecretReference.TryParse(reference));
    }

    [Theory]
    [InlineData("op://$APP_ENV/db/password", "prod", "db", "password")]
    [InlineData("op://${APP_ENV}/db/password", "prod", "db", "password")]
    [InlineData("op://$APP_ENV-x/db/password", "prod-x", "db", "password")]
    [InlineData("op://v/${ITEM}/f", "v", "my item", "f")]
    public void Expands_variables_from_the_environment(string reference, string vault, string item, string key)
    {
        var environment = new Dictionary<string, string> { ["APP_ENV"] = "prod", ["ITEM"] = "my item" };

        Assert.Equal(new SecretPath(vault, item, key), SecretReference.TryParseExpanded(reference, environment));
    }

    [Theory]
    [InlineData("op://$MISSING/db/password")]
    [InlineData("op://${APP_ENV/db/password")]
    [InlineData("op://$/db/password")]
    [InlineData("op://${}/db/password")]
    [InlineData("op://${1X}/db/password")]
    [InlineData("op://$BAD/db/password")]
    public void Unexpandable_references_are_unknown(string reference)
    {
        var environment = new Dictionary<string, string> { ["APP_ENV"] = "prod", ["BAD"] = "a/b" };

        Assert.Null(SecretReference.TryParseExpanded(reference, environment));
    }
}
