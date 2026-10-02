namespace OpWarden.Core;

/// <summary>
/// The vault, item and key an invocation targets. A null field is a field the shim
/// could not parse, which REQ-CLAS-9 and REQ-RULE-5 call unknown.
/// </summary>
public sealed record SecretPath(string? Vault, string? Item, string? Key)
{
    /// <summary>
    /// A path with every field unknown.
    /// </summary>
    public static SecretPath Unknown { get; } = new(null, null, null);
}
