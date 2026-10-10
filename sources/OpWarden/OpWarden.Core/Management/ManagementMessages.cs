using System.Text.Json.Serialization;
using OpWarden.Core.Pipe;
using OpWarden.Core.Rules;

namespace OpWarden.Core.Management;

/// <summary>
/// A request from the management window. Reading the rules and flushing the cache take
/// any connection; a rule mutation takes an elevated Administrators token (REQ-TRUST-5).
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(ListRules), "list-rules")]
[JsonDerivedType(typeof(AddRules), "add-rules")]
[JsonDerivedType(typeof(RemoveRule), "remove-rule")]
[JsonDerivedType(typeof(SetPromptAlways), "set-prompt-always")]
[JsonDerivedType(typeof(FlushCache), "flush-cache")]
public abstract record ManagementRequest
{
    /// <summary>
    /// True for the requests REQ-TRUST-5 gates.
    /// </summary>
    [JsonIgnore]
    public virtual bool MutatesRules => true;
}

public sealed record ListRules : ManagementRequest
{
    public override bool MutatesRules => false;
}

public sealed record AddRules(IReadOnlyList<Rule> Rules) : ManagementRequest;

/// <summary>
/// Deletes the stored rule equal to <paramref name="Rule"/> in every field.
/// </summary>
public sealed record RemoveRule(Rule Rule) : ManagementRequest;

/// <summary>
/// Marks a vault <c>prompt-always</c>, or clears the mark (REQ-RULE-17).
/// </summary>
public sealed record SetPromptAlways(string Vault, bool PromptAlways) : ManagementRequest;

/// <summary>
/// Deletes every cache entry (REQ-CACHE-8). Flushing only takes access away, so it needs
/// no elevation.
/// </summary>
public sealed record FlushCache : ManagementRequest
{
    public override bool MutatesRules => false;
}

/// <summary>
/// The broker's answer: the rules as they stand after the request, or why the request
/// was refused.
/// </summary>
/// <param name="Flushed">The number of cache entries a <see cref="FlushCache"/> deleted.</param>
public sealed record ManagementResponse(string? Error, RuleSet? Rules = null, int? Flushed = null);

/// <summary>
/// The broker–management window conversation: a request, a response, repeated for as
/// long as the window stays connected.
/// </summary>
public static class ManagementProtocol
{
    public const string DefaultPipeName = "OpWarden.Manage";

    public static Task WriteAsync(Stream stream, ManagementRequest message, CancellationToken cancellationToken) =>
        Framing.WriteAsync(stream, message, ManagementJsonContext.Default.ManagementRequest, cancellationToken);

    public static Task WriteAsync(Stream stream, ManagementResponse message, CancellationToken cancellationToken) =>
        Framing.WriteAsync(stream, message, ManagementJsonContext.Default.ManagementResponse, cancellationToken);

    /// <summary>
    /// Reads the next request, or returns null when the window closed the pipe.
    /// </summary>
    public static Task<ManagementRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, ManagementJsonContext.Default.ManagementRequest, cancellationToken);

    public static Task<ManagementResponse?> ReadResponseAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, ManagementJsonContext.Default.ManagementResponse, cancellationToken);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ManagementRequest))]
[JsonSerializable(typeof(ManagementResponse))]
internal sealed partial class ManagementJsonContext : JsonSerializerContext;
