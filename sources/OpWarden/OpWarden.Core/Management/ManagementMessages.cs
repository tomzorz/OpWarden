using System.Text.Json.Serialization;
using OpWarden.Core.Pipe;
using OpWarden.Core.Rules;

namespace OpWarden.Core.Management;

/// <summary>
/// A request from the management window. Reading the rules and the status, and flushing
/// the cache, take any connection; a rule mutation takes an elevated Administrators token
/// (REQ-TRUST-5).
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(ListRules), "list-rules")]
[JsonDerivedType(typeof(AddRules), "add-rules")]
[JsonDerivedType(typeof(RemoveRule), "remove-rule")]
[JsonDerivedType(typeof(SetPromptAlways), "set-prompt-always")]
[JsonDerivedType(typeof(FlushCache), "flush-cache")]
[JsonDerivedType(typeof(GetStatus), "get-status")]
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
/// What the broker is doing: for the session agent's status view, and so the agent can
/// find the audit log it is allowed to read (REQ-TRUST-2).
/// </summary>
public sealed record GetStatus : ManagementRequest
{
    public override bool MutatesRules => false;
}

/// <param name="DataDirectory">Where the rule store and the audit log live.</param>
/// <param name="Account">The account the broker runs as: the service account when installed, the user in a console.</param>
/// <param name="ProcessEventsAvailable">False when the broker resolves callers by the live walk alone (REQ-CALL-20).</param>
/// <param name="CacheEntries">Values cached right now.</param>
public sealed record BrokerStatus(string DataDirectory, string Account, bool ProcessEventsAvailable, int CacheEntries, DateTimeOffset StartedAt, string Version);

/// <summary>
/// The broker's answer: the rules as they stand after the request with their notices, the
/// status, or why the request was refused.
/// </summary>
/// <param name="Flushed">The number of cache entries a <see cref="FlushCache"/> deleted.</param>
/// <param name="Notices">The rule notices of REQ-RULE-29 to REQ-RULE-31, beside the rules they are about.</param>
public sealed record ManagementResponse(string? Error, RuleSet? Rules = null, int? Flushed = null, BrokerStatus? Status = null, IReadOnlyList<RuleNotice>? Notices = null);

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
