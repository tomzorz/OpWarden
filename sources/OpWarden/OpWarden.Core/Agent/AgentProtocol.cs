using System.Text.Json.Serialization;
using OpWarden.Core.Pipe;

namespace OpWarden.Core.Agent;

/// <summary>
/// The broker–session agent conversation: <see cref="AgentMessage"/>s in both directions,
/// one per frame, for as long as the session agent stays connected.
/// </summary>
public static class AgentProtocol
{
    public const string DefaultPipeName = "OpWarden.Agent";

    public static Task WriteAsync(Stream stream, AgentMessage message, CancellationToken cancellationToken) =>
        Framing.WriteAsync(stream, message, AgentJsonContext.Default.AgentMessage, cancellationToken);

    /// <summary>
    /// Reads the next message, or returns null when the peer closed the pipe.
    /// </summary>
    public static Task<AgentMessage?> ReadAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, AgentJsonContext.Default.AgentMessage, cancellationToken);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true)]
[JsonSerializable(typeof(AgentMessage))]
internal sealed partial class AgentJsonContext : JsonSerializerContext;
