using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace OpWarden.Core.Pipe;

/// <summary>
/// The shim–broker conversation over a named pipe: the shim sends a <see cref="ShimRequest"/>,
/// the broker answers with a <see cref="VerdictResponse"/>, and when
/// <see cref="ExpectsCapture"/> holds the shim sends one <see cref="ReadCapture"/> after
/// the op CLI exits. Each message is one frame: a 4-byte little-endian length, then
/// that many bytes of UTF-8 JSON.
/// </summary>
public static class PipeProtocol
{
    public const int Version = 1;

    public const string DefaultPipeName = "OpWarden";

    /// <summary>
    /// Overrides the pipe name, so tests can run a broker beside an installed one. It
    /// grants nothing: whoever sets a caller's environment also sets its PATH.
    /// </summary>
    public const string PipeNameVariable = "OPWARDEN_PIPE";

    // ceiling: one frame holds one whole message; a document read larger than this is
    // relayed in full but captured truncated, and then never cached.
    public const int MaxFrameBytes = 16 * 1024 * 1024;

    public static string ResolvePipeName() => Environment.GetEnvironmentVariable(PipeNameVariable) is { Length: > 0 } name ? name : DefaultPipeName;

    /// <summary>
    /// True when the shim owes the broker a <see cref="ReadCapture"/>: an allowed
    /// <c>read</c> that runs the op CLI (REQ-SHIM-9).
    /// </summary>
    public static bool ExpectsCapture(ShimRequest request, VerdictResponse verdict) =>
        request.Action == OpAction.Read && verdict.Verdict == Verdict.Allow && verdict.Cached is null;

    public static Task WriteAsync(Stream stream, ShimRequest message, CancellationToken cancellationToken) =>
        WriteFrameAsync(stream, message, ProtocolJsonContext.Default.ShimRequest, cancellationToken);

    public static Task WriteAsync(Stream stream, VerdictResponse message, CancellationToken cancellationToken) =>
        WriteFrameAsync(stream, message, ProtocolJsonContext.Default.VerdictResponse, cancellationToken);

    public static Task WriteAsync(Stream stream, ReadCapture message, CancellationToken cancellationToken) =>
        WriteFrameAsync(stream, message, ProtocolJsonContext.Default.ReadCapture, cancellationToken);

    /// <summary>
    /// Reads the next request, or returns null when the peer closed the pipe cleanly.
    /// </summary>
    public static Task<ShimRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken) =>
        ReadFrameAsync(stream, ProtocolJsonContext.Default.ShimRequest, cancellationToken);

    /// <summary>
    /// Reads the broker's verdict, or returns null when the broker closed the pipe.
    /// </summary>
    public static Task<VerdictResponse?> ReadVerdictAsync(Stream stream, CancellationToken cancellationToken) =>
        ReadFrameAsync(stream, ProtocolJsonContext.Default.VerdictResponse, cancellationToken);

    /// <summary>
    /// Reads the read capture, or returns null when the shim closed the pipe without one.
    /// </summary>
    public static Task<ReadCapture?> ReadCaptureAsync(Stream stream, CancellationToken cancellationToken) =>
        ReadFrameAsync(stream, ProtocolJsonContext.Default.ReadCapture, cancellationToken);

    private static async Task WriteFrameAsync<T>(Stream stream, T message, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, typeInfo);
        if (payload.Length > MaxFrameBytes) throw new InvalidDataException($"OpWarden pipe frame of {payload.Length} bytes exceeds the {MaxFrameBytes}-byte limit ({typeof(T).Name}).");

        var frame = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame, 4);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T?> ReadFrameAsync<T>(Stream stream, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : class
    {
        var header = new byte[4];
        var headerRead = await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (headerRead == 0) return null;
        if (headerRead < header.Length) throw new EndOfStreamException($"OpWarden pipe closed inside a frame header ({headerRead} of 4 bytes, {typeof(T).Name}).");

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 0 or > MaxFrameBytes) throw new InvalidDataException($"OpWarden pipe frame announces {length} bytes, outside 0..{MaxFrameBytes} ({typeof(T).Name}).");

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize(payload, typeInfo)
               ?? throw new InvalidDataException($"OpWarden pipe frame decoded to null ({typeof(T).Name}).");
    }
}
