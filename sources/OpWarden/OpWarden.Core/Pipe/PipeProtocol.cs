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
        Framing.WriteAsync(stream, message, ProtocolJsonContext.Default.ShimRequest, cancellationToken);

    public static Task WriteAsync(Stream stream, VerdictResponse message, CancellationToken cancellationToken) =>
        Framing.WriteAsync(stream, message, ProtocolJsonContext.Default.VerdictResponse, cancellationToken);

    public static Task WriteAsync(Stream stream, ReadCapture message, CancellationToken cancellationToken) =>
        Framing.WriteAsync(stream, message, ProtocolJsonContext.Default.ReadCapture, cancellationToken);

    /// <summary>
    /// Reads the next request, or returns null when the peer closed the pipe cleanly.
    /// </summary>
    public static Task<ShimRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, ProtocolJsonContext.Default.ShimRequest, cancellationToken);

    /// <summary>
    /// Reads the broker's verdict, or returns null when the broker closed the pipe.
    /// </summary>
    public static Task<VerdictResponse?> ReadVerdictAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, ProtocolJsonContext.Default.VerdictResponse, cancellationToken);

    /// <summary>
    /// Reads the read capture, or returns null when the shim closed the pipe without one.
    /// </summary>
    public static Task<ReadCapture?> ReadCaptureAsync(Stream stream, CancellationToken cancellationToken) =>
        Framing.ReadAsync(stream, ProtocolJsonContext.Default.ReadCapture, cancellationToken);
}
