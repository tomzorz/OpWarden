using System.IO.Pipes;
using System.Security.Principal;
using OpWarden.Broker.Pipes;
using OpWarden.Core.Pipe;

namespace OpWarden.Broker;

/// <summary>
/// Serves shim connections on the broker's named pipe: one request, one verdict, and
/// the read capture when the protocol calls for one.
/// </summary>
/// <remarks>
/// The verdict comes from <see cref="Decide"/>. Its cancellation token fires when the
/// shim disconnects before the verdict, which is how a prompt for a killed caller gets
/// abandoned (REQ-FAIL-5).
/// </remarks>
public sealed class ShimPipeServer : IAsyncDisposable
{
    /// <param name="client">The shim's process ID, the anchor of caller resolution, and its identity, for file checks made on its behalf.</param>
    /// <param name="abandoned">Fires when the shim disconnects, or when the broker shuts down.</param>
    internal delegate ValueTask<VerdictResponse> Decide(ShimRequest request, PipeClient client, CancellationToken abandoned);

    internal delegate ValueTask CaptureReceived(ShimRequest request, ReadCapture capture, CancellationToken cancellationToken);

    private readonly PipeServer _server;
    private readonly Decide _decide;
    private readonly CaptureReceived _captureReceived;

    internal ShimPipeServer(string pipeName, SecurityIdentifier user, Decide decide, CaptureReceived captureReceived, Action<Exception> connectionFailed)
    {
        _decide = decide;
        _captureReceived = captureReceived;
        _server = new PipeServer(pipeName, user, ServeAsync, connectionFailed);
    }

    /// <inheritdoc cref="PipeServer.Start"/>
    public void Start() => _server.Start();

    public ValueTask DisposeAsync() => _server.DisposeAsync();

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        // Closing the pipe without a verdict, which any failure here does, is a deny on
        // the shim's side (REQ-SHIM-6).
        var request = await PipeProtocol.ReadRequestAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (request is null) return;

        if (request.ProtocolVersion != PipeProtocol.Version)
        {
            await PipeProtocol.WriteAsync(pipe, VerdictResponse.Deny($"the shim speaks pipe protocol {request.ProtocolVersion}, the broker speaks {PipeProtocol.Version}; reinstall OpWarden"), cancellationToken).ConfigureAwait(false);
            return;
        }

        using var client = PipeClient.Capture(pipe);
        var verdict = await DecideWatchingForDisconnectAsync(pipe, request, client, cancellationToken).ConfigureAwait(false);
        if (verdict is null) return;
        await PipeProtocol.WriteAsync(pipe, verdict, cancellationToken).ConfigureAwait(false);

        if (!PipeProtocol.ExpectsCapture(request, verdict)) return;
        var capture = await PipeProtocol.ReadCaptureAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (capture is not null) await _captureReceived(request, capture, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs <see cref="Decide"/> while a read waits on the pipe. The shim sends nothing
    /// between its request and the verdict, so that read completes only when the shim
    /// disconnects; it then cancels the decision. Returns null when the shim is gone.
    /// </summary>
    private async Task<VerdictResponse?> DecideWatchingForDisconnectAsync(NamedPipeServerStream pipe, ShimRequest request, PipeClient client, CancellationToken stopping)
    {
        using var abandoned = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        using var stopWatching = new CancellationTokenSource();
        var watcher = WatchAsync(pipe, abandoned, stopWatching.Token);
        try
        {
            return await _decide(request, client, abandoned.Token).ConfigureAwait(false);
        }
        finally
        {
            await stopWatching.CancelAsync().ConfigureAwait(false);
            await watcher.ConfigureAwait(false);
        }
    }

    private static async Task WatchAsync(NamedPipeServerStream pipe, CancellationTokenSource abandoned, CancellationToken stopWatching)
    {
        var probe = new byte[1];
        try
        {
            // Zero bytes is a disconnect; a byte is a shim breaking protocol. Either way the
            // decision has nobody to go to.
            await pipe.ReadAsync(probe, stopWatching).ConfigureAwait(false);
            await abandoned.CancelAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stopWatching.IsCancellationRequested)
        {
            // The verdict is ready; stop watching.
        }
        catch (IOException)
        {
            await abandoned.CancelAsync().ConfigureAwait(false);
        }
    }
}
