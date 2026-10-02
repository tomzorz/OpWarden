using System.Collections.Concurrent;
using System.IO.Pipes;
using OpWarden.Core.Pipe;

namespace OpWarden.Broker;

/// <summary>
/// Serves shim connections on the broker's named pipe: one request, one verdict, and
/// the read capture when the protocol calls for one.
/// </summary>
/// <remarks>
/// The verdict comes from <see cref="Decide"/>, which is where the rule engine and the
/// prompt flow plug in. The pipe still carries the default security descriptor; the
/// user-only ACL and the client-identity checks arrive with trust hardening.
/// </remarks>
public sealed class ShimPipeServer : IAsyncDisposable
{
    public delegate ValueTask<VerdictResponse> Decide(ShimRequest request, CancellationToken cancellationToken);

    public delegate ValueTask CaptureReceived(ShimRequest request, ReadCapture capture, CancellationToken cancellationToken);

    private readonly string _pipeName;
    private readonly Decide _decide;
    private readonly CaptureReceived _captureReceived;
    private readonly Action<Exception> _connectionFailed;
    private readonly CancellationTokenSource _stopping = new();
    private readonly ConcurrentDictionary<Task, byte> _connections = new();
    private Task? _acceptLoop;

    public ShimPipeServer(string pipeName, Decide decide, CaptureReceived captureReceived, Action<Exception> connectionFailed)
    {
        _pipeName = pipeName;
        _decide = decide;
        _captureReceived = captureReceived;
        _connectionFailed = connectionFailed;
    }

    /// <summary>
    /// Starts listening. The first pipe instance exists when this returns, so a shim
    /// started afterwards connects instead of finding no broker.
    /// </summary>
    public void Start()
    {
        if (_acceptLoop is not null) throw new InvalidOperationException($"The pipe server on '{_pipeName}' is already started.");
        var first = CreateListener();
        _acceptLoop = AcceptLoopAsync(first, _stopping.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_acceptLoop is not null) await _acceptLoop.ConfigureAwait(false);
        await Task.WhenAll(_connections.Keys).ConfigureAwait(false);
        _stopping.Dispose();
    }

    private NamedPipeServerStream CreateListener() =>
        new(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    private async Task AcceptLoopAsync(NamedPipeServerStream listener, CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await listener.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var connected = listener;

                // The next instance is listening before this connection is served, so a
                // burst of shims never finds the pipe busy.
                listener = CreateListener();

                var connection = ServeAsync(connected, cancellationToken);
                _connections.TryAdd(connection, 0);
                _ = connection.ContinueWith(done => _connections.TryRemove(done, out _), TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Shutting down.
        }
        finally
        {
            await listener.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                var request = await PipeProtocol.ReadRequestAsync(pipe, cancellationToken).ConfigureAwait(false);
                if (request is null) return;

                var verdict = request.ProtocolVersion == PipeProtocol.Version
                    ? await _decide(request, cancellationToken).ConfigureAwait(false)
                    : VerdictResponse.Deny($"the shim speaks pipe protocol {request.ProtocolVersion}, the broker speaks {PipeProtocol.Version}; reinstall OpWarden");
                await PipeProtocol.WriteAsync(pipe, verdict, cancellationToken).ConfigureAwait(false);

                if (!PipeProtocol.ExpectsCapture(request, verdict)) return;
                var capture = await PipeProtocol.ReadCaptureAsync(pipe, cancellationToken).ConfigureAwait(false);
                if (capture is not null) await _captureReceived(request, capture, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutting down.
            }
            catch (Exception e)
            {
                // One bad connection must not take the broker down. Closing the pipe
                // without a verdict is a deny on the shim's side (REQ-SHIM-6).
                _connectionFailed(e);
            }
        }
    }
}
