using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using OpWarden.Core.Pipe;

namespace OpWarden.Broker;

/// <summary>
/// Serves shim connections on the broker's named pipe: one request, one verdict, and
/// the read capture when the protocol calls for one.
/// </summary>
/// <remarks>
/// The verdict comes from <see cref="Decide"/>. Its cancellation token fires when the
/// shim disconnects before the verdict, which is how a prompt for a killed caller gets
/// abandoned (REQ-FAIL-5). The pipe still carries the default security descriptor; the
/// user-only ACL arrives with trust hardening.
/// </remarks>
public sealed partial class ShimPipeServer : IAsyncDisposable
{
    /// <param name="clientProcessId">The shim's process ID, read from the pipe itself: the anchor of caller resolution.</param>
    /// <param name="abandoned">Fires when the shim disconnects, or when the broker shuts down.</param>
    public delegate ValueTask<VerdictResponse> Decide(ShimRequest request, int clientProcessId, CancellationToken abandoned);

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

                if (request.ProtocolVersion != PipeProtocol.Version)
                {
                    await PipeProtocol.WriteAsync(pipe, VerdictResponse.Deny($"the shim speaks pipe protocol {request.ProtocolVersion}, the broker speaks {PipeProtocol.Version}; reinstall OpWarden"), cancellationToken).ConfigureAwait(false);
                    return;
                }

                var verdict = await DecideWatchingForDisconnectAsync(pipe, request, cancellationToken).ConfigureAwait(false);
                if (verdict is null) return;
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

    /// <summary>
    /// Runs <see cref="Decide"/> while a read waits on the pipe. The shim sends nothing
    /// between its request and the verdict, so that read completes only when the shim
    /// disconnects; it then cancels the decision. Returns null when the shim is gone.
    /// </summary>
    private async Task<VerdictResponse?> DecideWatchingForDisconnectAsync(NamedPipeServerStream pipe, ShimRequest request, CancellationToken stopping)
    {
        using var abandoned = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        using var stopWatching = new CancellationTokenSource();
        var watcher = WatchAsync(pipe, abandoned, stopWatching.Token);
        try
        {
            return await _decide(request, ClientProcessId(pipe), abandoned.Token).ConfigureAwait(false);
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

    private static int ClientProcessId(NamedPipeServerStream pipe) =>
        GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId)
            ? (int)processId
            : throw new IOException($"GetNamedPipeClientProcessId failed ({Marshal.GetLastPInvokeError()}).");

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}
