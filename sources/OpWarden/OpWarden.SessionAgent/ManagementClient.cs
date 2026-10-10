using System.IO;
using System.IO.Pipes;
using OpWarden.Core.Management;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent's end of the management pipe: one connection per request, so a
/// window never holds the broker's attention while it sits open.
/// </summary>
internal sealed class ManagementClient(string pipeName)
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);

    public async Task<ManagementResponse> SendAsync(ManagementRequest request)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync((int)ConnectTimeout.TotalMilliseconds).ConfigureAwait(false);
        await ManagementProtocol.WriteAsync(pipe, request, CancellationToken.None).ConfigureAwait(false);
        return await ManagementProtocol.ReadResponseAsync(pipe, CancellationToken.None).ConfigureAwait(false)
            ?? throw new IOException($"The broker closed \\\\.\\pipe\\{pipeName} without answering.");
    }

    /// <summary>
    /// <see cref="SendAsync"/>, with a broker that cannot be reached turned into the
    /// sentence a window shows instead of the answer.
    /// </summary>
    public async Task<ManagementResponse> TrySendAsync(ManagementRequest request)
    {
        try
        {
            return await SendAsync(request).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException)
        {
            return new ManagementResponse($"The broker cannot be reached ({e.Message}).");
        }
    }
}
