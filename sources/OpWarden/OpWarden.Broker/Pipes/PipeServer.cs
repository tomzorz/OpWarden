using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace OpWarden.Broker.Pipes;

/// <summary>
/// One of the broker's named pipes: an accept loop that keeps an instance listening at
/// all times and serves each connection on its own task.
/// </summary>
/// <remarks>
/// The pipe is created as the first instance of its name, so a process squatting the
/// name before the broker starts stops the broker with an error instead of receiving its
/// clients. An instance listens at all times, so the name is never free between two
/// clients for a squatter to take. Access is limited to the broker's
/// own account and the interactive user (REQ-TRUST-9); the user may connect but not
/// create instances of their own.
/// </remarks>
internal sealed partial class PipeServer : IAsyncDisposable
{
    /// <summary>
    /// Serves one connection. The pipe is disposed when this returns.
    /// </summary>
    public delegate Task Serve(NamedPipeServerStream pipe, CancellationToken stopping);

    private static readonly TimeSpan BusyRetryDelay = TimeSpan.FromSeconds(1);

    private readonly string _name;
    private readonly PipeSecurity _security;
    private readonly Serve _serve;
    private readonly Action<Exception> _connectionFailed;
    private readonly CancellationTokenSource _stopping = new();
    private readonly ConcurrentDictionary<Task, byte> _connections = new();
    private Task? _acceptLoop;

    public PipeServer(string name, SecurityIdentifier user, Serve serve, Action<Exception> connectionFailed)
    {
        (_name, _serve, _connectionFailed) = (name, serve, connectionFailed);
        _security = SecurityFor(user);
    }

    /// <summary>
    /// Creates the first instance and starts listening. The pipe exists when this returns,
    /// so a client started afterwards connects instead of finding no broker.
    /// </summary>
    public void Start()
    {
        if (_acceptLoop is not null) throw new InvalidOperationException($"The pipe server on '{_name}' is already started.");

        NamedPipeServerStream first;
        try
        {
            first = Create(PipeOptions.FirstPipeInstance);
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException)
        {
            // Access denied when the name exists under another owner, busy when its owner
            // allows a single instance: either way someone else holds the name.
            throw new IOException($"Another process already serves \\\\.\\pipe\\{_name}: a second broker, or a process squatting the broker's pipe. The broker cannot start while it does.", e);
        }

        _acceptLoop = AcceptLoopAsync(first, _stopping.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_acceptLoop is not null) await _acceptLoop.ConfigureAwait(false);
        await Task.WhenAll(_connections.Keys).ConfigureAwait(false);
        _stopping.Dispose();
    }

    /// <summary>
    /// The pipe's access list: full control for the account the broker runs as, connect
    /// for the interactive user, and nothing for any network logon, whoever it claims to be.
    /// </summary>
    internal static PipeSecurity SecurityFor(SecurityIdentifier user)
    {
        using var self = WindowsIdentity.GetCurrent();
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(self.User!, PipeAccessRights.FullControl, AccessControlType.Allow));

        // ReadWrite leaves out CreateNewInstance, so the user can talk to the broker but
        // cannot add an instance of their own for the broker's clients to land on.
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return security;
    }

    private NamedPipeServerStream Create(PipeOptions extra = PipeOptions.None) =>
        NamedPipeServerStreamAcl.Create(_name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | extra, 0, 0, _security);

    private async Task AcceptLoopAsync(NamedPipeServerStream listener, CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await listener.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var connection = ServeAsync(listener, cancellationToken);
                _connections.TryAdd(connection, 0);
                _ = connection.ContinueWith(done => _connections.TryRemove(done, out _), TaskScheduler.Default);
                listener = await NextListenerAsync(cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// The next instance. Creation fails only when every instance Windows allows is
    /// connected, which takes a client holding hundreds of connections open; the loop
    /// waits for some to close rather than ending, because an ended loop is a broker
    /// that never answers again.
    /// </summary>
    private async Task<NamedPipeServerStream> NextListenerAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            try
            {
                return Create();
            }
            catch (IOException e)
            {
                _connectionFailed(new IOException($@"Cannot add an instance to \\.\pipe\{_name}: {e.Message}", e));
                await Task.Delay(BusyRetryDelay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                await _serve(pipe, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutting down.
            }
            catch (Exception e)
            {
                // One bad connection must not take the broker down.
                _connectionFailed(e);
            }
        }
    }
}

/// <summary>
/// Who is on the other end of a pipe: the client's process ID, read from the pipe, and
/// its token, taken by impersonating it.
/// </summary>
/// <remarks>
/// The broker's own account cannot read the interactive user's profile, where the op CLI
/// and the agent hosts live, so file checks made for a client run as that client
/// (<see cref="RunAs"/>). The token also answers the elevation question of REQ-TRUST-5.
/// </remarks>
internal sealed partial class PipeClient : IDisposable
{
    private readonly WindowsIdentity _identity;

    private PipeClient(int processId, WindowsIdentity identity) => (ProcessId, _identity) = (processId, identity);

    public int ProcessId { get; }

    /// <summary>
    /// True when the client's token carries the Administrators group enabled, which only
    /// an elevated token does under UAC: a filtered token holds the group deny-only.
    /// </summary>
    public bool IsElevatedAdministrator => new WindowsPrincipal(_identity).IsInRole(WindowsBuiltInRole.Administrator);

    public string Name => _identity.Name;

    /// <summary>
    /// Takes the client's identity. Windows allows impersonation only after the server
    /// has read from the pipe, so call this once the first message is in.
    /// </summary>
    public static PipeClient Capture(NamedPipeServerStream pipe)
    {
        var processId = ProcessIdOf(pipe);
        WindowsIdentity? identity = null;
        pipe.RunAsClient(() => identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Impersonate | TokenAccessLevels.Duplicate));
        return new PipeClient(processId, identity!);
    }

    public static int ProcessIdOf(NamedPipeServerStream pipe) =>
        GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var processId)
            ? (int)processId
            : throw new IOException($"GetNamedPipeClientProcessId failed ({Marshal.GetLastPInvokeError()}).");

    /// <summary>
    /// Runs <paramref name="work"/> as the client.
    /// </summary>
    public T RunAs<T>(Func<T> work) => WindowsIdentity.RunImpersonated(_identity.AccessToken, work);

    public void Dispose() => _identity.Dispose();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);
}
