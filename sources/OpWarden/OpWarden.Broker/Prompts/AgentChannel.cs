using System.IO.Pipes;
using System.Threading.Channels;
using OpWarden.Core.Agent;

namespace OpWarden.Broker.Prompts;

/// <summary>
/// The broker's end of the session-agent pipe: one session agent at a time, prompts and
/// notices out, decisions in.
/// </summary>
/// <remarks>
/// Outgoing messages go through one ordered channel, so a <see cref="ClosePrompt"/> never
/// overtakes the <see cref="ShowPrompt"/> it closes. Prompt messages sent while no session
/// agent is connected are dropped, and a session agent that connects is sent the prompt
/// on screen. Notices are kept until a session agent connects, so a warning raised at
/// start, before any session agent exists, still reaches the user (REQ-INT-8).
/// Pinning the session agent to the process the broker started (REQ-TRUST-4) arrives
/// with trust hardening.
/// </remarks>
public sealed class AgentChannel : IAsyncDisposable
{
    private readonly string _pipeName;
    private readonly Action<Exception> _connectionFailed;
    private readonly Channel<AgentMessage> _outgoing = Channel.CreateUnbounded<AgentMessage>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _stopping = new();
    private const int MaxHeldNotices = 20;

    private readonly Queue<ShowNotice> _heldNotices = new();
    private readonly Lock _noticeLock = new();
    private readonly Action _workstationLocked;
    private PromptQueue? _prompts;
    private NamedPipeServerStream? _connected;
    private Task? _acceptLoop;
    private Task? _sendLoop;

    public AgentChannel(string pipeName, Action<Exception> connectionFailed, Action workstationLocked) =>
        (_pipeName, _connectionFailed, _workstationLocked) = (pipeName, connectionFailed, workstationLocked);

    /// <summary>
    /// Queues a message for the connected session agent.
    /// </summary>
    public void Send(AgentMessage message) => _outgoing.Writer.TryWrite(message);

    public void Start(PromptQueue prompts)
    {
        if (_acceptLoop is not null) throw new InvalidOperationException($"The session-agent channel on '{_pipeName}' is already started.");
        _prompts = prompts;
        var first = CreateListener();
        _acceptLoop = AcceptLoopAsync(first, _stopping.Token);
        _sendLoop = SendLoopAsync(_stopping.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _outgoing.Writer.TryComplete();
        if (_acceptLoop is not null) await _acceptLoop.ConfigureAwait(false);
        if (_sendLoop is not null) await _sendLoop.ConfigureAwait(false);
        _stopping.Dispose();
    }

    private NamedPipeServerStream CreateListener() =>
        new(_pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

    private async Task AcceptLoopAsync(NamedPipeServerStream listener, CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await listener.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                Volatile.Write(ref _connected, listener);
                if (_prompts!.CurrentPrompt() is { } showing) Send(showing);
                lock (_noticeLock)
                {
                    while (_heldNotices.TryDequeue(out var notice)) Send(notice);
                }

                await ReceiveAsync(listener, cancellationToken).ConfigureAwait(false);

                Volatile.Write(ref _connected, null);
                await listener.DisposeAsync().ConfigureAwait(false);
                listener = CreateListener();
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

    private async Task ReceiveAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            while (await AgentProtocol.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) is { } message)
            {
                // A session agent sends decisions and lock events; anything else is ignored.
                if (message is DecisionMade decision) _prompts!.Decide(decision);
                else if (message is WorkstationLocked) _workstationLocked();
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException)
        {
            _connectionFailed(e);
        }
    }

    private void Hold(ShowNotice notice)
    {
        lock (_noticeLock)
        {
            if (_heldNotices.Count == MaxHeldNotices) _heldNotices.Dequeue();
            _heldNotices.Enqueue(notice);
        }
    }

    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var message in _outgoing.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (Volatile.Read(ref _connected) is not { IsConnected: true } pipe)
                {
                    if (message is ShowNotice notice) Hold(notice);
                    continue;
                }

                try
                {
                    await AgentProtocol.WriteAsync(pipe, message, cancellationToken).ConfigureAwait(false);
                }
                catch (IOException e)
                {
                    // The session agent went away mid-write; the receive side notices too
                    // and the next session agent is sent the prompt on screen.
                    _connectionFailed(e);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }
}
