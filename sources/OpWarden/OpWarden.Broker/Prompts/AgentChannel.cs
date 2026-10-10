using System.IO.Pipes;
using System.Security.Principal;
using System.Threading.Channels;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Pipes;
using OpWarden.Core.Agent;

namespace OpWarden.Broker.Prompts;

/// <summary>
/// The broker's end of the session-agent pipe: one pinned session agent at a time,
/// prompts and notices out, decisions in.
/// </summary>
/// <remarks>
/// Outgoing messages go through one ordered channel, so a <see cref="ClosePrompt"/> never
/// overtakes the <see cref="ShowPrompt"/> it closes. Prompt messages sent while no session
/// agent is pinned are dropped, and a session agent that is pinned is sent the prompt on
/// screen. Notices are kept until a session agent is pinned, so a warning raised at start,
/// before any session agent exists, still reaches the user (REQ-INT-8).
/// A connection is pinned only when <see cref="SessionAgentGate"/> passes it and no other
/// is pinned; any other connection is told why and closed, and both outcomes go to the
/// audit log (REQ-TRUST-4, REQ-TRUST-8).
/// </remarks>
public sealed class AgentChannel : IAsyncDisposable
{
    private const int MaxHeldNotices = 20;

    private readonly Action<Exception> _connectionFailed;
    private readonly Channel<AgentMessage> _outgoing = Channel.CreateUnbounded<AgentMessage>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _stopping = new();
    private readonly Queue<ShowNotice> _heldNotices = new();
    private readonly Lock _noticeLock = new();
    private readonly Action _workstationLocked;
    private readonly SessionAgentGate _gate;
    private readonly AuditLog _audit;
    private readonly PipeServer _server;
    private PromptQueue? _prompts;
    private NamedPipeServerStream? _connected;
    private Task? _sendLoop;

    internal AgentChannel(string pipeName, SecurityIdentifier user, SessionAgentGate gate, AuditLog audit, Action<Exception> connectionFailed, Action workstationLocked)
    {
        (_gate, _audit, _connectionFailed, _workstationLocked) = (gate, audit, connectionFailed, workstationLocked);

        // Any number of connections: one is pinned, and every other one hears why it is
        // refused instead of finding the pipe busy.
        _server = new PipeServer(pipeName, user, ServeAsync, connectionFailed);
    }

    /// <summary>
    /// Queues a message for the pinned session agent.
    /// </summary>
    public void Send(AgentMessage message) => _outgoing.Writer.TryWrite(message);

    public void Start(PromptQueue prompts)
    {
        if (_sendLoop is not null) throw new InvalidOperationException("The session-agent channel is already started.");
        _prompts = prompts;
        _server.Start();
        _sendLoop = SendLoopAsync(_stopping.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _outgoing.Writer.TryComplete();
        await _server.DisposeAsync().ConfigureAwait(false);
        if (_sendLoop is not null) await _sendLoop.ConfigureAwait(false);
        _stopping.Dispose();
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var check = _gate.Check(PipeClient.ProcessIdOf(pipe));
        var refusal = check.Refusal ?? (Interlocked.CompareExchange(ref _connected, pipe, null) is null ? null : "another session agent is pinned");
        if (refusal is not null)
        {
            Record("agent-refused", $"Refused the session-agent connection from {check.Client}: {refusal}.");
            await AgentProtocol.WriteAsync(pipe, new AgentRefused(refusal), cancellationToken).ConfigureAwait(false);
            return;
        }

        Record("agent-pinned", $"Pinned the session agent {check.Client}.");
        try
        {
            if (_prompts!.CurrentPrompt() is { } showing) Send(showing);
            lock (_noticeLock)
            {
                while (_heldNotices.TryDequeue(out var notice)) Send(notice);
            }

            await ReceiveAsync(pipe, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Volatile.Write(ref _connected, null);
        }
    }

    private void Record(string eventName, string detail)
    {
        try
        {
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, eventName, Detail: detail));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _connectionFailed(e);
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
                catch (Exception e) when (e is IOException or ObjectDisposedException)
                {
                    // The session agent went away mid-write; the receive side notices too
                    // and the next pinned session agent is sent the prompt on screen.
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
