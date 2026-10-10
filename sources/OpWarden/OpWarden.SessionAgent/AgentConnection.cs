using System.IO;
using System.IO.Pipes;
using System.Threading.Channels;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent's end of the broker pipe: connects, reconnects whenever the broker
/// goes away, hands each incoming message to <paramref name="received"/>, and sends
/// decisions and lock events in order. Holds no state of its own (spec glossary: session agent).
/// </summary>
internal sealed class AgentConnection(string pipeName, Action<AgentMessage> received, Action<bool> connectedChanged)
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(2);

    // A refusal does not go away on its own (another session agent is pinned, or this
    // one is not the installed copy), and each attempt costs an audit-log entry.
    private static readonly TimeSpan RefusedRetryDelay = TimeSpan.FromMinutes(1);

    private readonly Channel<AgentMessage> _outgoing = Channel.CreateUnbounded<AgentMessage>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>
    /// Queues a message for the broker. A decision made while disconnected is lost; the
    /// broker times the prompt out into a deny, which is the safe failure.
    /// </summary>
    public void Send(AgentMessage message) => _outgoing.Writer.TryWrite(message);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var delay = RetryDelay;
            try
            {
                await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
                connectedChanged(true);
                AgentLog.Write($"connected to the broker on '{pipeName}'");

                using var connection = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var sending = SendLoopAsync(pipe, connection.Token);
                while (await AgentProtocol.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) is { } message)
                {
                    if (message is AgentRefused refused)
                    {
                        AgentLog.Write($"the broker refused this session agent: {refused.Reason}");
                        delay = RefusedRetryDelay;
                    }

                    received(message);
                }

                await connection.CancelAsync().ConfigureAwait(false);
                await sending.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException)
            {
                AgentLog.Write($"broker connection lost: {e.Message}");
            }

            connectedChanged(false);
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendLoopAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var message in _outgoing.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                await AgentProtocol.WriteAsync(pipe, message, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The connection ended.
        }
        catch (IOException e)
        {
            AgentLog.Write($"could not send to the broker: {e.Message}");
        }
    }
}
