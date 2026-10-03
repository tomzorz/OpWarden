using System.IO.Pipes;
using System.Threading.Channels;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent's end of the broker pipe: connects, reconnects whenever the broker
/// goes away, hands each incoming message to <paramref name="received"/>, and sends
/// decisions in order. Holds no state of its own (spec glossary: session agent).
/// </summary>
internal sealed class AgentConnection(string pipeName, Action<AgentMessage> received, Action<bool> connectedChanged)
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(2);

    private readonly Channel<DecisionMade> _outgoing = Channel.CreateUnbounded<DecisionMade>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>
    /// Queues a decision for the broker. A decision made while disconnected is lost; the
    /// broker times the prompt out into a deny, which is the safe failure.
    /// </summary>
    public void Send(DecisionMade decision) => _outgoing.Writer.TryWrite(decision);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(cancellationToken).ConfigureAwait(false);
                connectedChanged(true);
                AgentLog.Write($"connected to the broker on '{pipeName}'");

                using var connection = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var sending = SendLoopAsync(pipe, connection.Token);
                while (await AgentProtocol.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) is { } message) received(message);

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
            await Task.Delay(RetryDelay, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendLoopAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var decision in _outgoing.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                await AgentProtocol.WriteAsync(pipe, decision, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The connection ended.
        }
        catch (IOException e)
        {
            AgentLog.Write($"could not send a decision: {e.Message}");
        }
    }
}
