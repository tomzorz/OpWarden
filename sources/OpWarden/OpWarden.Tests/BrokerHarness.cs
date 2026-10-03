using System.IO.Pipes;
using System.Text.Json;
using System.Threading.Channels;
using OpWarden.Broker;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The whole broker on pipes and files of its own: shim server, session-agent channel,
/// prompt queue, rule store, alias file and audit log, wired as the console host wires
/// them. Only the caller resolver is the test's, until the process map exists.
/// </summary>
internal sealed class BrokerHarness : IAsyncDisposable
{
    private readonly DirectoryInfo _data = Directory.CreateTempSubdirectory("opwarden-broker-");
    private readonly AgentChannel _agent;
    private readonly ShimPipeServer _shims;

    private BrokerHarness(TimeSpan promptTimeout, CallerIdentity caller, IEnumerable<Rule> rules)
    {
        Rules = RuleStore.Open(Path.Combine(_data.FullName, "rules.json"));
        Rules.Add(rules);
        AliasFile = new AliasFile(Path.Combine(_data.FullName, "aliases.json"));
        Aliases = AliasFile.Load();
        var audit = new AuditLog(AuditPath);

        _agent = new AgentChannel(AgentPipeName, ConnectionErrors.Add);
        var prompts = new PromptQueue(10, promptTimeout, _agent.Send);
        var broker = new BrokerService(new BrokerSettings(BuiltExecutables.Probe), Rules, Aliases, AliasFile, audit, prompts, _agent.Send, _ => caller);
        _shims = new ShimPipeServer(ShimPipeName, broker.DecideAsync, (request, capture, _) => broker.CaptureReceivedAsync(request, capture), ConnectionErrors.Add);
        _agent.Start(prompts);
        _shims.Start();
    }

    public string ShimPipeName { get; } = $"OpWarden-test-{Guid.NewGuid():N}";

    public string AgentPipeName { get; } = $"OpWarden-test-agent-{Guid.NewGuid():N}";

    public RuleStore Rules { get; }

    public AliasStore Aliases { get; }

    public AliasFile AliasFile { get; }

    public List<Exception> ConnectionErrors { get; } = [];

    public string DataDirectory => _data.FullName;

    private string AuditPath => Path.Combine(_data.FullName, "audit.jsonl");

    public static BrokerHarness Start(CallerIdentity caller, IEnumerable<Rule>? rules = null, TimeSpan? promptTimeout = null) =>
        new(promptTimeout ?? TimeSpan.FromSeconds(20), caller, rules ?? []);

    public Task<ShimRun> RunShimAsync(IEnumerable<string> args, IReadOnlyDictionary<string, string>? environment = null) =>
        ShimHarness.RunShimAsync(ShimPipeName, args, environment);

    public async Task<TestAgent> ConnectAgentAsync()
    {
        var pipe = new NamedPipeClientStream(".", AgentPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        return new TestAgent(pipe);
    }

    public IReadOnlyList<JsonElement> AuditEntries() =>
        File.Exists(AuditPath) ? [.. File.ReadAllLines(AuditPath).Select(line => JsonDocument.Parse(line).RootElement.Clone())] : [];

    public async ValueTask DisposeAsync()
    {
        await _shims.DisposeAsync();
        await _agent.DisposeAsync();
        _data.Delete(recursive: true);
    }
}

/// <summary>
/// The interactive user at a session agent: reads what the broker shows and answers it,
/// over the real session-agent protocol.
/// </summary>
internal sealed class TestAgent : IAsyncDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly Channel<AgentMessage> _received = Channel.CreateUnbounded<AgentMessage>();
    private readonly Task _reader;

    public TestAgent(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _reader = Task.Run(async () =>
        {
            try
            {
                while (await AgentProtocol.ReadAsync(_pipe, CancellationToken.None) is { } message) await _received.Writer.WriteAsync(message);
            }
            catch (IOException)
            {
                // Disposed.
            }
            finally
            {
                _received.Writer.TryComplete();
            }
        });
    }

    /// <summary>
    /// The next message from the broker, which must be a <typeparamref name="T"/>.
    /// </summary>
    public async Task<T> NextAsync<T>()
        where T : AgentMessage
    {
        var message = await _received.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15));
        return Assert.IsType<T>(message);
    }

    public bool TryPeek(out AgentMessage? message) => _received.Reader.TryPeek(out message);

    public Task DecideAsync(ShowPrompt prompt, PromptDecision decision, RuleScope? scope = null, CacheTtl? grant = null) =>
        AgentProtocol.WriteAsync(_pipe, new DecisionMade(prompt.PromptId, decision, scope, grant), CancellationToken.None);

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync();
        await _reader;
    }
}
