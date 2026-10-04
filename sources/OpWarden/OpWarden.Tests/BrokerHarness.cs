using System.IO.Pipes;
using System.Text.Json;
using System.Threading.Channels;
using OpWarden.Broker;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Callers;
using OpWarden.Broker.Storage;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The whole broker on pipes and files of its own, assembled by <see cref="BrokerHost"/>
/// exactly as the console host assembles it. Only the caller resolver is the test's,
/// until the process map exists.
/// </summary>
internal sealed class BrokerHarness : IAsyncDisposable
{
    private readonly DirectoryInfo _data;
    private readonly bool _ownsData;
    private readonly BrokerHost _host;

    private BrokerHarness(DirectoryInfo data, bool ownsData, TimeSpan promptTimeout, CallerIdentity caller, IEnumerable<Rule> rules)
    {
        (_data, _ownsData) = (data, ownsData);
        _host = BrokerHost.Start(new BrokerHostOptions(BuiltExecutables.Probe, data.FullName, ShimPipeName, AgentPipeName, promptTimeout, _ => new CallerResolution(caller, ["test-caller(0)"]), ConnectionErrors.Add));
        var seed = rules.ToList();
        if (seed.Count > 0) Rules.Add(seed);
    }

    public string ShimPipeName { get; } = $"OpWarden-test-{Guid.NewGuid():N}";

    public string AgentPipeName { get; } = $"OpWarden-test-agent-{Guid.NewGuid():N}";

    public RuleStore Rules => _host.Rules;

    public AliasStore Aliases => _host.Aliases;

    public SecretCache Cache => _host.Cache;

    public List<Exception> ConnectionErrors { get; } = [];

    public string DataDirectory => _data.FullName;

    private string AuditPath => Path.Combine(_data.FullName, "audit.jsonl");

    public static BrokerHarness Start(CallerIdentity caller, IEnumerable<Rule>? rules = null, TimeSpan? promptTimeout = null) =>
        new(Directory.CreateTempSubdirectory("opwarden-broker-"), true, promptTimeout ?? TimeSpan.FromSeconds(20), caller, rules ?? []);

    /// <summary>
    /// Starts a broker on a data directory the test owns, to restart over the same files.
    /// </summary>
    public static BrokerHarness StartIn(DirectoryInfo data, CallerIdentity caller) => new(data, false, TimeSpan.FromSeconds(20), caller, []);

    public Task<ShimRun> RunShimAsync(IEnumerable<string> args, IReadOnlyDictionary<string, string>? environment = null) =>
        ShimHarness.RunShimAsync(ShimPipeName, args, environment);

    public async Task<TestAgent> ConnectAgentAsync()
    {
        var pipe = new NamedPipeClientStream(".", AgentPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        return new TestAgent(pipe);
    }

    /// <summary>
    /// The audit log so far, read the way any tail would: sharing the file with the
    /// broker, which may be appending.
    /// </summary>
    public IReadOnlyList<JsonElement> AuditEntries()
    {
        if (!File.Exists(AuditPath)) return [];
        using var reader = new StreamReader(new FileStream(AuditPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
        var entries = new List<JsonElement>();
        while (reader.ReadLine() is { } line)
        {
            using var document = JsonDocument.Parse(line);
            entries.Add(document.RootElement.Clone());
        }

        return entries;
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        if (_ownsData) _data.Delete(recursive: true);
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
        SendAsync(new DecisionMade(prompt.PromptId, decision, scope, grant));

    public Task SendAsync(AgentMessage message) => AgentProtocol.WriteAsync(_pipe, message, CancellationToken.None);

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync();
        await _reader;
    }
}
