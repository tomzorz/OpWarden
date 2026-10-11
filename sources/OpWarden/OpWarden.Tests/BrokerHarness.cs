using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using OpWarden.Broker;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Callers;
using OpWarden.Broker.Storage;
using OpWarden.Core.Agent;
using OpWarden.Core.Management;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The whole broker on pipes and files of its own, assembled by <see cref="BrokerHost"/>
/// exactly as the console host assembles it. Only the caller resolver is the test's.
/// </summary>
internal sealed class BrokerHarness : IAsyncDisposable
{
    private readonly DirectoryInfo _data;
    private readonly bool _ownsData;
    private readonly BrokerHost _host;

    private BrokerHarness(DirectoryInfo data, bool ownsData, TimeSpan promptTimeout, CallerIdentity caller, IEnumerable<Rule> rules, string? sessionAgentPath, IReadOnlyList<ProcessIdentity> ancestors)
    {
        (_data, _ownsData) = (data, ownsData);
        using var self = WindowsIdentity.GetCurrent();
        _host = BrokerHost.Start(new BrokerHostOptions(
            BuiltExecutables.Probe,
            data.FullName,
            self.User!,
            sessionAgentPath ?? Environment.ProcessPath!,
            Pipes,
            promptTimeout,
            _ => new CallerResolution(caller, ["test-caller(0)"]) { Ancestors = ancestors },
            ConnectionErrors.Add));
        var seed = rules.ToList();
        if (seed.Count > 0) Rules.Add(seed);
    }

    public BrokerPipeNames Pipes { get; } = NewPipeNames();

    public string ShimPipeName => Pipes.Shim;

    public string AgentPipeName => Pipes.Agent;

    public RuleStore Rules => _host.Rules;

    public AliasStore Aliases => _host.Aliases;

    public SecretCache Cache => _host.Cache;

    public List<Exception> ConnectionErrors { get; } = [];

    public string DataDirectory => _data.FullName;

    private string AuditPath => Path.Combine(_data.FullName, "audit.jsonl");

    /// <param name="sessionAgentPath">The executable the broker pins; by default the test process itself, so <see cref="ConnectAgentAsync"/> is pinned.</param>
    /// <param name="ancestors">The shim's ancestors the caller resolution reports, which the notifications carry.</param>
    public static BrokerHarness Start(CallerIdentity caller, IEnumerable<Rule>? rules = null, TimeSpan? promptTimeout = null, string? sessionAgentPath = null, IReadOnlyList<ProcessIdentity>? ancestors = null) =>
        new(Directory.CreateTempSubdirectory("opwarden-broker-"), true, promptTimeout ?? TimeSpan.FromSeconds(20), caller, rules ?? [], sessionAgentPath, ancestors ?? []);

    /// <summary>
    /// Starts a broker on a data directory the test owns, to restart over the same files.
    /// </summary>
    public static BrokerHarness StartIn(DirectoryInfo data, CallerIdentity caller) => new(data, false, TimeSpan.FromSeconds(20), caller, [], null, []);

    public static BrokerPipeNames NewPipeNames()
    {
        var id = Guid.NewGuid().ToString("N");
        return new($"OpWarden-test-{id}", $"OpWarden-test-agent-{id}", $"OpWarden-test-manage-{id}");
    }

    /// <summary>
    /// A management-window connection over the real management protocol.
    /// </summary>
    public async Task<ManagementResponse> ManageAsync(ManagementRequest request)
    {
        await using var pipe = new NamedPipeClientStream(".", Pipes.Management, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        await ManagementProtocol.WriteAsync(pipe, request, CancellationToken.None);
        return (await ManagementProtocol.ReadResponseAsync(pipe, CancellationToken.None))!;
    }

    public Task<ShimRun> RunShimAsync(IEnumerable<string> args, IReadOnlyDictionary<string, string>? environment = null) =>
        ShimHarness.RunShimAsync(ShimPipeName, args, environment);

    /// <summary>
    /// Connects a session agent and returns once the broker has pinned or refused it. The
    /// broker resends the prompt on screen when it pins, so a prompt raised before the pin
    /// would otherwise arrive twice.
    /// </summary>
    public async Task<TestAgent> ConnectAgentAsync()
    {
        int Settled() => AuditEntries("agent-pinned").Count + AuditEntries("agent-refused").Count;
        var before = Settled();
        var pipe = new NamedPipeClientStream(".", AgentPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        var agent = new TestAgent(pipe);
        for (var i = 0; i < 250 && Settled() == before; i++) await Task.Delay(20);
        return agent;
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

    /// <summary>
    /// The audit entries of one event type, such as <c>invocation</c>.
    /// </summary>
    public IReadOnlyList<JsonElement> AuditEntries(string eventName) => [.. AuditEntries().Where(e => e.GetProperty("event").GetString() == eventName)];

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

    /// <summary>
    /// The next <typeparamref name="T"/>, skipping whatever the broker sent before it.
    /// </summary>
    public async Task<T> SkipToAsync<T>()
        where T : AgentMessage
    {
        while (true)
        {
            if (await _received.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15)) is T match) return match;
        }
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
