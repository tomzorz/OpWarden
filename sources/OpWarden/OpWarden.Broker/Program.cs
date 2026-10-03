using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Broker;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core.Agent;
using OpWarden.Core.Pipe;
using OpWarden.Core.Rules;

// The broker as a console process, for development: build-order step 3 runs it here
// before service registration exists. It runs as whoever starts it, so none of the
// privilege separation of spec section 8 applies yet.

if (args is not ["--config", var configPath])
{
    Console.Error.WriteLine("usage: OpWarden.Broker --config <path to broker.json>");
    return 2;
}

BrokerConfig? config;
try
{
    config = JsonSerializer.Deserialize(File.ReadAllBytes(configPath), BrokerConfigJsonContext.Default.BrokerConfig);
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
{
    Console.Error.WriteLine($"Cannot read the broker config {configPath}: {e.Message}");
    return 2;
}

if (config is null)
{
    Console.Error.WriteLine($"The broker config {configPath} is empty.");
    return 2;
}

if (!Path.IsPathFullyQualified(config.OpPath) || !File.Exists(config.OpPath))
{
    Console.Error.WriteLine($"opPath in {configPath} must be the absolute path of the op CLI; '{config.OpPath}' is not.");
    return 2;
}

var data = Path.GetFullPath(config.DataDirectory, Path.GetDirectoryName(Path.GetFullPath(configPath))!);
var audit = new AuditLog(Path.Combine(data, "audit.jsonl"));
var rules = RuleStore.Open(Path.Combine(data, "rules.json"));
var aliasFile = new AliasFile(Path.Combine(data, "aliases.json"));
var aliases = aliasFile.Load();

void Log(Exception e) => Console.Error.WriteLine($"{DateTimeOffset.Now:HH:mm:ss} connection error: {e.Message}");

await using var agent = new AgentChannel(AgentProtocol.DefaultPipeName, Log);
var prompts = new PromptQueue(capacity: 10, timeout: TimeSpan.FromSeconds(30), agent.Send);

// Caller resolution arrives with the process map (build-order step 6). Until then every
// caller is unknown, which REQ-CALL-19 turns into a once-only prompt each time: the
// safe placeholder, never a guess.
var broker = new BrokerService(new BrokerSettings(config.OpPath), rules, aliases, aliasFile, audit, prompts, agent.Send, _ => CallerIdentity.Unknown);

await using var shims = new ShimPipeServer(PipeProtocol.DefaultPipeName, broker.DecideAsync, (request, capture, _) => broker.CaptureReceivedAsync(request, capture), Log);
agent.Start(prompts);
shims.Start();

Console.WriteLine($"OpWarden broker listening on \\\\.\\pipe\\{PipeProtocol.DefaultPipeName} (shims) and \\\\.\\pipe\\{AgentProtocol.DefaultPipeName} (session agent).");
Console.WriteLine($"Data in {data}. Ctrl+C stops.");

var stopped = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stopped.TrySetResult();
};
await stopped.Task;
return 0;

/// <summary>
/// broker.json: <c>{ "opPath": "C:\\...\\op.exe", "dataDirectory": "data" }</c>. A relative
/// data directory resolves against the config file's folder.
/// </summary>
internal sealed record BrokerConfig(string OpPath, string DataDirectory);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(BrokerConfig))]
internal sealed partial class BrokerConfigJsonContext : JsonSerializerContext;
