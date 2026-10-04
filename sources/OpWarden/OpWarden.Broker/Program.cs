using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Broker;
using OpWarden.Broker.Callers;
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

void Log(Exception e) => Console.Error.WriteLine($"{DateTimeOffset.Now:HH:mm:ss} connection error: {e.Message}");

// ResolveCaller null: the real caller resolution, with the process-event session when
// Windows allows it (an elevated or Performance Log Users console) and the live walk
// otherwise.
await using var broker = BrokerHost.Start(new BrokerHostOptions(
    config.OpPath,
    data,
    PipeProtocol.DefaultPipeName,
    AgentProtocol.DefaultPipeName,
    TimeSpan.FromSeconds(30),
    null,
    Log,
    config.Agents?.Select(a => new AgentHost(a.Name, a.FileName, a.Signer)).ToList()));

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
/// broker.json: <c>{ "opPath": "C:\\...\\op.exe", "dataDirectory": "data", "agents": [ … ] }</c>.
/// A relative data directory resolves against the config file's folder. Without
/// <c>agents</c>, the defaults of <see cref="CallerService.DefaultAgents"/> apply.
/// </summary>
internal sealed record BrokerConfig(string OpPath, string DataDirectory, IReadOnlyList<AgentHostConfig>? Agents = null);

/// <summary>
/// One agent host in broker.json: <c>{ "name": "claude-code", "fileName": "claude.exe", "signer": "Anthropic, PBC" }</c>.
/// </summary>
internal sealed record AgentHostConfig(string Name, string FileName, string? Signer);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(BrokerConfig))]
internal sealed partial class BrokerConfigJsonContext : JsonSerializerContext;
