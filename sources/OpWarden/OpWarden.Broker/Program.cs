using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpWarden.Broker;
using OpWarden.Broker.Callers;

// The broker. `--service` runs it under the service control manager, as the install
// registers it (REQ-TRUST-1); without it the broker runs in this console as whoever
// started it, for development, where none of the privilege separation of spec section 8
// applies.

var (service, configPath) = args switch
{
    ["--service", "--config", var path] => (true, path),
    ["--config", var path] => (false, path),
    _ => (false, null),
};
if (configPath is null)
{
    Console.Error.WriteLine("usage: OpWarden.Broker [--service] --config <path to broker.json>");
    return 2;
}

var options = BrokerConfig.Load(configPath, service, out var error);

if (service)
{
    // A config the service cannot use still goes through the service control manager,
    // so the failure lands in the event log as the service's exit code rather than as
    // a service that never answered. The broker log needs the data directory, which
    // only a readable config names.
    var log = options is null ? null : new BrokerLog(Path.Combine(options.DataDirectory, "broker.log"));
    Action<string> write = log is null ? Console.Error.WriteLine : log.Write;
    var exitCode = ServiceHost.Run(
        () => options is null
            ? throw new InvalidDataException(error)
            : BrokerHost.Start(options with { ConnectionFailed = e => write($"connection error: {e.Message}") }),
        write);
    if (exitCode == 1063) Console.Error.WriteLine("--service runs only under the service control manager; start the OpWarden service instead, or drop --service to run in this console.");
    return exitCode;
}

if (options is null)
{
    Console.Error.WriteLine(error);
    return 2;
}

await using var broker = BrokerHost.Start(options);
Console.WriteLine($"OpWarden broker listening on \\\\.\\pipe\\{options.Pipes.Shim} (shims), \\\\.\\pipe\\{options.Pipes.Agent} (session agent) and \\\\.\\pipe\\{options.Pipes.Management} (management).");
Console.WriteLine($"Data in {options.DataDirectory}. Pinning the session agent at {options.SessionAgentPath}. Ctrl+C stops.");

var stopped = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stopped.TrySetResult();
};
await stopped.Task;
return 0;

/// <summary>
/// broker.json:
/// <c>{ "opPath": "C:\\...\\op.exe", "dataDirectory": "data", "userSid": "S-1-5-21-…", "sessionAgentPath": "C:\\...\\OpWarden.SessionAgent.exe", "agents": [ … ] }</c>.
/// A relative data directory resolves against the config file's folder. <c>userSid</c>
/// names the interactive user and is required under the service; the console broker
/// defaults it to whoever runs it. <c>sessionAgentPath</c> defaults to the session agent
/// beside the broker. Without <c>agents</c>, the defaults of
/// <see cref="CallerService.DefaultAgents"/> apply.
/// </summary>
internal sealed record BrokerConfig(string OpPath, string DataDirectory, string? UserSid = null, string? SessionAgentPath = null, IReadOnlyList<AgentHostConfig>? Agents = null)
{
    public static BrokerHostOptions? Load(string path, bool service, out string error)
    {
        BrokerConfig? config;
        try
        {
            config = JsonSerializer.Deserialize(File.ReadAllBytes(path), BrokerConfigJsonContext.Default.BrokerConfig);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            error = $"Cannot read the broker config {path}: {e.Message}";
            return null;
        }

        error = "";
        if (config is null)
        {
            error = $"The broker config {path} is empty.";
            return null;
        }

        // Only the form is checked: the op CLI usually lives in the user's profile, which
        // the service account cannot see. A wrong path surfaces as the shim's launch error.
        if (!Path.IsPathFullyQualified(config.OpPath))
        {
            error = $"opPath in {path} must be the absolute path of the op CLI; '{config.OpPath}' is not.";
            return null;
        }

        SecurityIdentifier user;
        try
        {
            user = config.UserSid is { } sid ? new SecurityIdentifier(sid)
                : service ? throw new ArgumentException("userSid is required when the broker runs as a service, because the service account is not the interactive user.")
                : CurrentUser();
        }
        catch (ArgumentException e)
        {
            error = $"userSid in {path}: {e.Message}";
            return null;
        }

        var folder = Path.GetDirectoryName(Path.GetFullPath(path))!;
        return new BrokerHostOptions(
            config.OpPath,
            Path.GetFullPath(config.DataDirectory, folder),
            user,
            config.SessionAgentPath ?? Path.Combine(AppContext.BaseDirectory, "OpWarden.SessionAgent.exe"),
            BrokerPipeNames.Default,
            TimeSpan.FromSeconds(30),
            null,
            e => Console.Error.WriteLine($"{DateTimeOffset.Now:HH:mm:ss} connection error: {e.Message}"),
            config.Agents?.Select(a => new AgentHost(a.Name, a.FileName, a.Signer)).ToList());
    }

    private static SecurityIdentifier CurrentUser()
    {
        using var self = WindowsIdentity.GetCurrent();
        return self.User!;
    }
}

/// <summary>
/// One agent host in broker.json: <c>{ "name": "claude-code", "fileName": "claude.exe", "signer": "Anthropic, PBC" }</c>.
/// </summary>
internal sealed record AgentHostConfig(string Name, string FileName, string? Signer);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(BrokerConfig))]
internal sealed partial class BrokerConfigJsonContext : JsonSerializerContext;
