using OpWarden.Broker.Audit;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Integrity;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <param name="DataDirectory">Where the rule store, alias file, integrity vault and audit log live.</param>
/// <param name="ResolveCaller">Maps the shim's process ID to a caller identity.</param>
public sealed record BrokerHostOptions(
    string OpPath,
    string DataDirectory,
    string ShimPipeName,
    string AgentPipeName,
    TimeSpan PromptTimeout,
    Func<int, CallerIdentity> ResolveCaller,
    Action<Exception> ConnectionFailed);

/// <summary>
/// The broker, assembled: integrity vault, sealed stores, cache, prompt queue, and both
/// pipes. The console host and the end-to-end tests start the same assembly.
/// </summary>
public sealed class BrokerHost : IAsyncDisposable
{
    private readonly AgentChannel _agent;
    private readonly ShimPipeServer _shims;

    private BrokerHost(BrokerHostOptions options)
    {
        var data = options.DataDirectory;
        var audit = new AuditLog(Path.Combine(data, "audit.jsonl"));

        BrokerService? broker = null;
        _agent = new AgentChannel(options.AgentPipeName, options.ConnectionFailed, () => broker?.WorkstationLocked());
        var alarm = new IntegrityAlarm(audit, _agent.Send);

        var vault = OpenVault(Path.Combine(data, "integrity.vault"), alarm);
        Rules = RuleStore.Open(Path.Combine(data, "rules.json"), vault, alarm.Raise);
        var aliasFile = new AliasFile(Path.Combine(data, "aliases.json"), vault, alarm.Raise);
        Aliases = aliasFile.Load();
        Cache = new SecretCache(alarm.Raise);

        var prompts = new PromptQueue(10, options.PromptTimeout, _agent.Send);
        broker = new BrokerService(new BrokerSettings(options.OpPath), Rules, Aliases, aliasFile, audit, prompts, Cache, _agent.Send, options.ResolveCaller);
        _shims = new ShimPipeServer(options.ShimPipeName, broker.DecideAsync, (request, capture, _) => broker.CaptureReceivedAsync(request, capture), options.ConnectionFailed);

        _agent.Start(prompts);
        _shims.Start();
    }

    public RuleStore Rules { get; }

    public AliasStore Aliases { get; }

    public SecretCache Cache { get; }

    public static BrokerHost Start(BrokerHostOptions options) => new(options);

    public async ValueTask DisposeAsync()
    {
        await _shims.DisposeAsync().ConfigureAwait(false);
        await _agent.DisposeAsync().ConfigureAwait(false);
        Cache.Dispose();
    }

    /// <summary>
    /// Opens the vault, or replaces one that cannot be read. Everything sealed with the
    /// old key then fails its own check and is quarantined in turn, so a destroyed vault
    /// costs the stored rules, never their integrity.
    /// </summary>
    private static IntegrityVault OpenVault(string path, IntegrityAlarm alarm)
    {
        try
        {
            return IntegrityVault.Open(path);
        }
        catch (TamperedException e)
        {
            var quarantined = RuleStore.Quarantine(path);
            alarm.Raise($"{e.Message} It was moved to {quarantined}, and a new vault was created; files sealed with the old one will be quarantined as they load.");
            return IntegrityVault.Open(path);
        }
    }
}
