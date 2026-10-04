using OpWarden.Broker.Audit;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Callers;
using OpWarden.Broker.Integrity;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <param name="DataDirectory">Where the rule store, alias file, integrity vault and audit log live.</param>
/// <param name="ResolveCaller">Maps the shim's process ID to its caller; null runs the real caller resolution (spec section 5).</param>
/// <param name="Agents">The agent hosts for real caller resolution; null takes <see cref="CallerService.DefaultAgents"/>.</param>
public sealed record BrokerHostOptions(
    string OpPath,
    string DataDirectory,
    string ShimPipeName,
    string AgentPipeName,
    TimeSpan PromptTimeout,
    Func<int, CallerResolution>? ResolveCaller,
    Action<Exception> ConnectionFailed,
    IReadOnlyList<AgentHost>? Agents = null);

/// <summary>
/// The broker, assembled: integrity vault, sealed stores, cache, prompt queue, and both
/// pipes. The console host and the end-to-end tests start the same assembly.
/// </summary>
public sealed class BrokerHost : IAsyncDisposable
{
    private readonly AgentChannel _agent;
    private readonly ShimPipeServer _shims;
    private readonly AuditLog _audit;
    private readonly CallerService? _callers;

    private BrokerHost(BrokerHostOptions options)
    {
        var data = options.DataDirectory;

        // The vault comes first because the audit log's chain needs its key; any problem
        // either finds is raised once the alarm exists, which in turn needs the audit log.
        var (vault, vaultProblem) = OpenVault(Path.Combine(data, "integrity.vault"));
        _audit = AuditLog.Open(Path.Combine(data, "audit.jsonl"), vault, out var auditProblem);

        BrokerService? broker = null;
        _agent = new AgentChannel(options.AgentPipeName, options.ConnectionFailed, () => broker?.WorkstationLocked());
        var alarm = new IntegrityAlarm(_audit, _agent.Send);
        if (vaultProblem is not null) alarm.Raise(vaultProblem);
        if (auditProblem is not null) alarm.Raise(auditProblem);

        Rules = RuleStore.Open(Path.Combine(data, "rules.json"), vault, alarm.Raise);
        var aliasFile = new AliasFile(Path.Combine(data, "aliases.json"), vault, alarm.Raise);
        Aliases = aliasFile.Load();
        Cache = new SecretCache(alarm.Raise);

        var resolveCaller = options.ResolveCaller;
        if (resolveCaller is null)
        {
            _callers = new CallerService(options.Agents ?? CallerService.DefaultAgents, _audit, _agent.Send);
            resolveCaller = _callers.Resolve;
        }

        var prompts = new PromptQueue(10, options.PromptTimeout, _agent.Send);
        broker = new BrokerService(new BrokerSettings(options.OpPath), Rules, Aliases, aliasFile, _audit, prompts, Cache, alarm, _agent.Send, resolveCaller);
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
        _callers?.Dispose();
        _audit.Dispose();
    }

    /// <summary>
    /// Opens the vault, or replaces one that cannot be read. Everything sealed with the
    /// old key then fails its own check and is quarantined in turn, so a destroyed vault
    /// costs the stored rules, never their integrity.
    /// </summary>
    private static (IntegrityVault Vault, string? Problem) OpenVault(string path)
    {
        try
        {
            return (IntegrityVault.Open(path), null);
        }
        catch (TamperedException e)
        {
            var quarantined = RuleStore.Quarantine(path);
            return (IntegrityVault.Open(path), $"{e.Message} It was moved to {quarantined}, and a new vault was created; files sealed with the old one will be quarantined as they load.");
        }
    }
}
