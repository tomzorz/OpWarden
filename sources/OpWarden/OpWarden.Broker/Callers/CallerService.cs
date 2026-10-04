using OpWarden.Broker.Audit;
using OpWarden.Core.Agent;

namespace OpWarden.Broker.Callers;

/// <summary>
/// Caller resolution as the broker runs it: the process map, seeded at start and fed by
/// the ETW session, a retention pass every few minutes, and the resolver over both.
/// </summary>
public sealed class CallerService : IDisposable
{
    // ceiling: REQ-CALL-7 leaves the interval to implementation; five minutes keeps the
    // map small without snapshotting often. Measure on a busy machine before tuning.
    private static readonly TimeSpan RetentionInterval = TimeSpan.FromMinutes(5);

    private readonly ProcessMap _map = new();
    private readonly ProcessEventSession? _events;
    private readonly CallerResolver _resolver;
    private readonly AuditLog _audit;
    private readonly Timer _retention;
    private uint _lostReported;

    public CallerService(IReadOnlyList<AgentHost> agents, AuditLog audit, Action<AgentMessage> notify)
    {
        _audit = audit;

        // Subscribe before seeding, so no process starts in the gap between the two
        // (REQ-CALL-5); an entry seen twice is stored once.
        _events = ProcessEventSession.TryStart(_map, out var failure);
        _map.Seed(LiveProcesses.Snapshot());

        if (failure is not null)
        {
            // REQ-CALL-20: without events most callers resolve as unknown; say why.
            audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "process-events-unavailable", Detail: failure));
            notify(new ShowNotice("OpWarden caller resolution", failure));
        }

        _resolver = new CallerResolver(_map, agents, Authenticode.SignerOf, LiveProcesses.Find, () => LiveProcesses.ConsoleSessionId);
        _retention = new Timer(_ => Retain(), null, RetentionInterval, RetentionInterval);
    }

    /// <summary>
    /// The agent hosts configured at install when broker.json names none (REQ-CALL-16),
    /// with the signers verified on a real machine. Codex CLI and Cursor need entries of
    /// their own once their signers are checked.
    /// </summary>
    public static IReadOnlyList<AgentHost> DefaultAgents { get; } =
    [
        new("claude-code", "claude.exe", "Anthropic, PBC"),
        new("opencode", "opencode.exe", null),
    ];

    public bool ReceivesEvents => _events is not null;

    public CallerResolution Resolve(int shimProcessId) => _resolver.Resolve(shimProcessId);

    public void Dispose()
    {
        _retention.Dispose();
        _events?.Dispose();
    }

    private void Retain()
    {
        try
        {
            RetainOnce();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // A timer callback must not throw; the audit log failing here is reported by the
            // next invocation, which it denies (REQ-AUD-7).
            Console.Error.WriteLine($"process map retention could not record its result: {e.Message}");
        }
    }

    private void RetainOnce()
    {
        var capped = _map.Retain(LiveProcesses.Snapshot());
        if (capped > 0) _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "process-map-full", Detail: $"The process map reached its cap; {capped} of its oldest entries were deleted (REQ-CALL-8)."));

        if (_events is null) return;
        var lost = _events.EventsLost();
        if (lost > _lostReported)
        {
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "process-events-lost", Detail: $"ETW has dropped {lost} process events since the broker started; a caller whose start was dropped resolves as unknown."));
            _lostReported = lost;
        }
    }
}
