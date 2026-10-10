using System.IO.Pipes;
using System.Security.Principal;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Pipes;
using OpWarden.Broker.Storage;
using OpWarden.Core.Management;
using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <summary>
/// Serves the management window: reads the rules for anyone on the pipe, flushes the
/// cache for anyone, and changes rules only for an elevated administrator (REQ-TRUST-5).
/// </summary>
/// <remarks>
/// Every rule change is recorded with the source <c>management</c> (REQ-TRUST-7), and a
/// refused change is recorded too: an unelevated process trying to edit rules is exactly
/// the agent behaviour the audit log exists to show.
/// </remarks>
public sealed class ManagementServer : IAsyncDisposable
{
    private readonly PipeServer _server;
    private readonly RuleStore _rules;
    private readonly SecretCache _cache;
    private readonly AuditLog _audit;

    internal ManagementServer(string pipeName, SecurityIdentifier user, RuleStore rules, SecretCache cache, AuditLog audit, Action<Exception> connectionFailed)
    {
        (_rules, _cache, _audit) = (rules, cache, audit);
        _server = new PipeServer(pipeName, user, ServeAsync, connectionFailed);
    }

    /// <inheritdoc cref="PipeServer.Start"/>
    public void Start() => _server.Start();

    public ValueTask DisposeAsync() => _server.DisposeAsync();

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        PipeClient? client = null;
        try
        {
            while (await ManagementProtocol.ReadRequestAsync(pipe, cancellationToken).ConfigureAwait(false) is { } request)
            {
                // Impersonation needs a message read first, so the identity is taken here.
                client ??= PipeClient.Capture(pipe);
                await ManagementProtocol.WriteAsync(pipe, Handle(request, client), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            client?.Dispose();
        }
    }

    private ManagementResponse Handle(ManagementRequest request, PipeClient client)
    {
        if (request.MutatesRules && !client.IsElevatedAdministrator)
        {
            _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "management-refused", Detail: $"Refused a {Describe(request)} from {client.Name} (process {client.ProcessId}): the token is not an elevated administrator's."));
            return new ManagementResponse("Changing rules needs an elevated administrator (REQ-TRUST-5); open the management window with elevation.");
        }

        switch (request)
        {
            case ListRules:
                return new ManagementResponse(null, _rules.Current);

            case FlushCache:
                var flushed = _cache.Flush();
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "cache-flush", Detail: $"The management window flushed the cache; {flushed} cache entries deleted."));
                return new ManagementResponse(null, Flushed: flushed);

            case AddRules add:
                _rules.Add(add.Rules);
                foreach (var rule in add.Rules) RecordChange("stored", rule);
                return new ManagementResponse(null, _rules.Current);

            case RemoveRule remove:
                if (!_rules.Remove(remove.Rule)) return new ManagementResponse($"No stored rule equals {RuleText.Describe(remove.Rule)}.", _rules.Current);
                RecordChange("removed", remove.Rule);
                return new ManagementResponse(null, _rules.Current);

            case SetPromptAlways mark:
                _rules.SetPromptAlways(mark.Vault, mark.PromptAlways);
                _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "rule-change", Source: RuleChangeSource.Management, Detail: mark.PromptAlways ? $"Marked the vault {mark.Vault} prompt-always." : $"Cleared prompt-always from the vault {mark.Vault}."));
                return new ManagementResponse(null, _rules.Current);

            default:
                return new ManagementResponse($"The broker does not handle a {Describe(request)}.");
        }
    }

    private void RecordChange(string what, Rule rule) =>
        _audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "rule-change", Source: RuleChangeSource.Management, Rule: rule, Detail: $"The management window {what} this rule."));

    private static string Describe(ManagementRequest request) => request.GetType().Name;
}
