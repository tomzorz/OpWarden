using System.Security.Cryptography;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Pipe;
using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <param name="OpPath">The op CLI's absolute path, handed to the shim with each <c>allow</c> (spec section 14, step 5).</param>
public sealed record BrokerSettings(string OpPath);

/// <summary>
/// Turns one shim request into a verdict: resolve the caller, evaluate the rules, prompt
/// when they do not settle it, store the rules the user chose, and record all of it in
/// the audit log.
/// </summary>
public sealed class BrokerService(
    BrokerSettings settings,
    RuleStore rules,
    AliasStore aliases,
    AliasFile aliasFile,
    AuditLog audit,
    PromptQueue prompts,
    Action<AgentMessage> notify,
    Func<int, CallerIdentity> resolveCaller)
{
    public async ValueTask<VerdictResponse> DecideAsync(ShimRequest request, int clientProcessId, CancellationToken abandoned)
    {
        var caller = resolveCaller(clientProcessId);
        var evaluation = Evaluate(caller, request);
        var (verdict, reason, message) = evaluation switch
        {
            RuleVerdict ruled => FromRule(ruled),
            PromptNeeded needed => await PromptAsync(caller, request, needed, abandoned).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unhandled evaluation {evaluation}."),
        };

        try
        {
            audit.Append(new AuditEntry(
                DateTimeOffset.UtcNow,
                "invocation",
                caller,
                CallerChain: [],
                request.Action,
                request.Command,
                AuditLog.RedactArguments(request.Arguments, request.Action),
                request.Path,
                request.SecretReferences,
                request.SecretReferencesUnknown,
                verdict,
                reason));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // REQ-AUD-7: an invocation the broker cannot record does not run.
            return VerdictResponse.Deny($"the audit log cannot be written ({e.Message})");
        }

        return verdict == Verdict.Allow ? VerdictResponse.RunOp(settings.OpPath) : VerdictResponse.Deny(message);
    }

    /// <summary>
    /// Learns alias pairs from an allowed read's output (REQ-RULE-15), then wipes the copy.
    /// </summary>
    public ValueTask CaptureReceivedAsync(ShimRequest request, ReadCapture capture)
    {
        try
        {
            if (request.Action == OpAction.Read && capture.ExitCode == 0 && !capture.Truncated && aliases.AddRange(AliasExtractor.FromReadOutput(capture.Output)))
            {
                aliasFile.Save(aliases);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(capture.Output);
        }

        return ValueTask.CompletedTask;
    }

    private Evaluation Evaluate(CallerIdentity caller, ShimRequest request) =>
        new RuleEngine(rules.Current, aliases).Evaluate(caller, request.Action, request.Path, request.SecretReferences, request.SecretReferencesUnknown);

    private static (Verdict, VerdictReason, string) FromRule(RuleVerdict ruled) =>
        (ruled.Verdict, VerdictReason.Rule, ruled.Verdict == Verdict.Deny ? $"a rule denies this ({RuleText.Describe(ruled.Matches[0].Rule)})" : "");

    private async Task<(Verdict, VerdictReason, string)> PromptAsync(CallerIdentity caller, ShimRequest request, PromptNeeded needed, CancellationToken abandoned)
    {
        // REQ-RULE-19: only `op read` gets the cache-grant control.
        var offersCacheGrant = request.Command == "read" && !caller.IsUnknown;
        var prompt = new PromptRequest(caller, request.Action, request.Command, needed.Tuples, needed.ReferencesUnknown, needed.Options, offersCacheGrant, () => Evaluate(caller, request) as RuleVerdict);

        var result = await prompts.RequestAsync(prompt, abandoned).ConfigureAwait(false);
        return result switch
        {
            PromptDecided decided => ApplyDecision(prompt, decided.Decision),
            PromptSettledByRule settled => FromRule(settled.Verdict),
            PromptTimedOut => (Verdict.Deny, VerdictReason.Timeout, "nobody answered the prompt within its timeout"),
            PromptAbandoned => (Verdict.Deny, VerdictReason.Abandoned, "the caller went away before a decision"),
            PromptQueueFull => (Verdict.Deny, VerdictReason.QueueFull, "too many prompts are already waiting"),
            _ => throw new InvalidOperationException($"Unhandled prompt result {result}."),
        };
    }

    private (Verdict, VerdictReason, string) ApplyDecision(PromptRequest prompt, DecisionMade decision)
    {
        var allow = decision.Decision is PromptDecision.AlwaysAllow or PromptDecision.AllowOnce;
        if (decision.Decision is PromptDecision.AlwaysAllow or PromptDecision.AlwaysDisallow)
        {
            var verdict = allow ? Verdict.Allow : Verdict.Deny;
            var grant = allow ? decision.CacheGrant : null;
            // REQ-RULE-33: one rule per listed tuple.
            var stored = prompt.Tuples.Select(tuple => ToRule(tuple, decision.Scope!, verdict, grant)).ToList();
            StoreFromPrompt(stored);
        }

        return (allow ? Verdict.Allow : Verdict.Deny, VerdictReason.User, allow ? "" : "denied at the prompt");
    }

    /// <summary>
    /// Stores the rules a prompt decision made, records each change (REQ-TRUST-7), and
    /// passes their notices to the session agent (REQ-RULE-32).
    /// </summary>
    private void StoreFromPrompt(IReadOnlyList<Rule> stored)
    {
        rules.Add(stored);
        foreach (var rule in stored) audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "rule-change", Source: RuleChangeSource.Prompt, Rule: rule));

        foreach (var notice in RuleAdvisor.Review(rules.Current, aliases).Where(n => stored.Contains(n.Rule)))
        {
            notify(new ShowNotice("OpWarden rule notice", RuleText.Describe(notice)));
        }
    }

    private static Rule ToRule(RequestTuple tuple, RuleScope scope, Verdict verdict, CacheTtl? grant) =>
        new(
            scope.Caller ? tuple.Caller : null,
            scope.Action ? tuple.Action : null,
            scope.Vault ? tuple.Path.Vault : null,
            scope.Item ? tuple.Path.Item : null,
            scope.Key ? tuple.Path.Key : null,
            verdict,
            grant);
}
