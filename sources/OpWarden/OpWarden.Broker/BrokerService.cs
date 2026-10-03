using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using OpWarden.Broker.Audit;
using OpWarden.Broker.Cache;
using OpWarden.Broker.Integrity;
using OpWarden.Broker.Prompts;
using OpWarden.Broker.Storage;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.CommandLine;
using OpWarden.Core.Pipe;
using OpWarden.Core.Rules;

namespace OpWarden.Broker;

/// <param name="OpPath">The op CLI's absolute path, handed to the shim with each <c>allow</c> (spec section 14, step 5).</param>
public sealed record BrokerSettings(string OpPath);

/// <summary>
/// Turns one shim request into a verdict: resolve the caller, evaluate the rules, serve a
/// cached answer or prompt when they do not settle it, store the rules the user chose,
/// and record all of it in the audit log.
/// </summary>
public sealed class BrokerService(
    BrokerSettings settings,
    RuleStore rules,
    AliasStore aliases,
    AliasFile aliasFile,
    AuditLog audit,
    PromptQueue prompts,
    SecretCache cache,
    IntegrityAlarm alarm,
    Action<AgentMessage> notify,
    Func<int, CallerIdentity> resolveCaller)
{
    // The cache grant an allowed read earned, held until its capture arrives on the same
    // connection. Keyed by the request object, which the pipe server hands to both calls.
    private readonly ConditionalWeakTable<ShimRequest, Grant> _grants = [];

    public async ValueTask<VerdictResponse> DecideAsync(ShimRequest request, int clientProcessId, CancellationToken abandoned)
    {
        var caller = resolveCaller(clientProcessId);
        var cacheKey = IsCacheable(request, caller) ? CacheKey.For(caller, request.Arguments) : null;
        var evaluation = Evaluate(caller, request);

        // REQ-CACHE-12: a cached answer stands in only where a rule allows, or where the
        // prompt would offer every decision. A deny rule, an unknown caller and a
        // prompt-always vault each outrank a cache entry.
        var cacheMayAnswer = evaluation is RuleVerdict { Verdict: Verdict.Allow } or PromptNeeded { Options: PromptOptions.AllDecisions };
        if (cacheKey is not null && cacheMayAnswer && cache.TryGet(cacheKey) is { } cached)
        {
            return TryAudit(caller, request, Verdict.Allow, VerdictReason.Cache) is { } failure ? failure : VerdictResponse.FromCache(cached);
        }

        var outcome = evaluation switch
        {
            RuleVerdict ruled => FromRule(ruled),
            PromptNeeded needed => await PromptAsync(caller, request, needed, cacheKey is not null, abandoned).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unhandled evaluation {evaluation}."),
        };

        if (TryAudit(caller, request, outcome.Verdict, outcome.Reason) is { } auditFailure) return auditFailure;
        if (outcome.Verdict == Verdict.Deny) return VerdictResponse.Deny(outcome.Message);

        if (cacheKey is not null && outcome.Grant is { } ttl) _grants.AddOrUpdate(request, new Grant(cacheKey, ttl));
        return VerdictResponse.RunOp(settings.OpPath);
    }

    /// <summary>
    /// Handles an allowed read's output: caches it under the grant it earned (REQ-CACHE-3),
    /// learns alias pairs from it (REQ-RULE-15), then wipes the copy.
    /// </summary>
    public ValueTask CaptureReceivedAsync(ShimRequest request, ReadCapture capture)
    {
        try
        {
            var succeeded = capture.ExitCode == 0 && !capture.Truncated;
            if (_grants.TryGetValue(request, out var grant))
            {
                _grants.Remove(request);
                if (succeeded) cache.Put(grant.Key, capture.Output, grant.Ttl);
            }

            if (request.Action == OpAction.Read && succeeded && aliases.AddRange(AliasExtractor.FromReadOutput(capture.Output)))
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

    /// <summary>
    /// Flushes the cache when the interactive user locks the workstation (REQ-CACHE-7).
    /// </summary>
    public void WorkstationLocked()
    {
        var flushed = cache.Flush();
        audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "cache-flush", Detail: $"The workstation locked; {flushed} cache entries deleted."));
    }

    /// <summary>
    /// True for the invocations REQ-CACHE-10 lets the cache hold: an <c>op read</c> whose
    /// output goes to standard output (not to <c>--out-file</c>, which a cached answer could
    /// not reproduce) from a caller the broker identified.
    /// </summary>
    private static bool IsCacheable(ShimRequest request, CallerIdentity caller)
    {
        if (request.Command != "read" || caller.IsUnknown) return false;
        var parsed = OpArgvParser.Parse(request.Arguments);
        return parsed.OutputFile is null && !parsed.ReferencesUnknown;
    }

    /// <summary>
    /// Records an invocation, and returns the deny to hand out instead when the audit log
    /// cannot take it (REQ-AUD-7).
    /// </summary>
    private VerdictResponse? TryAudit(CallerIdentity caller, ShimRequest request, Verdict verdict, VerdictReason reason)
    {
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
            return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return VerdictResponse.Deny($"the audit log cannot be written ({e.Message})");
        }
    }

    private Evaluation Evaluate(CallerIdentity caller, ShimRequest request)
    {
        // REQ-INT-9: alias pairs decide whether an allow rule covers a request, so they
        // are checked before every evaluation, like the rules are.
        if (!aliases.IsIntact())
        {
            alarm.Raise("The alias pairs in broker memory no longer match their seal: something outside OpWarden changed the broker's memory. They were reloaded from disk.");
            aliases.Reset(aliasFile.Load().Pairs());
        }

        return new RuleEngine(rules.Current, aliases).Evaluate(caller, request.Action, request.Path, request.SecretReferences, request.SecretReferencesUnknown);
    }

    /// <summary>
    /// A rule's verdict, carrying the rule's cache grant when it allows (REQ-RULE-19).
    /// </summary>
    private static Outcome FromRule(RuleVerdict ruled) => ruled.Verdict == Verdict.Deny
        ? new Outcome(Verdict.Deny, VerdictReason.Rule, $"a rule denies this ({RuleText.Describe(ruled.Matches[0].Rule)})", null)
        : new Outcome(Verdict.Allow, VerdictReason.Rule, "", ruled.Matches.Count == 1 ? ruled.Matches[0].Rule.CacheGrant : null);

    private async Task<Outcome> PromptAsync(CallerIdentity caller, ShimRequest request, PromptNeeded needed, bool cacheable, CancellationToken abandoned)
    {
        // REQ-RULE-19: the cache-grant control appears only where a grant could be used,
        // and never on a once-only prompt, which a cached answer would let skip.
        var offersCacheGrant = cacheable && needed.Options == PromptOptions.AllDecisions;
        var prompt = new PromptRequest(caller, request.Action, request.Command, needed.Tuples, needed.ReferencesUnknown, needed.Options, offersCacheGrant, () => Evaluate(caller, request) as RuleVerdict);

        var result = await prompts.RequestAsync(prompt, abandoned).ConfigureAwait(false);
        return result switch
        {
            PromptDecided decided => ApplyDecision(prompt, decided.Decision),
            PromptSettledByRule settled => FromRule(settled.Verdict),
            PromptTimedOut => new Outcome(Verdict.Deny, VerdictReason.Timeout, "nobody answered the prompt within its timeout", null),
            PromptAbandoned => new Outcome(Verdict.Deny, VerdictReason.Abandoned, "the caller went away before a decision", null),
            PromptQueueFull => new Outcome(Verdict.Deny, VerdictReason.QueueFull, "too many prompts are already waiting", null),
            _ => throw new InvalidOperationException($"Unhandled prompt result {result}."),
        };
    }

    private Outcome ApplyDecision(PromptRequest prompt, DecisionMade decision)
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

        return allow
            ? new Outcome(Verdict.Allow, VerdictReason.User, "", decision.CacheGrant)
            : new Outcome(Verdict.Deny, VerdictReason.User, "denied at the prompt", null);
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

    private sealed record Outcome(Verdict Verdict, VerdictReason Reason, string Message, CacheTtl? Grant);

    private sealed record Grant(CacheKey Key, CacheTtl Ttl);
}
