using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Broker.Prompts;

/// <summary>
/// What the broker asks the interactive user.
/// </summary>
/// <param name="Tuples">The request tuples the prompt decides; empty when only unknown secret references are left.</param>
/// <param name="Recheck">Evaluates the rules again just before the prompt shows (REQ-FAIL-7), so a rule stored by an earlier prompt settles a queued one without asking twice.</param>
public sealed record PromptRequest(
    CallerIdentity Caller,
    OpAction Action,
    string? Command,
    IReadOnlyList<RequestTuple> Tuples,
    bool ReferencesUnknown,
    PromptOptions Options,
    bool OffersCacheGrant,
    Func<RuleVerdict?> Recheck);

public abstract record PromptResult;

public sealed record PromptDecided(DecisionMade Decision) : PromptResult;

public sealed record PromptSettledByRule(RuleVerdict Verdict) : PromptResult;

public sealed record PromptTimedOut : PromptResult;

public sealed record PromptAbandoned : PromptResult;

public sealed record PromptQueueFull : PromptResult;

/// <summary>
/// Shows prompts one at a time (REQ-RULE-12) and resolves each with the user's decision,
/// a timeout (REQ-FAIL-1, REQ-FAIL-2), the caller going away (REQ-FAIL-5), or a full
/// queue (REQ-FAIL-6).
/// </summary>
/// <remarks>
/// <code>
///   RequestAsync ──► [ head | waiting … ]   at most <c>capacity</c> pending, head included
///                       │
///                       ├─ rules settle it now ........ PromptSettledByRule
///                       └─ shown: ShowPrompt sent, deadline starts
///                             ├─ DecisionMade ......... PromptDecided
///                             ├─ deadline passes ...... PromptTimedOut
///                             └─ shim disconnects ..... PromptAbandoned
///   every exit of a shown prompt sends ClosePrompt and shows the next one
/// </code>
/// The deadline starts when a prompt reaches the head, whether or not a session agent
/// is connected to see it: with no session agent, nobody can answer, and the timeout is
/// what turns that into a deny instead of a shim waiting forever.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "Spec section 11 calls it the prompt queue.")]
public sealed class PromptQueue(int capacity, TimeSpan timeout, Action<AgentMessage> send)
{
    private readonly Lock _lock = new();
    private readonly List<Pending> _pending = [];

    public Task<PromptResult> RequestAsync(PromptRequest request, CancellationToken abandoned)
    {
        var pending = new Pending(Guid.NewGuid(), request);
        lock (_lock)
        {
            if (_pending.Count >= capacity) return Task.FromResult<PromptResult>(new PromptQueueFull());
            _pending.Add(pending);
        }

        // Registered outside the lock: an already-cancelled token runs the callback
        // synchronously, and Finish takes the lock.
        pending.Abandoned = abandoned.Register(() => Finish(pending.Id, new PromptAbandoned(), "abandoned"));
        ShowNextIfIdle();
        return pending.Result.Task;
    }

    /// <summary>
    /// Applies a decision from the session agent. Returns false, and keeps waiting, when
    /// the decision is not for the prompt on screen or is not one that prompt offers.
    /// </summary>
    public bool Decide(DecisionMade decision)
    {
        lock (_lock)
        {
            var head = _pending.FirstOrDefault();
            if (head is null || head.Id != decision.PromptId || head.Deadline is null || !IsValid(head.Request, decision)) return false;
        }

        Finish(decision.PromptId, new PromptDecided(decision), "decided");
        return true;
    }

    /// <summary>
    /// The prompt on screen, for a session agent that connects while it is showing.
    /// </summary>
    public ShowPrompt? CurrentPrompt()
    {
        lock (_lock)
        {
            var head = _pending.FirstOrDefault();
            return head?.Deadline is { } deadline ? ToMessage(head, deadline) : null;
        }
    }

    /// <summary>
    /// True when the decision is one the prompt offers (REQ-RULE-6, REQ-CALL-19,
    /// REQ-RULE-18, REQ-RULE-19), and an <c>always-</c> decision pins only fields the
    /// prompt knows (REQ-RULE-34): a pinned unknown field would store a rule broader than
    /// the one the user saw.
    /// </summary>
    internal static bool IsValid(PromptRequest request, DecisionMade decision)
    {
        var always = decision.Decision is PromptDecision.AlwaysAllow or PromptDecision.AlwaysDisallow;
        if (always)
        {
            if (request.Options == PromptOptions.OnceOnly || decision.Scope is not { } scope || request.Tuples.Count == 0) return false;
            if (request.Tuples.Any(t => (scope.Vault && t.Path.Vault is null) || (scope.Item && t.Path.Item is null) || (scope.Key && t.Path.Key is null))) return false;
        }

        if (decision.CacheGrant is not null)
        {
            if (!request.OffersCacheGrant || decision.Decision is not (PromptDecision.AlwaysAllow or PromptDecision.AllowOnce)) return false;
        }

        return true;
    }

    private void Finish(Guid id, PromptResult result, string reason)
    {
        Pending finished;
        bool wasShown;
        lock (_lock)
        {
            var index = _pending.FindIndex(p => p.Id == id);
            if (index < 0) return;
            finished = _pending[index];
            wasShown = finished.Deadline is not null;
            _pending.RemoveAt(index);
        }

        finished.Timer?.Cancel();
        finished.Timer?.Dispose();
        finished.Abandoned.Unregister();
        if (wasShown) send(new ClosePrompt(id, reason));
        finished.Result.TrySetResult(result);
        ShowNextIfIdle();
    }

    private void ShowNextIfIdle()
    {
        while (true)
        {
            Pending? head;
            lock (_lock)
            {
                head = _pending.FirstOrDefault();
                if (head is null || head.Deadline is not null) return;
            }

            // Rules may have changed since this prompt queued; ask the engine again before
            // asking the user. Outside the lock: the engine reads the rule store.
            if (head.Request.Recheck() is { } settled)
            {
                Finish(head.Id, new PromptSettledByRule(settled), "settled");
                return;
            }

            ShowPrompt message;
            var timer = new CancellationTokenSource();
            lock (_lock)
            {
                if (_pending.FirstOrDefault() != head || head.Deadline is not null)
                {
                    timer.Dispose();
                    continue;
                }

                var deadline = DateTimeOffset.UtcNow + timeout;
                head.Deadline = deadline;
                head.Timer = timer;
                message = ToMessage(head, deadline);
            }

            send(message);
            var shown = head;
            _ = Task.Delay(timeout, timer.Token).ContinueWith(
                delay =>
                {
                    if (!delay.IsCanceled) Finish(shown.Id, new PromptTimedOut(), "timeout");
                },
                TaskScheduler.Default);
            return;
        }
    }

    private static ShowPrompt ToMessage(Pending pending, DateTimeOffset deadline)
    {
        var request = pending.Request;
        return new ShowPrompt(pending.Id, request.Caller, request.Action, request.Command, [.. request.Tuples.Select(t => t.Path)], request.ReferencesUnknown, request.Options, request.OffersCacheGrant, deadline);
    }

    private sealed class Pending(Guid id, PromptRequest request)
    {
        public Guid Id { get; } = id;

        public PromptRequest Request { get; } = request;

        public TaskCompletionSource<PromptResult> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public CancellationTokenRegistration Abandoned { get; set; }

        public DateTimeOffset? Deadline { get; set; }

        public CancellationTokenSource? Timer { get; set; }
    }
}
