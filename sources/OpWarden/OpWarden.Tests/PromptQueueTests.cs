using System.Collections.Concurrent;
using OpWarden.Broker.Prompts;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class PromptQueueTests
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(30);

    private readonly ConcurrentQueue<AgentMessage> _sent = new();

    private PromptQueue Queue(int capacity = 10, TimeSpan? timeout = null) => new(capacity, timeout ?? Long, _sent.Enqueue);

    private static PromptRequest Request(string vault = "V", PromptOptions options = PromptOptions.AllDecisions, bool offersCache = false, Func<RuleVerdict?>? recheck = null, string? key = "K") =>
        new(Claude, OpAction.Read, "read", [new RequestTuple(Claude, OpAction.Read, new SecretPath(vault, "I", key))], false, options, offersCache, recheck ?? (() => null));

    private static DecisionMade Decision(ShowPrompt shown, PromptDecision decision, RuleScope? scope = null, CacheTtl? grant = null) => new(shown.PromptId, decision, scope, grant);

    [Fact]
    public async Task Shows_one_prompt_at_a_time_and_moves_on_after_a_decision()
    {
        var queue = Queue();
        var first = queue.RequestAsync(Request("A"), CancellationToken.None);
        var second = queue.RequestAsync(Request("B"), CancellationToken.None);

        var shownFirst = Assert.IsType<ShowPrompt>(Assert.Single(_sent));
        Assert.Equal("A", shownFirst.Paths[0].Vault);

        Assert.True(queue.Decide(Decision(shownFirst, PromptDecision.AllowOnce)));
        var result = Assert.IsType<PromptDecided>(await first);

        Assert.Equal(PromptDecision.AllowOnce, result.Decision.Decision);
        Assert.Collection(
            _sent,
            m => Assert.IsType<ShowPrompt>(m),
            m => Assert.Equal(new ClosePrompt(shownFirst.PromptId, "decided"), m),
            m => Assert.Equal("B", Assert.IsType<ShowPrompt>(m).Paths[0].Vault));
        Assert.False(second.IsCompleted);
    }

    [Fact]
    public async Task A_shown_prompt_times_out()
    {
        var queue = Queue(timeout: TimeSpan.FromMilliseconds(200));

        var result = await queue.RequestAsync(Request(), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.IsType<PromptTimedOut>(result);
        Assert.Equal("timeout", Assert.IsType<ClosePrompt>(_sent.Last()).Reason);
    }

    [Fact]
    public async Task Abandoning_the_shown_prompt_closes_it_and_shows_the_next()
    {
        var queue = Queue();
        using var abandon = new CancellationTokenSource();
        var first = queue.RequestAsync(Request("A"), abandon.Token);
        _ = queue.RequestAsync(Request("B"), CancellationToken.None);

        await abandon.CancelAsync();

        Assert.IsType<PromptAbandoned>(await first);
        Assert.Equal("abandoned", _sent.OfType<ClosePrompt>().Single().Reason);
        Assert.Equal("B", _sent.OfType<ShowPrompt>().Last().Paths[0].Vault);
    }

    [Fact]
    public async Task Abandoning_a_waiting_prompt_removes_it_quietly()
    {
        var queue = Queue();
        _ = queue.RequestAsync(Request("A"), CancellationToken.None);
        using var abandon = new CancellationTokenSource();
        var second = queue.RequestAsync(Request("B"), abandon.Token);

        await abandon.CancelAsync();

        Assert.IsType<PromptAbandoned>(await second);
        Assert.Single(_sent);
    }

    [Fact]
    public async Task An_already_abandoned_request_never_shows()
    {
        var result = await Queue().RequestAsync(Request(), new CancellationToken(canceled: true));

        Assert.IsType<PromptAbandoned>(result);
        Assert.Empty(_sent);
    }

    [Fact]
    public async Task A_full_queue_refuses_the_next_request()
    {
        var queue = Queue(capacity: 2);
        _ = queue.RequestAsync(Request(), CancellationToken.None);
        _ = queue.RequestAsync(Request(), CancellationToken.None);

        Assert.IsType<PromptQueueFull>(await queue.RequestAsync(Request(), CancellationToken.None));
    }

    [Fact]
    public void A_decision_for_another_prompt_is_ignored()
    {
        var queue = Queue();
        _ = queue.RequestAsync(Request(), CancellationToken.None);

        Assert.False(queue.Decide(new DecisionMade(Guid.NewGuid(), PromptDecision.AllowOnce, null, null)));
    }

    [Fact]
    public void A_decision_the_prompt_does_not_offer_is_ignored_and_the_prompt_stays()
    {
        var queue = Queue();
        var pending = queue.RequestAsync(Request(options: PromptOptions.OnceOnly), CancellationToken.None);
        var shown = Assert.IsType<ShowPrompt>(Assert.Single(_sent));

        Assert.False(queue.Decide(Decision(shown, PromptDecision.AlwaysAllow, RuleScope.Exact)));
        Assert.False(pending.IsCompleted);
        Assert.Equal(shown.PromptId, queue.CurrentPrompt()?.PromptId);
    }

    [Fact]
    public async Task A_queued_prompt_that_rules_now_settle_never_shows()
    {
        var queue = Queue();
        var first = queue.RequestAsync(Request("A"), CancellationToken.None);
        var settled = new RuleVerdict(Verdict.Allow, []);
        var second = queue.RequestAsync(Request("B", recheck: () => settled), CancellationToken.None);
        var shownFirst = Assert.IsType<ShowPrompt>(Assert.Single(_sent));

        queue.Decide(Decision(shownFirst, PromptDecision.AlwaysAllow, RuleScope.Exact));
        await first;

        Assert.Same(settled, Assert.IsType<PromptSettledByRule>(await second).Verdict);
        Assert.Single(_sent.OfType<ShowPrompt>());
    }

    [Theory]
    [InlineData(PromptOptions.AllDecisions, PromptDecision.AlwaysAllow, true, false, null, true)]
    [InlineData(PromptOptions.AllDecisions, PromptDecision.AlwaysAllow, false, false, null, false)]
    [InlineData(PromptOptions.OnceOnly, PromptDecision.AlwaysDisallow, true, false, null, false)]
    [InlineData(PromptOptions.OnceOnly, PromptDecision.DisallowOnce, false, false, null, true)]
    [InlineData(PromptOptions.AllDecisions, PromptDecision.AllowOnce, false, true, CacheTtl.OneHour, true)]
    [InlineData(PromptOptions.AllDecisions, PromptDecision.AllowOnce, false, false, CacheTtl.OneHour, false)]
    [InlineData(PromptOptions.AllDecisions, PromptDecision.DisallowOnce, false, true, CacheTtl.OneHour, false)]
    public void Validates_decisions_against_what_the_prompt_offers(PromptOptions options, PromptDecision decision, bool withScope, bool offersCache, CacheTtl? grant, bool valid)
    {
        var request = Request(options: options, offersCache: offersCache);

        Assert.Equal(valid, PromptQueue.IsValid(request, new DecisionMade(Guid.Empty, decision, withScope ? RuleScope.Exact : null, grant)));
    }

    [Fact]
    public void An_always_decision_cannot_pin_a_field_the_prompt_does_not_know()
    {
        var request = Request(key: null);

        Assert.False(PromptQueue.IsValid(request, new DecisionMade(Guid.Empty, PromptDecision.AlwaysAllow, RuleScope.Exact, null)));
        Assert.True(PromptQueue.IsValid(request, new DecisionMade(Guid.Empty, PromptDecision.AlwaysAllow, RuleScope.Exact with { Key = false }, null)));
    }
}
