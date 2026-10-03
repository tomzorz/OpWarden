using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The prompt flow end to end (spec sections 7, 11 and 12): a real shim, the whole
/// broker, and a session agent speaking the real protocol on the user's behalf.
/// </summary>
public sealed class BrokerTests
{
    private const int ExitDenied = 77;
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");

    [Fact]
    public async Task A_matching_rule_decides_without_a_prompt_and_is_audited()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)]);
        await using var agent = await broker.ConnectAgentAsync();

        var run = await broker.RunShimAsync(["read", "op://v/i/f"], new Dictionary<string, string> { ["PROBE_STDOUT"] = "value" });

        Assert.Equal(0, run.ExitCode);
        Assert.Equal("value", run.Stdout);
        Assert.False(agent.TryPeek(out _));
        var entry = Assert.Single(broker.AuditEntries());
        Assert.Equal("invocation", entry.GetProperty("event").GetString());
        Assert.Equal("rule", entry.GetProperty("reason").GetString());
        Assert.Equal("Allow", entry.GetProperty("verdict").GetString());
    }

    [Fact]
    public async Task A_deny_rule_refuses_and_names_the_rule()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, null, "Prod", null, null, Verdict.Deny)]);

        var run = await broker.RunShimAsync(["read", "op://Prod/i/f"]);

        Assert.Equal(ExitDenied, run.ExitCode);
        Assert.Contains("deny claude-code * Prod * *", run.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Always_allow_stores_a_rule_at_the_chosen_scope_and_the_next_call_needs_no_prompt()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var first = broker.RunShimAsync(["read", "op://V/I/K"]);
        var prompt = await agent.NextAsync<ShowPrompt>();
        Assert.Equal([new SecretPath("V", "I", "K")], prompt.Paths);
        Assert.Equal(PromptOptions.AllDecisions, prompt.Options);
        Assert.True(prompt.OffersCacheGrant);
        await agent.DecideAsync(prompt, PromptDecision.AlwaysAllow, RuleScope.Exact with { Key = false });

        Assert.Equal(0, (await first).ExitCode);
        Assert.Equal("decided", (await agent.NextAsync<ClosePrompt>()).Reason);
        Assert.Equal(new Rule(Claude, OpAction.Read, "V", "I", null, Verdict.Allow), Assert.Single(broker.Rules.Current.Rules));

        Assert.Equal(0, (await broker.RunShimAsync(["read", "op://V/I/other"])).ExitCode);
        Assert.Equal(["user", "rule"], broker.AuditEntries().Where(e => e.GetProperty("event").GetString() == "invocation").Select(e => e.GetProperty("reason").GetString()));
        Assert.Contains(broker.AuditEntries(), e => e.GetProperty("event").GetString() == "rule-change" && e.GetProperty("source").GetString() == "prompt");
    }

    [Fact]
    public async Task A_stored_rule_with_a_one_sided_name_sends_a_notice()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var run = broker.RunShimAsync(["read", "op://V/I/K"]);
        await agent.DecideAsync(await agent.NextAsync<ShowPrompt>(), PromptDecision.AlwaysAllow, RuleScope.Exact with { Item = false, Key = false });
        await run;

        // The prompt closes, then the notice for the new rule's vault arrives.
        await agent.NextAsync<ClosePrompt>();
        var notice = await agent.NextAsync<ShowNotice>();
        Assert.Contains("\"V\"", notice.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(PromptDecision.AllowOnce, 0)]
    [InlineData(PromptDecision.DisallowOnce, ExitDenied)]
    public async Task A_once_decision_answers_this_call_and_stores_nothing(PromptDecision decision, int exitCode)
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var run = broker.RunShimAsync(["read", "op://V/I/K"]);
        await agent.DecideAsync(await agent.NextAsync<ShowPrompt>(), decision);

        Assert.Equal(exitCode, (await run).ExitCode);
        Assert.Empty(broker.Rules.Current.Rules);
    }

    [Fact]
    public async Task An_unknown_caller_gets_a_once_only_prompt_without_a_cache_grant()
    {
        await using var broker = BrokerHarness.Start(CallerIdentity.Unknown, [new Rule(null, null, null, null, null, Verdict.Allow)]);
        await using var agent = await broker.ConnectAgentAsync();

        var run = broker.RunShimAsync(["read", "op://V/I/K"]);
        var prompt = await agent.NextAsync<ShowPrompt>();
        await agent.DecideAsync(prompt, PromptDecision.AllowOnce);

        Assert.Equal(PromptOptions.OnceOnly, prompt.Options);
        Assert.False(prompt.OffersCacheGrant);
        Assert.Equal(0, (await run).ExitCode);
    }

    [Fact]
    public async Task With_no_session_agent_the_prompt_times_out_into_a_deny()
    {
        await using var broker = BrokerHarness.Start(Claude, promptTimeout: TimeSpan.FromMilliseconds(300));

        var run = await broker.RunShimAsync(["read", "op://V/I/K"]);

        Assert.Equal(ExitDenied, run.ExitCode);
        Assert.Equal("timeout", Assert.Single(broker.AuditEntries()).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task A_session_agent_that_connects_late_is_shown_the_waiting_prompt()
    {
        await using var broker = BrokerHarness.Start(Claude);

        var run = broker.RunShimAsync(["whoami"]);
        await Task.Delay(500, TestContext.Current.CancellationToken);
        await using var agent = await broker.ConnectAgentAsync();
        await agent.DecideAsync(await agent.NextAsync<ShowPrompt>(), PromptDecision.AllowOnce);

        Assert.Equal(0, (await run).ExitCode);
    }

    [Fact]
    public async Task A_caller_killed_mid_prompt_abandons_it()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();
        using var shim = ShimHarness.StartShim(broker.ShimPipeName, ["read", "op://V/I/K"]);

        var prompt = await agent.NextAsync<ShowPrompt>();
        shim.Kill();

        Assert.Equal(new ClosePrompt(prompt.PromptId, "abandoned"), await agent.NextAsync<ClosePrompt>());
        await WaitUntilAsync(() => broker.AuditEntries().Count == 1);
        Assert.Equal("abandoned", broker.AuditEntries()[0].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task An_allowed_item_read_teaches_the_broker_its_aliases()
    {
        const string itemId = "q1w2e3r4t5y6u7i8o9p0a1s2d3";
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)]);
        var itemJson = $$"""{"id":"{{itemId}}","title":"GitHub"}""";

        var run = await broker.RunShimAsync(["item", "get", "GitHub", "--format", "json"], new Dictionary<string, string> { ["PROBE_STDOUT"] = itemJson });

        Assert.Equal(itemJson, run.Stdout);
        await WaitUntilAsync(() => broker.Aliases.NamesFor(AliasKind.Item, itemId).Count == 1);
        var vault = Broker.Integrity.IntegrityVault.Open(Path.Combine(broker.DataDirectory, "integrity.vault"));
        Assert.Equal(["GitHub"], new Broker.Storage.AliasFile(Path.Combine(broker.DataDirectory, "aliases.json"), vault, _ => { }).Load().NamesFor(AliasKind.Item, itemId));
    }

    [Fact]
    public async Task A_run_prompts_for_its_references_and_always_allow_stores_one_rule_each()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();
        var environment = new Dictionary<string, string> { ["OPWARDEN_TEST_A"] = "op://V/db/user", ["OPWARDEN_TEST_B"] = "op://V/db/password" };

        var run = broker.RunShimAsync(["run", "--", "cmd"], environment);
        var prompt = await agent.NextAsync<ShowPrompt>();
        await agent.DecideAsync(prompt, PromptDecision.AlwaysAllow, RuleScope.Exact);

        // The shim also inherits this test process's environment, so assert on these two
        // references rather than on the count.
        Assert.Equal(0, (await run).ExitCode);
        Assert.Contains(new SecretPath("V", "db", "user"), prompt.Paths);
        Assert.Contains(new SecretPath("V", "db", "password"), prompt.Paths);
        Assert.Equal(prompt.Paths.Count, broker.Rules.Current.Rules.Count);
        Assert.False(prompt.OffersCacheGrant);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++) await Task.Delay(50);
        Assert.True(condition(), "The condition did not hold within 5 seconds.");
    }
}
