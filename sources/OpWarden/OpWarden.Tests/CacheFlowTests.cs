using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The cache end to end (spec section 9): real shim, whole broker, and a session agent
/// on the user's behalf. A served answer shows as the probe not running.
/// </summary>
public sealed class CacheFlowTests : IDisposable
{
    private const int ExitDenied = 77;
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");

    private readonly DirectoryInfo _scratch = Directory.CreateTempSubdirectory("opwarden-cacheflow-");

    public void Dispose() => _scratch.Delete(recursive: true);

    private string ArgvFile => Path.Combine(_scratch.FullName, "argv.json");

    private Dictionary<string, string> Probe(string stdout) => new() { ["PROBE_STDOUT"] = stdout, ["PROBE_ARGV_FILE"] = ArgvFile };

    private bool ProbeRan()
    {
        var ran = File.Exists(ArgvFile);
        if (ran) File.Delete(ArgvFile);
        return ran;
    }

    [Fact]
    public async Task An_always_allow_with_a_grant_answers_the_next_identical_read_from_the_cache()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var first = broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret\n"));
        var prompt = await agent.NextAsync<ShowPrompt>();
        Assert.True(prompt.OffersCacheGrant);
        await agent.DecideAsync(prompt, PromptDecision.AlwaysAllow, RuleScope.Exact, CacheTtl.OneHour);
        Assert.Equal("s3cret\n", (await first).Stdout);
        Assert.True(ProbeRan());
        await WaitUntilAsync(() => broker.Cache.Count == 1);

        var second = await broker.RunShimAsync(["read", "op://V/I/K"], Probe("this would be wrong"));

        Assert.Equal(0, second.ExitCode);
        Assert.Equal("s3cret\n", second.Stdout);
        Assert.False(ProbeRan());
        Assert.Equal("cache", broker.AuditEntries().Last(e => e.GetProperty("event").GetString() == "invocation").GetProperty("reason").GetString());
    }

    [Fact]
    public async Task An_allow_once_with_a_grant_answers_repeats_without_a_prompt()
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var first = broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret"));
        await agent.DecideAsync(await agent.NextAsync<ShowPrompt>(), PromptDecision.AllowOnce, grant: CacheTtl.FifteenMinutes);
        await first;
        await WaitUntilAsync(() => broker.Cache.Count == 1);
        ProbeRan();

        var second = await broker.RunShimAsync(["read", "op://V/I/K"], Probe("wrong"));

        Assert.Equal("s3cret", second.Stdout);
        Assert.False(ProbeRan());
        Assert.Empty(broker.Rules.Current.Rules);
    }

    [Fact]
    public async Task A_rule_with_a_grant_fills_the_cache_without_any_prompt()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, "V", null, null, Verdict.Allow, CacheTtl.OneHour)]);

        await broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret"));
        await WaitUntilAsync(() => broker.Cache.Count == 1);
        ProbeRan();

        Assert.Equal("s3cret", (await broker.RunShimAsync(["read", "op://V/I/K"], Probe("wrong"))).Stdout);
        Assert.False(ProbeRan());
    }

    [Fact]
    public async Task A_failed_read_is_never_cached()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow, CacheTtl.OneHour)]);
        var failing = Probe("partial");
        failing["PROBE_EXIT"] = "1";

        await broker.RunShimAsync(["read", "op://V/I/K"], failing);
        await Task.Delay(300, TestContext.Current.CancellationToken);

        Assert.Equal(0, broker.Cache.Count);
    }

    [Fact]
    public async Task A_deny_rule_stored_later_outranks_a_cache_entry()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow, CacheTtl.OneHour)]);
        await broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret"));
        await WaitUntilAsync(() => broker.Cache.Count == 1);

        broker.Rules.Add([new Rule(Claude, null, "V", null, null, Verdict.Deny)]);

        Assert.Equal(ExitDenied, (await broker.RunShimAsync(["read", "op://V/I/K"])).ExitCode);
    }

    [Fact]
    public async Task Locking_the_workstation_flushes_the_cache()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow, CacheTtl.EightHours)]);
        await using var agent = await broker.ConnectAgentAsync();
        await broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret"));
        await WaitUntilAsync(() => broker.Cache.Count == 1);

        await agent.SendAsync(new WorkstationLocked());

        await WaitUntilAsync(() => broker.Cache.Count == 0);
        Assert.Contains(broker.AuditEntries(), e => e.GetProperty("event").GetString() == "cache-flush");
    }

    [Theory]
    [InlineData("read|op://V/I/K|--out-file|secret.txt")]
    [InlineData("read|-o|secret.txt|op://V/I/K")]
    [InlineData("item|get|I|--vault|V")]
    public async Task No_grant_is_offered_where_a_cached_answer_could_not_stand_in(string arguments)
    {
        await using var broker = BrokerHarness.Start(Claude);
        await using var agent = await broker.ConnectAgentAsync();

        var run = broker.RunShimAsync(arguments.Split('|'));
        var prompt = await agent.NextAsync<ShowPrompt>();
        await agent.DecideAsync(prompt, PromptDecision.DisallowOnce);
        await run;

        Assert.False(prompt.OffersCacheGrant);
    }

    [Fact]
    public async Task A_prompt_always_vault_offers_no_grant_and_ignores_the_cache()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow, CacheTtl.OneHour)]);
        await using var agent = await broker.ConnectAgentAsync();
        await broker.RunShimAsync(["read", "op://V/I/K"], Probe("s3cret"));
        await WaitUntilAsync(() => broker.Cache.Count == 1);

        broker.Rules.MarkPromptAlways("V");
        var run = broker.RunShimAsync(["read", "op://V/I/K"]);
        var prompt = await agent.NextAsync<ShowPrompt>();
        await agent.DecideAsync(prompt, PromptDecision.DisallowOnce);

        Assert.Equal(PromptOptions.OnceOnly, prompt.Options);
        Assert.False(prompt.OffersCacheGrant);
        Assert.Equal(ExitDenied, (await run).ExitCode);
    }

    [Fact]
    public async Task A_rule_store_tampered_while_the_broker_was_down_is_reported_once_a_session_agent_connects()
    {
        var data = Directory.CreateTempSubdirectory("opwarden-tamper-");
        try
        {
            await using (var first = BrokerHarness.StartIn(data, Claude))
            {
                first.Rules.Add([new Rule(null, null, "Prod", null, null, Verdict.Deny)]);
            }

            var rulesPath = Path.Combine(data.FullName, "rules.json");
            await File.WriteAllTextAsync(rulesPath, (await File.ReadAllTextAsync(rulesPath, TestContext.Current.CancellationToken)).Replace("\"Deny\"", "\"Allow\"", StringComparison.Ordinal), TestContext.Current.CancellationToken);

            await using var second = BrokerHarness.StartIn(data, Claude);
            await using var agent = await second.ConnectAgentAsync();

            var notice = await agent.NextAsync<ShowNotice>();
            Assert.Equal("OpWarden integrity warning", notice.Title);
            Assert.Empty(second.Rules.Current.Rules);
            Assert.Contains(second.AuditEntries(), e => e.GetProperty("event").GetString() == "integrity-failure");
        }
        finally
        {
            data.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Alias_pairs_changed_in_broker_memory_are_reported_at_the_next_evaluation()
    {
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)]);
        await using var agent = await broker.ConnectAgentAsync();
        broker.Aliases.Add(new AliasPair(AliasKind.Item, "GitHub", "q1w2e3r4t5y6u7i8o9p0a1s2d3"));
        var idsByName = (Dictionary<(AliasKind, string), HashSet<string>>)typeof(AliasStore).GetField("_idsByName", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(broker.Aliases)!;
        idsByName[(AliasKind.Item, "PAYROLL")] = ["q1w2e3r4t5y6u7i8o9p0a1s2d3"];

        await broker.RunShimAsync(["read", "op://V/I/K"]);

        Assert.Equal("OpWarden integrity warning", (await agent.NextAsync<ShowNotice>()).Title);
        Assert.True(broker.Aliases.IsIntact());
        Assert.Contains(broker.AuditEntries(), e => e.GetProperty("event").GetString() == "integrity-failure");
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++) await Task.Delay(50);
        Assert.True(condition(), "The condition did not hold within 5 seconds.");
    }
}
