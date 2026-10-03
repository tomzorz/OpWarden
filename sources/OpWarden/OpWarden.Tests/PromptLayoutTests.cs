using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;
using OpWarden.SessionAgent;

namespace OpWarden.Tests;

public sealed class PromptLayoutTests
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");

    private static ShowPrompt Prompt(IReadOnlyList<SecretPath> paths, PromptOptions options = PromptOptions.AllDecisions, CallerIdentity? caller = null, bool referencesUnknown = false, bool offersCache = false, OpAction action = OpAction.Read, string? command = "read") =>
        new(Guid.NewGuid(), caller ?? Claude, action, command, paths, referencesUnknown, options, offersCache, DateTimeOffset.UtcNow.AddSeconds(30));

    [Fact]
    public void One_tuple_shows_its_fields_and_pins_only_the_known_ones()
    {
        var layout = PromptLayout.From(Prompt([new SecretPath("Private", "GitHub", null)]));

        Assert.Equal("claude-code wants to read", layout.Title);
        Assert.Equal("op read", layout.Command);
        Assert.Equal(["claude-code", "read", "Private", "GitHub", PromptLayout.Unknown], layout.Fields.Select(f => f.Value));
        Assert.Equal([true, true, true, true, false], layout.Fields.Select(f => f.Pinnable));
        Assert.Empty(layout.References);
        Assert.True(layout.OffersAlways);
    }

    [Fact]
    public void Several_references_are_listed_and_a_field_pins_only_when_every_reference_knows_it()
    {
        var layout = PromptLayout.From(Prompt([new SecretPath("Infra", "postgres", "username"), new SecretPath("Infra", null, "token")], action: OpAction.Run, command: "run"));

        Assert.Equal([PromptLayout.Varies, PromptLayout.Varies, PromptLayout.Varies], layout.Fields.Skip(2).Select(f => f.Value));
        Assert.Equal([true, false, true], layout.Fields.Skip(2).Select(f => f.Pinnable));
        Assert.Equal(["Infra / postgres / username", $"Infra / {PromptLayout.Unknown} / token"], layout.References);
    }

    [Fact]
    public void Unknown_references_get_a_note_and_no_always_decisions_when_nothing_is_listed()
    {
        var layout = PromptLayout.From(Prompt([], referencesUnknown: true, action: OpAction.Run, command: "run"));

        Assert.NotNull(layout.ReferencesNote);
        Assert.False(layout.OffersAlways);
    }

    [Fact]
    public void An_unknown_caller_reads_as_unidentified_and_gets_once_only()
    {
        var layout = PromptLayout.From(Prompt([new SecretPath("V", "I", "K")], PromptOptions.OnceOnly, CallerIdentity.Unknown));

        Assert.StartsWith("An unidentified caller", layout.Title, StringComparison.Ordinal);
        Assert.False(layout.OffersAlways);
    }

    [Fact]
    public void An_unrecognised_command_says_so()
    {
        var layout = PromptLayout.From(Prompt([SecretPath.Unknown], action: OpAction.Unknown, command: null));

        Assert.Contains("unrecognised", layout.Title, StringComparison.Ordinal);
        Assert.Equal("op (unrecognised command)", layout.Command);
    }

    [Theory]
    [InlineData(PromptDecision.AlwaysAllow, true, 2, CacheTtl.OneHour)]
    [InlineData(PromptDecision.AllowOnce, false, 3, CacheTtl.EightHours)]
    [InlineData(PromptDecision.DisallowOnce, false, 2, null)]
    [InlineData(PromptDecision.AlwaysDisallow, true, 2, null)]
    public void The_decision_carries_scope_only_when_always_and_a_grant_only_when_allowing(PromptDecision decision, bool hasScope, int cacheChoice, CacheTtl? grant)
    {
        var prompt = Prompt([new SecretPath("V", "I", "K")], offersCache: true);

        var made = DecisionBuilder.Build(prompt, decision, [true, true, true, false, false], cacheChoice);

        Assert.Equal(prompt.PromptId, made.PromptId);
        Assert.Equal(hasScope ? new RuleScope(true, true, true, false, false) : null, made.Scope);
        Assert.Equal(grant, made.CacheGrant);
    }

    [Fact]
    public void No_grant_rides_on_a_prompt_that_did_not_offer_one()
    {
        Assert.Null(DecisionBuilder.Build(Prompt([new SecretPath("V", "I", "K")]), PromptDecision.AllowOnce, [true, true, true, true, true], 3).CacheGrant);
    }
}
