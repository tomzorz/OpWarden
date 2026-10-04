using OpWarden.Core;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class RuleAdvisorTests
{
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private const string ProdId = "q1w2e3r4t5y6u7i8o9p0a1s2d3";
    private const string GitHubId1 = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string GitHubId2 = "cccccccccccccccccccccccccc";
    private const string ApiKeyFieldId = "dddddddddddddddddddddddddd";

    [Fact]
    public void An_allow_rule_pinning_a_name_with_no_known_id_gets_a_notice()
    {
        var rule = new Rule(Claude, OpAction.Read, "Prod", null, null, Verdict.Allow);

        var notice = Assert.Single(Review([rule]));

        Assert.Equal(NoticeKind.OtherFormUnknown, notice.Kind);
        Assert.Equal(AliasKind.Vault, notice.Field);
        Assert.Null(notice.Suggestion);
    }

    [Fact]
    public void A_deny_rule_needs_no_notice_for_an_unseen_other_form()
    {
        Assert.Empty(Review([new Rule(Claude, null, "Prod", null, "API Key", Verdict.Deny)]));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("Login/notesPlain")]
    public void The_password_and_notes_fields_have_no_second_form(string key)
    {
        Assert.Empty(Review([new Rule(Claude, null, null, null, key, Verdict.Allow)]));
    }

    [Fact]
    public void The_username_field_gets_a_notice_because_its_label_varies()
    {
        var notice = Assert.Single(Review([new Rule(Claude, null, null, null, "username", Verdict.Allow)]));

        Assert.Equal(NoticeKind.OtherFormUnknown, notice.Kind);
    }

    [Fact]
    public void A_known_id_is_offered_as_a_counterpart_rule()
    {
        var rule = new Rule(Claude, OpAction.Read, "Prod", "I", "K", Verdict.Allow, CacheTtl.OneHour);
        var aliases = Aliases(new AliasPair(AliasKind.Vault, "Prod", ProdId));

        var notice = Assert.Single(Review([rule], aliases), n => n.Field == AliasKind.Vault);

        Assert.Equal(NoticeKind.OtherFormKnown, notice.Kind);
        Assert.Equal(new Rule(Claude, OpAction.Read, ProdId, "I", "K", Verdict.Allow, CacheTtl.OneHour), notice.Suggestion);
    }

    [Fact]
    public void A_known_name_is_offered_for_a_rule_pinning_the_id_spelled_as_seen()
    {
        var rule = new Rule(Claude, null, ProdId, null, null, Verdict.Deny);

        var notice = Assert.Single(Review([rule], Aliases(new AliasPair(AliasKind.Vault, "Prod", ProdId))));

        Assert.Equal(new Rule(Claude, null, "Prod", null, null, Verdict.Deny), notice.Suggestion);
    }

    [Fact]
    public void No_counterpart_is_offered_when_a_rule_already_pins_it()
    {
        var aliases = Aliases(new AliasPair(AliasKind.Vault, "Prod", ProdId));
        Rule[] rules = [new(Claude, null, "Prod", null, null, Verdict.Deny), new(Claude, null, ProdId, null, null, Verdict.Deny)];

        Assert.Empty(Review(rules, aliases));
        Assert.Empty(Review([new(Claude, null, "prod", null, null, Verdict.Deny), new(Claude, null, ProdId, null, null, Verdict.Deny)], aliases));
    }

    [Fact]
    public void A_field_counterpart_keeps_its_section()
    {
        var rule = new Rule(Claude, null, null, null, "Login/API Key", Verdict.Allow);

        var notice = Assert.Single(Review([rule], Aliases(new AliasPair(AliasKind.Field, "API Key", ApiKeyFieldId))));

        Assert.Equal(AliasKind.Field, notice.Field);
        Assert.Equal("API Key", notice.PinnedValue);
        Assert.Equal("Login/" + ApiKeyFieldId, notice.Suggestion?.Key);
    }

    [Fact]
    public void A_name_with_several_ids_gets_an_ambiguity_notice_and_no_suggestion()
    {
        var aliases = Aliases(new AliasPair(AliasKind.Item, "GitHub", GitHubId1), new AliasPair(AliasKind.Item, "GitHub", GitHubId2));

        var notice = Assert.Single(Review([new Rule(Claude, null, null, "GitHub", null, Verdict.Allow)], aliases));

        Assert.Equal(NoticeKind.OtherFormAmbiguous, notice.Kind);
        Assert.Equal([GitHubId1, GitHubId2], notice.OtherForms);
        Assert.Null(notice.Suggestion);
    }

    [Fact]
    public void Every_pinned_field_is_reviewed_on_its_own()
    {
        var notices = Review([new Rule(Claude, null, "Prod", "GitHub", "API Key", Verdict.Allow)]);

        Assert.Equal([AliasKind.Vault, AliasKind.Item, AliasKind.Field], notices.Select(n => n.Field));
    }

    private static IReadOnlyList<RuleNotice> Review(Rule[] rules, AliasStore? aliases = null) =>
        RuleAdvisor.Review(new RuleSet(rules, []), aliases ?? new AliasStore());

    private static AliasStore Aliases(params AliasPair[] pairs)
    {
        var store = new AliasStore();
        store.AddRange(pairs);
        return store;
    }
}
