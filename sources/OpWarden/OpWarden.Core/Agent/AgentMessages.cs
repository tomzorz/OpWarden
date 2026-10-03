using System.Text.Json.Serialization;
using OpWarden.Core.Rules;

namespace OpWarden.Core.Agent;

/// <summary>
/// The interactive user's choice at a prompt (spec glossary: decision).
/// </summary>
public enum PromptDecision
{
    AlwaysAllow,
    AlwaysDisallow,
    AllowOnce,
    DisallowOnce,
}

/// <summary>
/// Which request-tuple fields an <c>always-</c> decision pins; the rest become wildcards
/// (REQ-RULE-7).
/// </summary>
public sealed record RuleScope(bool Caller, bool Action, bool Vault, bool Item, bool Key)
{
    public static RuleScope Exact { get; } = new(true, true, true, true, true);
}

/// <summary>
/// A message between the broker and the session agent. The broker sends prompts,
/// closes them and sends notices; the session agent sends decisions.
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(ShowPrompt), "show-prompt")]
[JsonDerivedType(typeof(ClosePrompt), "close-prompt")]
[JsonDerivedType(typeof(ShowNotice), "show-notice")]
[JsonDerivedType(typeof(DecisionMade), "decision")]
public abstract record AgentMessage;

/// <summary>
/// Show this prompt (REQ-RULE-5, REQ-RULE-6, REQ-RULE-14, REQ-RULE-19).
/// </summary>
/// <param name="Paths">The secret path of each request tuple the prompt decides; one for most invocations, one per secret reference for <c>run</c>.</param>
/// <param name="OffersCacheGrant">True when the prompt shows the cache-grant control.</param>
/// <param name="Deadline">When the broker stops waiting and denies with reason <c>timeout</c>.</param>
public sealed record ShowPrompt(
    Guid PromptId,
    CallerIdentity Caller,
    OpAction Action,
    string? Command,
    IReadOnlyList<SecretPath> Paths,
    bool ReferencesUnknown,
    PromptOptions Options,
    bool OffersCacheGrant,
    DateTimeOffset Deadline) : AgentMessage;

/// <summary>
/// Take this prompt down: the user decided, it timed out, or its caller went away.
/// </summary>
public sealed record ClosePrompt(Guid PromptId, string Reason) : AgentMessage;

/// <summary>
/// Show a notification, such as a rule notice (REQ-RULE-32).
/// </summary>
public sealed record ShowNotice(string Title, string Text) : AgentMessage;

/// <summary>
/// The user's decision on a prompt. <paramref name="Scope"/> applies to <c>always-</c>
/// decisions only; <paramref name="CacheGrant"/> to allowing decisions on a prompt that
/// offered it.
/// </summary>
public sealed record DecisionMade(Guid PromptId, PromptDecision Decision, RuleScope? Scope, CacheTtl? CacheGrant) : AgentMessage;
