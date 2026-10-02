namespace OpWarden.Core.Rules;

/// <summary>
/// Who called the op CLI (spec glossary): a named agent such as <c>claude-code</c>,
/// the interactive user, or <c>unknown</c>.
/// </summary>
public sealed record CallerIdentity(string Name)
{
    public static CallerIdentity InteractiveUser { get; } = new("interactive-user");

    public static CallerIdentity Unknown { get; } = new("unknown");

    public static CallerIdentity Agent(string name) => new(name);

    public bool IsUnknown => this == Unknown;
}
