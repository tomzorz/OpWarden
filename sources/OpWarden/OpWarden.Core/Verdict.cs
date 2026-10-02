namespace OpWarden.Core;

/// <summary>
/// The broker's answer to one invocation: exactly allow or deny (spec glossary).
/// </summary>
public enum Verdict
{
    Allow,
    Deny,
}
