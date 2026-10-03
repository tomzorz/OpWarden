namespace OpWarden.Core.CommandLine;

/// <summary>
/// What the arguments alone say about an invocation. Secret references that live in
/// files or in the environment are collected afterwards by <see cref="SecretReferenceCollector"/>.
/// </summary>
/// <param name="Command">The resolved command, such as <c>item get</c>, or null when none resolved.</param>
/// <param name="Action">The action from spec section 6.</param>
/// <param name="Path">The secret path; for <c>run</c> it stays unknown and the references carry the paths.</param>
/// <param name="ArgumentReferences">Secret references given as arguments (<c>op read op://…</c>).</param>
/// <param name="ReferencesUnknown">True when the arguments could not establish which references the invocation uses.</param>
/// <param name="EnvFiles">The <c>op run --env-file</c> values, in order.</param>
/// <param name="TemplateFile">The <c>op inject --in-file</c> value.</param>
/// <param name="OutputFile">The <c>--out-file</c> value: the op CLI then writes its output there, not to standard output.</param>
public sealed record ParsedInvocation(
    string? Command,
    OpAction Action,
    SecretPath Path,
    IReadOnlyList<SecretPath> ArgumentReferences,
    bool ReferencesUnknown,
    IReadOnlyList<string> EnvFiles,
    string? TemplateFile,
    string? OutputFile = null)
{
    /// <summary>
    /// True for <c>op read</c>, the only invocation whose output REQ-CACHE-10 lets the broker cache.
    /// </summary>
    public bool IsOpRead => Command == "read";

    /// <summary>
    /// True for <c>op inject</c> without <c>--in-file</c>: the template arrives on standard
    /// input, which the shim must pass through untouched, so its references stay unknown.
    /// </summary>
    public bool TemplateFromStdin => Command == "inject" && TemplateFile is null;

    internal static ParsedInvocation Unresolved { get; } = new(null, OpAction.Unknown, SecretPath.Unknown, [], false, [], null);
}
