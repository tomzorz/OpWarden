namespace OpWarden.Core.Pipe;

/// <summary>
/// The shim's question to the broker (REQ-SHIM-2). The caller identity is not in it:
/// the broker resolves that itself from the pipe client, because a same-user shim
/// could claim anything.
/// </summary>
/// <param name="Arguments">The invocation arguments, exactly as the op CLI will receive them.</param>
/// <param name="Command">The resolved command, such as <c>item get</c>, or null.</param>
public sealed record ShimRequest(
    int ProtocolVersion,
    IReadOnlyList<string> Arguments,
    string? Command,
    OpAction Action,
    SecretPath Path,
    IReadOnlyList<SecretPath> SecretReferences,
    bool SecretReferencesUnknown);

public enum Verdict
{
    Allow,
    Deny,
}

/// <summary>
/// The broker's answer. An <see cref="Verdict.Allow"/> carries either the op CLI's path
/// (REQ-SHIM-3) or cached output (REQ-SHIM-10), never both.
/// </summary>
/// <param name="OpPath">The absolute path of the op CLI, from the broker's configuration.</param>
/// <param name="Cached">Output to print instead of running the op CLI.</param>
/// <param name="Message">One line for standard error when the verdict is deny.</param>
public sealed record VerdictResponse(Verdict Verdict, string? OpPath, CachedOutput? Cached, string? Message)
{
    public static VerdictResponse Deny(string message) => new(Verdict.Deny, null, null, message);

    public static VerdictResponse RunOp(string opPath) => new(Verdict.Allow, opPath, null, null);

    public static VerdictResponse FromCache(byte[] output) => new(Verdict.Allow, null, new CachedOutput(output), null);
}

/// <summary>
/// Cached output, wrapped so that "no cached output" (null) and "an empty cached value"
/// stay distinct on the wire: the JSON source generator writes a null byte array as an
/// empty string, and an empty secret is a legitimate value.
/// </summary>
public sealed record CachedOutput(byte[] Bytes);

/// <summary>
/// The copy of an allowed read's standard output (REQ-SHIM-9), sent after the op CLI exits.
/// </summary>
/// <param name="Truncated">True when the output outgrew the capture limit; the copy is then incomplete and must not be cached.</param>
public sealed record ReadCapture(int ExitCode, byte[] Output, bool Truncated);
