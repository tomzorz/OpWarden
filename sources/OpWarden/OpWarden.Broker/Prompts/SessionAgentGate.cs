using OpWarden.Broker.Callers;

namespace OpWarden.Broker.Prompts;

/// <summary>
/// What the pinning test found about one session-agent connection.
/// </summary>
/// <param name="Client">The client process, described for the audit log.</param>
/// <param name="Refusal">Why the connection may not be pinned, or null when it may.</param>
public sealed record SessionAgentCheck(string Client, string? Refusal);

/// <summary>
/// The test of REQ-TRUST-4: a session agent is pinned only when its process runs the
/// installed session-agent executable, in the console session.
/// </summary>
/// <remarks>
/// The image path comes from the kernel's process table rather than from anything the
/// client says, so a same-user process cannot claim to be the session agent; it would
/// have to run the installed executable, which section 16 records as the remaining gap.
/// </remarks>
public sealed class SessionAgentGate(string installedPath)
{
    private readonly string _installedPath = Path.GetFullPath(installedPath);

    public SessionAgentCheck Check(int processId)
    {
        var path = LiveProcesses.ImagePathOf(processId);
        var session = LiveProcesses.Find(processId)?.SessionId ?? -1;
        var console = LiveProcesses.ConsoleSessionId;
        var client = $"{path ?? "?"} (process {processId}, session {session})";

        var refusal = path is null ? "its executable could not be determined"
            : !string.Equals(path, _installedPath, StringComparison.OrdinalIgnoreCase) ? $"it does not run the installed session agent {_installedPath}"
            : session != console ? $"it runs outside the console session {console}"
            : null;
        return new SessionAgentCheck(client, refusal);
    }
}
