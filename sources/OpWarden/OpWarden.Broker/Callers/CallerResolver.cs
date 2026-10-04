using OpWarden.Core.Rules;

namespace OpWarden.Broker.Callers;

/// <summary>
/// An executable that makes its descendants a named agent (REQ-CALL-16). A null signer
/// matches on the file name alone, for unsigned tools; anything can take that name, so
/// such an entry trusts the name, not the binary.
/// </summary>
public sealed record AgentHost(string Name, string FileName, string? Signer);

/// <summary>
/// Who called, and the ancestor chain that says so (REQ-CALL-17).
/// </summary>
public sealed record CallerResolution(CallerIdentity Caller, IReadOnlyList<string> Chain);

/// <summary>
/// Resolves the shim's caller by walking its ancestry (spec section 5.2): through the
/// process map first, through the live process table where the map has no entry, and
/// stopping at the first hop that cannot be proven.
/// </summary>
/// <remarks>
/// <code>
///   shim ─► parent ─► … ─► agent host?  ─► … ─► logon shell?
///           (map entry, else live entry started before its child)
///
///   an agent host anywhere on the way ........ that agent, the nearest one  REQ-CALL-13
///   the logon shell reached, no agent ........ interactive-user             REQ-CALL-15
///   the walk broke or ended anywhere else .... unknown                      REQ-CALL-18
/// </code>
/// </remarks>
public sealed class CallerResolver(
    ProcessMap map,
    IReadOnlyList<AgentHost> agents,
    Func<string, string?> signerOf,
    Func<int, ProcessEntry?> liveProcess,
    Func<int> consoleSession)
{
    /// <summary>
    /// The cycle guard of REQ-CALL-12; MSYS2 alone spends two processes per shell level.
    /// </summary>
    public const int MaxHops = 64;

    private static readonly string Explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");

    public CallerResolution Resolve(int shimProcessId)
    {
        var chain = new List<string>();

        // The shim is alive while it waits for its verdict, so the live table describes it
        // exactly; the map may not have seen its start yet.
        if (liveProcess(shimProcessId) is not { } current) return new(CallerIdentity.Unknown, ["shim process not found"]);

        var session = consoleSession();
        string? agent = null;
        for (var hop = 0; hop < MaxHops; hop++)
        {
            chain.Add($"{current.ImageName}({current.ProcessId})");

            // The shim itself is never its own agent host.
            if (hop > 0 && agent is null) agent = MatchAgent(current);
            if (agent is not null) return new(CallerIdentity.Agent(agent), chain);
            if (IsLogonShell(current, session)) return new(CallerIdentity.InteractiveUser, chain);

            if (Parent(current) is not { } parent)
            {
                chain.Add("(end: no provable parent)");
                return new(CallerIdentity.Unknown, chain);
            }

            current = parent;
        }

        chain.Add("(end: hop limit)");
        return new(CallerIdentity.Unknown, chain);
    }

    /// <summary>
    /// The parent from the process map, or else from the live table, but only a live
    /// parent that started before its child: a later start is a reused process ID
    /// (REQ-CALL-11).
    /// </summary>
    private ProcessEntry? Parent(ProcessEntry child)
    {
        if (map.ParentOf(child) is { } recorded) return recorded;
        if (child.ParentId is ProcessEntry.UnknownParent or 0) return null;
        return liveProcess(child.ParentId) is { CreateTime: > 0 } live && child.CreateTime > 0 && live.CreateTime <= child.CreateTime ? live : null;
    }

    private string? MatchAgent(ProcessEntry process)
    {
        foreach (var host in agents)
        {
            if (!string.Equals(process.ImageName, host.FileName, StringComparison.OrdinalIgnoreCase)) continue;
            if (host.Signer is null) return host.Name;
            if (process.ImagePath is { } path && string.Equals(signerOf(path), host.Signer, StringComparison.OrdinalIgnoreCase)) return host.Name;
        }

        return null;
    }

    private static bool IsLogonShell(ProcessEntry process, int consoleSession) =>
        process.SessionId == consoleSession && string.Equals(process.ImagePath, Explorer, StringComparison.OrdinalIgnoreCase);
}
