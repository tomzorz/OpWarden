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
/// <param name="AwaitsEvents">True when the walk stopped at a parent whose start or exit the event stream has not delivered yet: walking again after the events arrive may get further (REQ-CALL-26).</param>
public sealed record CallerResolution(CallerIdentity Caller, IReadOnlyList<string> Chain, bool AwaitsEvents = false)
{
    public const string AwaitingMarker = "(waiting for process events)";

    /// <summary>
    /// This resolution as the last word: a walk still waiting for events ends where it
    /// stopped, for <paramref name="reason"/>.
    /// </summary>
    public CallerResolution Final(string reason) =>
        AwaitsEvents ? new(CallerIdentity.Unknown, [.. Chain.Take(Chain.Count - 1), $"(end: {reason})"]) : this;
}

/// <summary>
/// Resolves the shim's caller by walking its ancestry (spec section 5.2): through the
/// running processes where the parent still runs, through the process map where it has
/// exited, and stopping at the first hop that cannot be proven.
/// </summary>
/// <remarks>
/// <code>
///   shim ─► parent ─► … ─► agent host?  ─► … ─► logon shell?
///           (the running process that started first, else a map
///            entry proven to be running when the child started)
///
///   an agent host anywhere on the way ........ that agent, the nearest one  REQ-CALL-13
///   an agent host's name, wrong signature .... unknown                      REQ-CALL-14
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

    // The two roots of what the user starts from the desktop (REQ-CALL-22): explorer for
    // ordinary programs, and the shell infrastructure host for packaged apps such as
    // Windows Terminal, which the Start menu and taskbar activate through it.
    private static readonly string[] LogonShells =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
        Path.Combine(Environment.SystemDirectory, "sihost.exe"),
    ];

    public CallerResolution Resolve(int shimProcessId)
    {
        var chain = new List<string>();

        // The shim is alive while it waits for its verdict, so the live table describes it
        // exactly; the map may not have seen its start yet.
        if (liveProcess(shimProcessId) is not { } current) return new(CallerIdentity.Unknown, ["shim process not found"]);

        var session = consoleSession();
        for (var hop = 0; hop < MaxHops; hop++)
        {
            chain.Add($"{current.ImageName}({current.ProcessId})");

            // The shim itself is never its own agent host.
            if (hop > 0)
            {
                var (agent, unverified) = MatchAgent(current);
                if (agent is not null) return new(CallerIdentity.Agent(agent), chain);
                if (unverified is not null)
                {
                    chain.Add($"(end: not signed by {unverified})");
                    return new(CallerIdentity.Unknown, chain);
                }
            }

            if (IsLogonShell(current, session)) return new(CallerIdentity.InteractiveUser, chain);

            if (Parent(current, out var awaitsEvents) is not { } parent)
            {
                if (awaitsEvents)
                {
                    chain.Add(CallerResolution.AwaitingMarker);
                    return new(CallerIdentity.Unknown, chain, AwaitsEvents: true);
                }

                chain.Add("(end: no provable parent)");
                return new(CallerIdentity.Unknown, chain);
            }

            current = parent;
        }

        chain.Add("(end: hop limit)");
        return new(CallerIdentity.Unknown, chain);
    }

    /// <summary>
    /// The parent of <paramref name="child"/> (REQ-CALL-9), or null with
    /// <paramref name="awaitsEvents"/> set when the events that would name it are still on
    /// their way.
    /// </summary>
    private ProcessEntry? Parent(ProcessEntry child, out bool awaitsEvents)
    {
        awaitsEvents = false;
        if (child.ParentId is ProcessEntry.UnknownParent or 0 || child.CreateTime == 0) return null;

        // A running process with the parent's ID that started first is the parent. Two
        // running processes never share an ID, and a later holder of the ID started after
        // the true parent exited, so after the child too (REQ-CALL-11).
        if (liveProcess(child.ParentId) is { CreateTime: > 0 } live && live.CreateTime <= child.CreateTime) return live;

        switch (map.FindParent(child.ParentId, child.CreateTime))
        {
            case ParentLookup.Found found:
                return found.Entry;
            case ParentLookup.ExitUnreported:
                // Nothing running fits, so the entry has exited; whether before or after
                // the child started, only its exit event can say.
                awaitsEvents = true;
                return null;
            default:
                // A parent of a process younger than the snapshot is in the snapshot or in
                // the event stream; if not yet in the map, its start is still on the way.
                awaitsEvents = child.CreateTime > map.SeededAt;
                return null;
        }
    }

    /// <summary>
    /// The agent this process hosts, or else the signer it failed to show: a process that
    /// takes an agent host's file name without its signature ends the walk as unknown
    /// (REQ-CALL-14). Walking on past it would reach the logon shell and promote whatever
    /// runs under it to the interactive user.
    /// </summary>
    private (string? Agent, string? Unverified) MatchAgent(ProcessEntry process)
    {
        string? unverified = null;
        foreach (var host in agents)
        {
            if (!string.Equals(process.ImageName, host.FileName, StringComparison.OrdinalIgnoreCase)) continue;
            if (host.Signer is null) return (host.Name, null);
            if (process.ImagePath is { } path && string.Equals(signerOf(path), host.Signer, StringComparison.OrdinalIgnoreCase)) return (host.Name, null);
            unverified = host.Signer;
        }

        return (null, unverified);
    }

    private static bool IsLogonShell(ProcessEntry process, int consoleSession) =>
        process.SessionId == consoleSession && LogonShells.Contains(process.ImagePath, StringComparer.OrdinalIgnoreCase);
}
