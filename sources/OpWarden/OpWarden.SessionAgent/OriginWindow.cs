using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// A top-level window that may be where a read came from, with the creation time of the
/// process that owns it (0 when it cannot be read).
/// </summary>
internal readonly record struct CandidateWindow(nint Handle, int ProcessId, long OwnerCreateTime);

/// <summary>
/// Finds the origin window of a read (REQ-RULE-41): the frontmost window of the nearest
/// ancestor of the shim that still runs and has one.
/// </summary>
/// <remarks>
/// A shell in Windows Terminal or VS Code owns no window of its own; the terminal above it
/// does, so the nearest ancestor with a window is the one to find. A classic console window
/// names the console's first process as its owner rather than conhost, so a plain
/// PowerShell window is found the same way. The hidden window a pseudo console gives its
/// shell is an owned tool window, which the filter drops.
/// </remarks>
internal static class OriginWindow
{
    /// <summary>
    /// The origin window for these ancestors, or 0 when none of them has a window.
    /// </summary>
    public static nint Find(IReadOnlyList<ProcessIdentity> ancestors)
    {
        if (ancestors.Count == 0) return 0;

        var owners = ancestors.Select(a => a.ProcessId).ToHashSet();
        var createTimes = new Dictionary<int, long>();
        var candidates = new List<CandidateWindow>();
        foreach (var window in Native.TopLevelWindows())
        {
            _ = Native.GetWindowThreadProcessId(window, out var owner);
            if (!owners.Contains(owner) || !IsApplicationWindow(window)) continue;
            if (!createTimes.TryGetValue(owner, out var created)) createTimes[owner] = created = Native.CreateTimeOf(owner);
            candidates.Add(new CandidateWindow(window, owner, created));
        }

        return Choose(ancestors, candidates);
    }

    /// <summary>
    /// The frontmost candidate of the nearest ancestor that owns one. A candidate whose
    /// owner started at another time than the ancestor did belongs to a later process that
    /// got the ancestor's ID after the ancestor exited.
    /// </summary>
    internal static nint Choose(IReadOnlyList<ProcessIdentity> ancestors, IReadOnlyList<CandidateWindow> frontToBack)
    {
        foreach (var ancestor in ancestors)
        {
            foreach (var window in frontToBack)
            {
                if (window.ProcessId == ancestor.ProcessId && window.OwnerCreateTime == ancestor.CreateTime) return window.Handle;
            }
        }

        return 0;
    }

    /// <summary>
    /// A window a person would call the app's: shown, on this virtual desktop, neither a
    /// tool palette nor owned by another window, and not empty. A minimized window still
    /// counts, and its toasts wait in the corner until it comes back (REQ-RULE-44).
    /// </summary>
    private static bool IsApplicationWindow(nint window) =>
        Native.IsWindowVisible(window)
        && !Native.IsToolOrOwned(window)
        && !Native.IsCloaked(window)
        && Native.VisibleFrameOf(window) is { Width: > 0, Height: > 0 };
}
