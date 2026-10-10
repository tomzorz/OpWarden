namespace OpWarden.Broker.Callers;

/// <summary>
/// One process as the broker knows it (REQ-CALL-2).
/// </summary>
/// <param name="CreateTime">Creation time as a UTC FILETIME, the unit ETW and <c>GetProcessTimes</c> both use; 0 when unknown.</param>
/// <param name="ParentId">The parent's process ID, or <see cref="UnknownParent"/> when the parent could not be proven (REQ-CALL-6).</param>
/// <param name="ImagePath">The executable's path as a drive path, or null when unknown.</param>
/// <param name="SessionId">The logon session the process runs in, or -1 when unknown.</param>
/// <param name="ExitTime">When the process exited, as a UTC FILETIME; 0 while no exit event has arrived for it.</param>
public readonly record struct ProcessEntry(int ProcessId, int ParentId, long CreateTime, string? ImagePath, int SessionId = -1, long ExitTime = 0)
{
    public const int UnknownParent = -1;

    public string ImageName => ImagePath is null ? "?" : Path.GetFileName(ImagePath);
}

/// <summary>
/// One process exit, as a ProcessStop event reports it. The creation time tells it apart
/// from every other process that ever had the same ID.
/// </summary>
public readonly record struct ProcessExit(int ProcessId, long CreateTime, long ExitTime);

/// <summary>
/// What the map knows about a parent: the entry, proven alive when the child started; an
/// entry whose exit has not been reported yet; or nothing that fits.
/// </summary>
public abstract record ParentLookup
{
    public sealed record Found(ProcessEntry Entry) : ParentLookup;

    public sealed record ExitUnreported(ProcessEntry Entry) : ParentLookup;

    public sealed record Missing : ParentLookup;
}

/// <summary>
/// The process map (spec section 5.1): every process start and exit the broker has seen,
/// kept in memory only (REQ-CALL-4) and walked to resolve callers.
/// </summary>
/// <remarks>
/// A process ID can belong to several entries over time, because Windows reuses IDs, and
/// ETW delivers events up to a second late. So the newest entry for an ID that started
/// before a child is the child's parent only if it was still running when the child
/// started (REQ-CALL-9). An entry that exited earlier belongs to an earlier process with
/// the same ID, and stands in for a parent whose own start has not arrived yet. That is
/// exactly how a busy machine's short-lived processes ended up as the parents of shells
/// they never met, before exits were recorded.
/// </remarks>
public sealed class ProcessMap(int maxEntries = ProcessMap.DefaultMaxEntries)
{
    // ceiling: REQ-CALL-8's backstop. Reachable entries stay few on a normal machine;
    // the cap only matters when retention cannot keep up.
    public const int DefaultMaxEntries = 50_000;

    // ceiling: exits that arrive before their process's start, or for a process the map
    // never saw (it exited between the subscription and the snapshot). The cap keeps a
    // flood of those from growing without bound; one lost here only makes a walk wait.
    private const int MaxPendingExits = 4_096;

    private readonly Dictionary<int, List<ProcessEntry>> _byId = [];
    private readonly Dictionary<(int ProcessId, long CreateTime), long> _pendingExits = [];
    private readonly Lock _lock = new();
    private int _count;

    public int Count
    {
        get
        {
            lock (_lock) return _count;
        }
    }

    /// <summary>
    /// When the seeding snapshot was taken, as a UTC FILETIME. A process created later has
    /// every ancestor either in the snapshot or in the event stream; 0 before seeding.
    /// </summary>
    public long SeededAt { get; private set; }

    /// <summary>
    /// Stores one process start. This is the whole of what an event handler may do
    /// (REQ-CALL-3): an insert under a lock, no file access, no resolution.
    /// </summary>
    public void Record(ProcessEntry entry)
    {
        lock (_lock)
        {
            if (entry.ExitTime == 0 && _pendingExits.Remove((entry.ProcessId, entry.CreateTime), out var exited)) entry = entry with { ExitTime = exited };

            if (!_byId.TryGetValue(entry.ProcessId, out var entries)) _byId[entry.ProcessId] = entries = [];
            var at = entries.FindLastIndex(e => e.CreateTime <= entry.CreateTime) + 1;
            if (at > 0 && entries[at - 1].CreateTime == entry.CreateTime)
            {
                // The same process seen twice (snapshot and event): keep what either knew.
                var known = entries[at - 1];
                entries[at - 1] = entry with { ExitTime = entry.ExitTime != 0 ? entry.ExitTime : known.ExitTime };
            }
            else
            {
                entries.Insert(at, entry);
                _count++;
            }
        }
    }

    /// <summary>
    /// Stores one process exit (REQ-CALL-2). ETW buffers events per processor, so an exit
    /// can arrive before its own start; it then waits for the start.
    /// </summary>
    public void RecordExit(ProcessExit exit)
    {
        lock (_lock)
        {
            if (_byId.TryGetValue(exit.ProcessId, out var entries))
            {
                var at = entries.FindIndex(e => e.CreateTime == exit.CreateTime);
                if (at >= 0)
                {
                    entries[at] = entries[at] with { ExitTime = exit.ExitTime };
                    return;
                }
            }

            if (_pendingExits.Count >= MaxPendingExits) _pendingExits.Clear();
            _pendingExits[(exit.ProcessId, exit.CreateTime)] = exit.ExitTime;
        }
    }

    /// <summary>
    /// Seeds the map from a snapshot of running processes (REQ-CALL-5). A parent that did
    /// not start before its child is a reused ID, so the entry keeps an unknown parent
    /// (REQ-CALL-6).
    /// </summary>
    /// <param name="takenAt">When the snapshot was taken, read before taking it.</param>
    public void Seed(IReadOnlyList<ProcessEntry> snapshot, long takenAt)
    {
        var created = snapshot.GroupBy(p => p.ProcessId).ToDictionary(g => g.Key, g => g.First().CreateTime);
        foreach (var process in snapshot)
        {
            var parentProven = process.CreateTime != 0
                && created.TryGetValue(process.ParentId, out var parentCreated)
                && parentCreated != 0
                && parentCreated <= process.CreateTime;
            Record(parentProven ? process : process with { ParentId = ProcessEntry.UnknownParent });
        }

        SeededAt = takenAt;
    }

    /// <summary>
    /// The entry for a process ID created at or before <paramref name="createdBy"/>: the
    /// newest such entry, which for a live process is the process itself.
    /// </summary>
    public ProcessEntry? Find(int processId, long createdBy)
    {
        lock (_lock) return FindUnlocked(processId, createdBy);
    }

    /// <summary>
    /// The parent of a process created at <paramref name="childCreated"/>, as far as the map
    /// can prove it (REQ-CALL-9). The caller checks the running processes first: a parent
    /// still running is not the map's to judge.
    /// </summary>
    public ParentLookup FindParent(int parentId, long childCreated)
    {
        lock (_lock)
        {
            if (FindUnlocked(parentId, childCreated) is not { } candidate) return new ParentLookup.Missing();
            if (candidate.ExitTime == 0) return new ParentLookup.ExitUnreported(candidate);
            return candidate.ExitTime >= childCreated ? new ParentLookup.Found(candidate) : new ParentLookup.Missing();
        }
    }

    /// <summary>
    /// Deletes every entry that no running process's ancestry reaches (REQ-CALL-7), then
    /// enforces the entry cap (REQ-CALL-8). Returns how many entries the cap deleted, which
    /// the caller records in the audit log.
    /// </summary>
    /// <remarks>
    /// Reachability follows the newest entry at or before each child, without the exit
    /// check of <see cref="FindParent"/>: keeping an entry too many costs memory, dropping
    /// a true parent costs a resolution.
    /// </remarks>
    public int Retain(IReadOnlyCollection<ProcessEntry> running)
    {
        lock (_lock)
        {
            var keep = new HashSet<(int, long)>();
            foreach (var process in running)
            {
                ProcessEntry? current = FindUnlocked(process.ProcessId, process.CreateTime);
                for (var hops = 0; current is { } entry && hops < CallerResolver.MaxHops && keep.Add((entry.ProcessId, entry.CreateTime)); hops++)
                {
                    current = entry.ParentId is ProcessEntry.UnknownParent or 0 ? null : FindUnlocked(entry.ParentId, entry.CreateTime);
                }
            }

            foreach (var (id, entries) in _byId.ToList())
            {
                _count -= entries.RemoveAll(e => !keep.Contains((e.ProcessId, e.CreateTime)));
                if (entries.Count == 0) _byId.Remove(id);
            }

            var overflow = _count - maxEntries;
            if (overflow <= 0) return 0;

            // Still over the cap with only reachable entries left: drop the oldest.
            foreach (var victim in _byId.Values.SelectMany(e => e).OrderBy(e => e.CreateTime).Take(overflow).ToList())
            {
                _byId[victim.ProcessId].Remove(victim);
                if (_byId[victim.ProcessId].Count == 0) _byId.Remove(victim.ProcessId);
                _count--;
            }

            return overflow;
        }
    }

    private ProcessEntry? FindUnlocked(int processId, long createdBy)
    {
        if (!_byId.TryGetValue(processId, out var entries)) return null;
        for (var i = entries.Count - 1; i >= 0; i--)
        {
            if (entries[i].CreateTime <= createdBy) return entries[i];
        }

        return null;
    }
}
