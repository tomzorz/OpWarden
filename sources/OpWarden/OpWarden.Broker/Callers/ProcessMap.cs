namespace OpWarden.Broker.Callers;

/// <summary>
/// One process as the broker knows it (REQ-CALL-2).
/// </summary>
/// <param name="CreateTime">Creation time as a UTC FILETIME, the unit ETW and <c>GetProcessTimes</c> both use; 0 when unknown.</param>
/// <param name="ParentId">The parent's process ID, or <see cref="UnknownParent"/> when the parent could not be proven (REQ-CALL-6).</param>
/// <param name="ImagePath">The executable's path as a drive path, or null when unknown.</param>
/// <param name="SessionId">The logon session the process runs in, or -1 when unknown.</param>
public readonly record struct ProcessEntry(int ProcessId, int ParentId, long CreateTime, string? ImagePath, int SessionId = -1)
{
    public const int UnknownParent = -1;

    public string ImageName => ImagePath is null ? "?" : Path.GetFileName(ImagePath);
}

/// <summary>
/// The process map (spec section 5.1): every process start the broker has seen, kept in
/// memory only (REQ-CALL-4) and walked to resolve callers.
/// </summary>
/// <remarks>
/// A process ID can belong to several entries over time, because Windows reuses IDs.
/// Each ID keeps its entries in creation order, and a parent is the entry with the
/// latest creation time at or before the child's (REQ-CALL-9). That is what lets the
/// map answer for an MSYS2 parent that has already exited, the case a live walk cannot.
/// </remarks>
public sealed class ProcessMap(int maxEntries = ProcessMap.DefaultMaxEntries)
{
    // ceiling: REQ-CALL-8's backstop. Reachable entries stay few on a normal machine;
    // the cap only matters when retention cannot keep up.
    public const int DefaultMaxEntries = 50_000;

    private readonly Dictionary<int, List<ProcessEntry>> _byId = [];
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
    /// Stores one process start. This is the whole of what an event handler may do
    /// (REQ-CALL-3): an insert under a lock, no file access, no resolution.
    /// </summary>
    public void Record(ProcessEntry entry)
    {
        lock (_lock)
        {
            if (!_byId.TryGetValue(entry.ProcessId, out var entries)) _byId[entry.ProcessId] = entries = [];
            var at = entries.FindLastIndex(e => e.CreateTime <= entry.CreateTime) + 1;
            if (at > 0 && entries[at - 1].CreateTime == entry.CreateTime) entries[at - 1] = entry;
            else
            {
                entries.Insert(at, entry);
                _count++;
            }
        }
    }

    /// <summary>
    /// Seeds the map from a snapshot of running processes (REQ-CALL-5). A parent that did
    /// not start before its child is a reused ID, so the entry keeps an unknown parent
    /// (REQ-CALL-6).
    /// </summary>
    public void Seed(IReadOnlyList<ProcessEntry> snapshot)
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
    /// The parent entry of <paramref name="child"/> (REQ-CALL-9), or null when the map
    /// does not hold it.
    /// </summary>
    public ProcessEntry? ParentOf(ProcessEntry child) =>
        child.ParentId == ProcessEntry.UnknownParent || child.ParentId == 0 ? null : Find(child.ParentId, child.CreateTime);

    /// <summary>
    /// Deletes every entry that no running process's ancestry reaches (REQ-CALL-7), then
    /// enforces the entry cap (REQ-CALL-8). Returns how many entries the cap deleted, which
    /// the caller records in the audit log.
    /// </summary>
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
