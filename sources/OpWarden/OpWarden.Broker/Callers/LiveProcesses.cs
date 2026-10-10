using System.Runtime.InteropServices;

namespace OpWarden.Broker.Callers;

/// <summary>
/// The processes running now: the seed of the process map (REQ-CALL-5), the live fallback
/// of the walk (REQ-CALL-11), and the running set that retention keeps (REQ-CALL-7).
/// </summary>
/// <remarks>
/// Everything comes from <c>NtQuerySystemInformation</c>, which describes every process
/// without opening any. The broker runs as a virtual service account, and Windows lets
/// that account open none of the interactive user's processes, so <c>OpenProcess</c>
/// plus <c>GetProcessTimes</c> would leave every user process without a start time and
/// unprovable as anyone's parent. <c>SystemProcessIdInformation</c> (class 88) is
/// undocumented but has kept its shape since Vista; Process Explorer and psutil read
/// image paths through it for the same reason.
/// </remarks>
public static unsafe partial class LiveProcesses
{
    /// <summary>
    /// Every running process, fully described. Looks up every image path, so it belongs
    /// to seeding and retention, not to the per-invocation walk.
    /// </summary>
    public static IReadOnlyList<ProcessEntry> Snapshot() => [.. Enumerate().Select(p => p with { ImagePath = ImagePathOf(p.ProcessId) ?? p.ImagePath })];

    /// <summary>
    /// The live entry for one process ID, with its parent as Windows records it now, or
    /// null when no such process runs. Parent and child must still be proven by start
    /// order (REQ-CALL-11); that is the walker's job.
    /// </summary>
    public static ProcessEntry? Find(int processId)
    {
        foreach (var process in Enumerate())
        {
            if (process.ProcessId == processId) return process with { ImagePath = ImagePathOf(processId) ?? process.ImagePath };
        }

        return null;
    }

    /// <summary>
    /// The logon session the user sits at.
    /// </summary>
    public static int ConsoleSessionId => (int)WTSGetActiveConsoleSessionId();

    /// <summary>
    /// The executable's drive path, or null for the pseudo-processes that have none (Idle,
    /// System) and for a process that exited meanwhile.
    /// </summary>
    public static string? ImagePathOf(int processId)
    {
        const int Capacity = 32_767;
        var buffer = (char*)NativeMemory.Alloc(Capacity * sizeof(char));
        try
        {
            var info = new SYSTEM_PROCESS_ID_INFORMATION
            {
                ProcessId = processId,
                ImageName = new UNICODE_STRING { Length = 0, MaximumLength = (Capacity - 1) * sizeof(char), Buffer = buffer },
            };
            if (NtQuerySystemInformation(SystemProcessIdInformation, &info, (uint)sizeof(SYSTEM_PROCESS_ID_INFORMATION), null) != 0) return null;
            return info.ImageName.Length == 0 ? null : DevicePaths.ToDrivePath(new string(buffer, 0, info.ImageName.Length / sizeof(char)));
        }
        finally
        {
            NativeMemory.Free(buffer);
        }
    }

    /// <summary>
    /// IDs, parent IDs, start times, sessions and bare file names of every process, with
    /// no process handle: the bare name stands in as the path until <see cref="ImagePathOf"/>
    /// fills it.
    /// </summary>
    private static List<ProcessEntry> Enumerate()
    {
        var result = new List<ProcessEntry>();
        var size = 512u * 1024;
        while (true)
        {
            var buffer = (byte*)NativeMemory.Alloc(size);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
                if (status == StatusInfoLengthMismatch)
                {
                    // Processes started between the calls; leave headroom for the next ones.
                    size += 64 * 1024;
                    continue;
                }

                if (status != 0) throw new InvalidOperationException($"NtQuerySystemInformation(SystemProcessInformation) failed with NTSTATUS 0x{status:X8}.");

                var offset = 0u;
                while (true)
                {
                    var entry = (SYSTEM_PROCESS_INFORMATION*)(buffer + offset);
                    var name = entry->ImageName.Length == 0 ? null : new string(entry->ImageName.Buffer, 0, entry->ImageName.Length / sizeof(char));
                    result.Add(new ProcessEntry((int)entry->UniqueProcessId, (int)entry->InheritedFromUniqueProcessId, entry->CreateTime, name, (int)entry->SessionId));
                    if (entry->NextEntryOffset == 0) return result;
                    offset += entry->NextEntryOffset;
                }
            }
            finally
            {
                NativeMemory.Free(buffer);
            }
        }
    }

    private const int SystemProcessInformation = 5, SystemProcessIdInformation = 88;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length, MaximumLength;
        public char* Buffer;
    }

    /// <summary>
    /// The head of one process record; the thread records that follow it are not read.
    /// The fields up to <c>CreateTime</c> are what winternl.h calls <c>Reserved1</c>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset, NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount, NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime, UserTime, KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public nint UniqueProcessId, InheritedFromUniqueProcessId;
        public uint HandleCount, SessionId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_ID_INFORMATION
    {
        public nint ProcessId;
        public UNICODE_STRING ImageName;
    }

    [LibraryImport("ntdll.dll")] private static partial int NtQuerySystemInformation(int informationClass, void* information, uint length, uint* returnLength);
    [LibraryImport("kernel32.dll")] private static partial uint WTSGetActiveConsoleSessionId();
}

/// <summary>
/// Turns the NT device paths that kernel events carry (<c>\Device\HarddiskVolume3\…</c>)
/// into drive paths (<c>C:\…</c>), so signature checks and comparisons see ordinary paths.
/// </summary>
public static unsafe partial class DevicePaths
{
    private static readonly Lock Gate = new();
    private static Dictionary<string, string> _deviceToDrive = Load();

    public static string ToDrivePath(string path)
    {
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;
        if (Translate(path) is { } translated) return translated;

        // A drive mounted since the broker started: reload once and try again.
        lock (Gate) _deviceToDrive = Load();
        return Translate(path) ?? path;
    }

    private static string? Translate(string path)
    {
        Dictionary<string, string> map;
        lock (Gate) map = _deviceToDrive;
        foreach (var (device, drive) in map)
        {
            if (path.StartsWith(device + @"\", StringComparison.OrdinalIgnoreCase)) return drive + path[device.Length..];
        }

        return null;
    }

    private static Dictionary<string, string> Load()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buffer = stackalloc char[512];
        foreach (var letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        {
            var drive = $"{letter}:";
            var length = QueryDosDeviceW(drive, buffer, 512);
            if (length > 0) map[new string(buffer)] = drive;
        }

        return map;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial uint QueryDosDeviceW(string device, char* target, uint max);
}
