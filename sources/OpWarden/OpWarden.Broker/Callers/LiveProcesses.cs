using System.Runtime.InteropServices;

namespace OpWarden.Broker.Callers;

/// <summary>
/// The processes running now, from the Toolhelp snapshot plus <c>GetProcessTimes</c>: the
/// seed of the process map (REQ-CALL-5), the live fallback of the walk (REQ-CALL-11), and
/// the running set that retention keeps (REQ-CALL-7).
/// </summary>
public static unsafe partial class LiveProcesses
{
    /// <summary>
    /// Every running process, fully described. Opens every process, so it belongs to
    /// seeding and retention, not to the per-invocation walk.
    /// </summary>
    public static IReadOnlyList<ProcessEntry> Snapshot() => [.. Enumerate().Select(p => Describe(p.ProcessId, p.ParentId, p.ExeName))];

    /// <summary>
    /// The live entry for one process ID, with its parent as Windows records it now, or
    /// null when no such process runs. Parent and child must still be proven by start
    /// order (REQ-CALL-11); that is the walker's job.
    /// </summary>
    public static ProcessEntry? Find(int processId)
    {
        foreach (var process in Enumerate())
        {
            if (process.ProcessId == processId) return Describe(process.ProcessId, process.ParentId, process.ExeName);
        }

        return null;
    }

    /// <summary>
    /// The logon session the user sits at.
    /// </summary>
    public static int ConsoleSessionId => (int)WTSGetActiveConsoleSessionId();

    /// <summary>
    /// Toolhelp's view: IDs, parent IDs and file names only, which needs no process handle.
    /// </summary>
    private static List<(int ProcessId, int ParentId, string ExeName)> Enumerate()
    {
        var result = new List<(int, int, string)>();
        var snapshot = CreateToolhelp32Snapshot(SnapProcess, 0);
        if (snapshot == InvalidHandle) return result;
        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)sizeof(PROCESSENTRY32W) };
            if (!Process32FirstW(snapshot, &entry)) return result;
            do
            {
                result.Add(((int)entry.th32ProcessID, (int)entry.th32ParentProcessID, new string(entry.szExeFile)));
            }
            while (Process32NextW(snapshot, &entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return result;
    }

    /// <summary>
    /// A process the broker may not open (a protected one) keeps creation time 0 and its
    /// bare file name, so it can never be proven anyone's parent.
    /// </summary>
    private static ProcessEntry Describe(int processId, int parentId, string exeName)
    {
        var session = ProcessIdToSessionId((uint)processId, out var processSession) ? (int)processSession : -1;
        var (created, path) = Open(processId);
        return new ProcessEntry(processId, parentId, created, path ?? exeName, session);
    }

    private static (long CreateTime, string? Path) Open(int processId)
    {
        var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId);
        if (process == 0) return (0, null);
        try
        {
            var created = GetProcessTimes(process, out var creation, out _, out _, out _) ? creation : 0;
            var buffer = stackalloc char[1024];
            var length = 1024u;
            var path = QueryFullProcessImageNameW(process, 0, buffer, &length) ? new string(buffer, 0, (int)length) : null;
            return (created, path);
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private const uint SnapProcess = 0x2, ProcessQueryLimitedInformation = 0x1000;
    private static readonly nint InvalidHandle = -1;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial nint CreateToolhelp32Snapshot(uint flags, uint processId);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool Process32FirstW(nint snapshot, PROCESSENTRY32W* entry);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool Process32NextW(nint snapshot, PROCESSENTRY32W* entry);
    [LibraryImport("kernel32.dll")] private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetProcessTimes(nint process, out long creation, out long exit, out long kernel, out long user);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool QueryFullProcessImageNameW(nint process, uint flags, char* name, uint* length);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint handle);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);
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
