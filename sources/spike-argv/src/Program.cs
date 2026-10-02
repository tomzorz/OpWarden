// OpWarden spike: argv-only passthrough logger.
//
// This is NOT the shim. There is no broker, no rule store, no gating. It runs
// the real op CLI with the arguments it was handed, forwards stdio and the exit
// code, and writes one JSON line per invocation describing the argv and the
// process ancestry.
//
// Answering, for one OpenTofu run:
//   1. which op CLI subcommands the run issues, with what flags, how often
//   2. whether secrets are addressed by name, by UUID, or both
//   3. what the ancestor chain looks like (validates SPEC section 5)
//   4. whether the run reaches a PATH-resolved op.exe at all
//
// Deliberately NOT captured: stdout (that is the secret value), stdin, and the
// environment. See REQ-CACHE-1 and REQ-AUD-4/5 in SPEC.md.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace OpWarden.SpikeArgv;

internal static partial class Program
{
    // The real op CLI, named by an absolute path and NEVER resolved through
    // PATH: this executable is itself named op.exe, so PATH resolution would
    // recurse into itself until the machine gives up.
    //
    // There is deliberately no default. The genuine op CLI lives somewhere
    // different on every machine, and a wrong guess would silently trace nothing.
    private const string RealOpVariable = "OPWARDEN_SPIKE_REAL_OP";

    private const string LogPathVariable = "OPWARDEN_SPIKE_LOG";

    private const int MaxAncestorDepth = 12; // matches REQ-CALL-1

    private static int Main(string[] args)
    {
        var startedUtc = DateTime.UtcNow;
        var stopwatch = Stopwatch.StartNew();

        var realOp = Environment.GetEnvironmentVariable(RealOpVariable);
        if (string.IsNullOrWhiteSpace(realOp))
        {
            Console.Error.WriteLine($"opwarden-spike: set {RealOpVariable} to the absolute path of the genuine op CLI.");
            return 127;
        }

        var logPath = Environment.GetEnvironmentVariable(LogPathVariable)
                      ?? Path.Combine(AppContext.BaseDirectory, "op-argv.jsonl");

        var selfPath = Environment.ProcessPath;
        if (selfPath is not null && PathsEqual(selfPath, realOp))
        {
            Console.Error.WriteLine($"opwarden-spike: refusing to exec myself ({realOp}). Point {RealOpVariable} at the genuine op CLI.");
            return 127;
        }

        if (!File.Exists(realOp))
        {
            Console.Error.WriteLine($"opwarden-spike: real op CLI not found at {realOp}. Check {RealOpVariable}.");
            return 127;
        }

        // Snapshot the ancestry before the child runs; the caller might exit
        // while op is still working.
        var procTable = SnapshotProcesses();
        var walk = SafeWalkAncestors(procTable, Environment.ProcessId);
        var console = SafeConsoleProcesses(procTable);
        var consoleWalks = console.Select(c => (c, SafeWalkAncestors(procTable, c.Pid))).ToList();

        int? exitCode = null;
        try
        {
            exitCode = RunPassthrough(realOp, args);
            return exitCode.Value;
        }
        finally
        {
            stopwatch.Stop();
            TryLog(logPath, startedUtc, args, walk, console, consoleWalks, exitCode, stopwatch.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// Runs the real op CLI with stdio inherited (not redirected), so the
    /// desktop app's biometric flow behaves exactly as if this logger were not
    /// on PATH. Returns the child's exit code (REQ-SHIM-4 semantics).
    /// </summary>
    private static int RunPassthrough(string realOp, string[] args)
    {
        var psi = new ProcessStartInfo(realOp)
        {
            UseShellExecute = false,
            // No RedirectStandard*: the child inherits our console handles
            // verbatim, which keeps TTY detection and interactive prompts intact.
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var child = Process.Start(psi);
        if (child is null)
        {
            Console.Error.WriteLine("opwarden-spike: failed to start the real op CLI.");
            return 127;
        }

        // Ctrl+C reaches the whole console group anyway. Don't let the logger
        // die first and orphan the child's exit code.
        Console.CancelKeyPress += (_, e) => e.Cancel = true;

        child.WaitForExit();
        return child.ExitCode;
    }

    private static void TryLog(
        string logPath,
        DateTime startedUtc,
        string[] args,
        Walk walk,
        List<ConsoleProc> console,
        List<(ConsoleProc Proc, Walk Walk)> consoleWalks,
        int? exitCode,
        long elapsedMs)
    {
        try
        {
            var line = BuildJsonLine(startedUtc, args, walk, console, consoleWalks, exitCode, elapsedMs);
            AppendLine(logPath, line);
        }
        catch (Exception ex)
        {
            // Logging must never break the run being traced.
            Console.Error.WriteLine($"opwarden-spike: log write failed: {ex.Message}");
        }
    }

    private static string BuildJsonLine(
        DateTime startedUtc,
        string[] args,
        Walk walk,
        List<ConsoleProc> console,
        List<(ConsoleProc Proc, Walk Walk)> consoleWalks,
        int? exitCode,
        long elapsedMs)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            w.WriteString("ts", startedUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ"));
            w.WriteNumber("pid", Environment.ProcessId);
            w.WriteString("cwd", Environment.CurrentDirectory);

            w.WriteStartArray("argv");
            foreach (var arg in args) w.WriteStringValue(Redact(arg));
            w.WriteEndArray();

            if (exitCode.HasValue) w.WriteNumber("exit", exitCode.Value);
            else w.WriteNull("exit");

            w.WriteNumber("durationMs", elapsedMs);

            w.WriteString("walkStop", walk.StopReason);
            if (walk.StopPid.HasValue) w.WriteNumber("walkStopPid", walk.StopPid.Value);

            // Follow-up spike: does console attachment identify the caller where
            // the parent walk cannot? See SPEC.md section 17.
            w.WriteStartArray("console");
            foreach (var c in console)
            {
                w.WriteStartObject();
                w.WriteNumber("pid", c.Pid);
                w.WriteString("name", c.Name);
                w.WriteEndObject();
            }
            w.WriteEndArray();

            w.WriteStartArray("consoleWalks");
            foreach (var (proc, cw) in consoleWalks)
            {
                w.WriteStartObject();
                w.WriteNumber("pid", proc.Pid);
                w.WriteString("name", proc.Name);
                w.WriteString("stop", cw.StopReason);
                w.WriteStartArray("chain");
                foreach (var a in cw.Ancestors) w.WriteStringValue($"{a.Name}({a.Pid})");
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();

            w.WriteStartArray("ancestors");
            foreach (var a in walk.Ancestors)
            {
                w.WriteStartObject();
                w.WriteNumber("pid", a.Pid);
                w.WriteString("name", a.Name);
                if (a.Path is not null) w.WriteString("path", a.Path);
                if (a.StartedUtc.HasValue) w.WriteString("started", a.StartedUtc.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ"));
                if (a.StartOrderOk.HasValue) w.WriteBoolean("startOrderOk", a.StartOrderOk.Value);
                w.WriteEndObject();
            }
            w.WriteEndArray();

            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Redacts the value half of assignment arguments, per REQ-AUD-5. Secret
    /// references (op://vault/item/field) carry no '=' and survive intact,
    /// which is the point: the spike needs them for the name-vs-UUID question.
    /// </summary>
    private static string Redact(string arg)
    {
        var eq = arg.IndexOf('=');
        if (eq <= 0) return arg;

        var head = arg[..eq];

        // Bare `field=value`: always an assignment, always a possible secret.
        if (!arg.StartsWith('-')) return head + "=<redacted>";

        // Flags: keep the value (`--format=json` is exactly the data we want)
        // unless the flag name smells like it carries a credential.
        string[] sensitive = ["session", "token", "password", "secret", "credential"];
        foreach (var s in sensitive)
        {
            if (head.Contains(s, StringComparison.OrdinalIgnoreCase)) return head + "=<redacted>";
        }

        return arg;
    }

    private static void AppendLine(string logPath, string line)
    {
        var dir = Path.GetDirectoryName(logPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // Concurrent op invocations are expected (tofu parallelises), so serialise
        // appends across processes.
        using var mutex = new Mutex(false, @"Global\OpWardenSpikeArgvLog");
        var held = false;
        try
        {
            try { held = mutex.WaitOne(TimeSpan.FromSeconds(5)); }
            catch (AbandonedMutexException) { held = true; }

            using var fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            var bytes = Encoding.UTF8.GetBytes(line + "\n");
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
        }
        finally
        {
            if (held) mutex.ReleaseMutex();
        }
    }

    // ---- process ancestry -------------------------------------------------

    private sealed record Ancestor(int Pid, string Name, string? Path, DateTime? StartedUtc, bool? StartOrderOk);

    /// <summary>
    /// The walk result. StopReason and StopPid say WHY the chain ended, which is
    /// the difference between "reached the shell" and "gave up", and therefore
    /// between an identified caller and REQ-CALL-8's `unknown`.
    /// </summary>
    private sealed record Walk(List<Ancestor> Ancestors, string StopReason, int? StopPid);

    private static Walk SafeWalkAncestors(Dictionary<int, ProcEntry> table, int startPid)
    {
        try { return WalkAncestors(table, startPid); }
        catch (Exception ex)
        {
            return new Walk([], $"walk-threw:{ex.GetType().Name}", null);
        }
    }

    private static Walk WalkAncestors(Dictionary<int, ProcEntry> table, int startPid)
    {
        var result = new List<Ancestor>();

        var childPid = startPid;
        var childStart = TryStartTime(childPid);
        var seen = new HashSet<int> { childPid };

        for (var depth = 0; depth < MaxAncestorDepth; depth++)
        {
            if (!table.TryGetValue(childPid, out var entry))
                return new Walk(result, "child-not-in-snapshot", childPid);

            var parentPid = entry.ParentPid;
            if (parentPid == 0)
                return new Walk(result, "parent-pid-zero", null);
            if (!seen.Add(parentPid))
                return new Walk(result, "cycle", parentPid);

            // The interesting failure: the parent pid is recorded but the process
            // is already gone, so the chain cannot be proven any further.
            if (!table.TryGetValue(parentPid, out var parent))
                return new Walk(result, "parent-exited", parentPid);

            var parentStart = TryStartTime(parentPid);

            // REQ-CALL-2: a recycled pid can otherwise attach a false ancestor.
            bool? startOrderOk = (childStart.HasValue && parentStart.HasValue)
                ? parentStart.Value <= childStart.Value
                : null;

            result.Add(new Ancestor(parentPid, parent.Name, TryMainModulePath(parentPid), parentStart, startOrderOk));

            childPid = parentPid;
            childStart = parentStart;
        }

        return new Walk(result, "depth-exhausted", null);
    }

    private static DateTime? TryStartTime(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.StartTime.ToUniversalTime();
        }
        catch { return null; }
    }

    private static string? TryMainModulePath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch { return null; } // protected or cross-bitness process; name only
    }

    private readonly record struct ProcEntry(int ParentPid, string Name);

    private static unsafe Dictionary<int, ProcEntry> SnapshotProcesses()
    {
        var table = new Dictionary<int, ProcEntry>();

        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return table;

        try
        {
            var entry = default(PROCESSENTRY32W);
            entry.dwSize = (uint)sizeof(PROCESSENTRY32W);

            if (!Process32FirstW(snapshot, &entry)) return table;

            do
            {
                var name = new string(entry.szExeFile);
                var nul = name.IndexOf('\0');
                if (nul >= 0) name = name[..nul];

                table[(int)entry.th32ProcessID] = new ProcEntry((int)entry.th32ParentProcessID, name);
            }
            while (Process32NextW(snapshot, &entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return table;
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool Process32FirstW(IntPtr hSnapshot, PROCESSENTRY32W* lppe);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool Process32NextW(IntPtr hSnapshot, PROCESSENTRY32W* lppe);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr hObject);

    // ---- console attribution ----------------------------------------------

    private readonly record struct ConsoleProc(int Pid, string Name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetConsoleProcessList(uint* lpdwProcessList, uint dwProcessCount);

    /// <summary>
    /// Every process attached to this process's console. Unlike the parent walk
    /// this does not need a walkable chain, but it identifies who shares the
    /// terminal rather than who invoked us, and it returns nothing at all for a
    /// caller with no console.
    /// </summary>
    private static unsafe List<ConsoleProc> SafeConsoleProcesses(Dictionary<int, ProcEntry> table)
    {
        var result = new List<ConsoleProc>();
        try
        {
            // Probe for the count, then take the real list. The count can grow
            // between the two calls, so loop rather than trust the first answer.
            for (var capacity = 16u; capacity <= 1024u; capacity *= 2)
            {
                var buffer = new uint[capacity];
                uint count;
                fixed (uint* p = buffer) count = GetConsoleProcessList(p, capacity);

                if (count == 0) return result; // no console attached
                if (count > capacity) continue;

                for (var i = 0; i < count; i++)
                {
                    var pid = (int)buffer[i];
                    var name = table.TryGetValue(pid, out var e) ? e.Name : "<gone>";
                    result.Add(new ConsoleProc(pid, name));
                }
                return result;
            }
        }
        catch { /* diagnostic only, never break the traced run */ }

        return result;
    }

    private static bool PathsEqual(string a, string b)
    {
        try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
}
