// The second question this spike answers (spec section 17, "Process events for the
// service account"): can the service account receive Microsoft-Windows-Kernel-Process
// events? An unelevated member of Performance Log Users can start a session but is
// refused when enabling this provider, so the rounds add Performance Log Users and then
// a provider grant through EventAccessControl, and log what each one changes.
//
// Throwaway: the ETW plumbing is a trimmed copy of the broker's, deliberately not shared.

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OpWarden.SpikeSessionSpawn;

internal static unsafe partial class Program
{
    private const string EtwSessionName = "OpWardenSpike-ProcessEvents";
    private static readonly Guid KernelProcess = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
    private static int _processStarts;

    /// <summary>
    /// Starts a session, enables Kernel-Process, starts a child process, and counts the
    /// ProcessStart events that arrive within five seconds.
    /// </summary>
    private static void EtwExperiment()
    {
        var properties = EtwProperties();
        try
        {
            ulong session;
            var status = StartTraceW(&session, EtwSessionName, properties);
            if (status == 183)
            {
                ControlTraceW(0, EtwSessionName, properties, 1);
                NativeMemory.Free(properties);
                properties = EtwProperties();
                status = StartTraceW(&session, EtwSessionName, properties);
            }

            Log($"etw StartTrace: {Describe(status)}");
            if (status != 0) return;

            try
            {
                var provider = KernelProcess;
                status = EnableTraceEx2(session, &provider, 1, 4, 0x10, 0, 0, null);
                Log($"etw EnableTraceEx2 Kernel-Process: {Describe(status)}");
                if (status != 0) return;

                fixed (char* name = EtwSessionName)
                {
                    var logfile = new EVENT_TRACE_LOGFILEW { LoggerName = name, ProcessTraceMode = 0x100 | 0x10000000, EventRecordCallback = &OnEtwEvent };
                    var trace = OpenTraceW(&logfile);
                    if (trace == ulong.MaxValue)
                    {
                        Log($"etw OpenTrace FAILED: {LastError()}");
                        return;
                    }

                    var consumer = new Thread(() => { var t = trace; _ = ProcessTrace(&t, 1, null, null); }) { IsBackground = true };
                    consumer.Start();
                    Thread.Sleep(1000);
                    using (var child = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c exit 0") { UseShellExecute = false, CreateNoWindow = true }))
                    {
                        child?.WaitForExit();
                    }

                    Thread.Sleep(4000);
                    Log($"etw ProcessStart events received in 5 s: {Volatile.Read(ref _processStarts)}");
                    ControlTraceW(session, null, properties, 1);
                    consumer.Join(TimeSpan.FromSeconds(5));
                    _ = CloseTrace(trace);
                    session = 0;
                }
            }
            finally
            {
                if (session != 0) ControlTraceW(session, null, properties, 1);
            }
        }
        catch (Exception e)
        {
            Log($"etw experiment threw: {e}");
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnEtwEvent(EVENT_RECORD* record)
    {
        if (record->EventHeader.ProviderId == KernelProcess && record->EventHeader.EventDescriptor.Id == 1) Interlocked.Increment(ref _processStarts);
    }

    /// <summary>
    /// Grants the account the right to enable Kernel-Process in a session (elevated).
    /// </summary>
    private static int GrantEtw(string account)
    {
        var sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var provider = KernelProcess;
        uint status;
        fixed (byte* sidPointer = bytes) status = EventAccessControl(&provider, EventSecurityAddDacl, sidPointer, TracelogGuidEnable, 1);
        var line = $"EventAccessControl grant enable on Kernel-Process to {account} ({sid.Value}): {Describe(status)}";
        Log(line);
        Console.WriteLine(line);
        return status == 0 ? 0 : 1;
    }

    private static string Describe(uint status) => status == 0 ? "ok" : $"FAILED {status} ({new Win32Exception((int)status).Message})";

    private static EVENT_TRACE_PROPERTIES* EtwProperties()
    {
        var size = (uint)(sizeof(EVENT_TRACE_PROPERTIES) + 2048 * sizeof(char));
        var p = (EVENT_TRACE_PROPERTIES*)NativeMemory.AllocZeroed(size);
        p->Wnode.BufferSize = size;
        p->Wnode.Flags = 0x00020000;
        p->Wnode.ClientContext = 1;
        p->LogFileMode = 0x100;
        p->BufferSize = 64;
        p->MinimumBuffers = 8;
        p->FlushTimer = 1;
        p->LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
        return p;
    }

    private const uint EventSecurityAddDacl = 2, TracelogGuidEnable = 0x80;

    [StructLayout(LayoutKind.Sequential)] private struct WNODE_HEADER { public uint BufferSize, ProviderId; public ulong HistoricalContext; public long TimeStamp; public Guid Guid; public uint ClientContext, Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct EVENT_TRACE_PROPERTIES { public WNODE_HEADER Wnode; public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags; public int AgeLimit; public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost; public nint LoggerThreadId; public uint LogFileNameOffset, LoggerNameOffset; }
    [StructLayout(LayoutKind.Explicit, Size = 448)] private struct EVENT_TRACE_LOGFILEW { [FieldOffset(8)] public char* LoggerName; [FieldOffset(28)] public uint ProcessTraceMode; [FieldOffset(424)] public delegate* unmanaged<EVENT_RECORD*, void> EventRecordCallback; }
    [StructLayout(LayoutKind.Sequential)] private struct EVENT_DESCRIPTOR { public ushort Id; public byte Version, Channel, Level, Opcode; public ushort Task; public ulong Keyword; }
    [StructLayout(LayoutKind.Sequential)] private struct EVENT_HEADER { public ushort Size, HeaderType, Flags, EventProperty; public uint ThreadId, ProcessId; public long TimeStamp; public Guid ProviderId; public EVENT_DESCRIPTOR EventDescriptor; public ulong ProcessorTime; public Guid ActivityId; }
    [StructLayout(LayoutKind.Sequential)] private struct EVENT_RECORD { public EVENT_HEADER EventHeader; public uint BufferContext; public ushort ExtendedDataCount, UserDataLength; public nint ExtendedData, UserData, UserContext; }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial uint StartTraceW(ulong* session, string name, EVENT_TRACE_PROPERTIES* properties);
    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial uint ControlTraceW(ulong session, string? name, EVENT_TRACE_PROPERTIES* properties, uint control);
    [LibraryImport("advapi32.dll")] private static partial uint EnableTraceEx2(ulong session, Guid* provider, uint control, byte level, ulong matchAny, ulong matchAll, uint timeout, void* parameters);
    [LibraryImport("advapi32.dll", SetLastError = true)] private static partial ulong OpenTraceW(EVENT_TRACE_LOGFILEW* logfile);
    [LibraryImport("advapi32.dll")] private static partial uint ProcessTrace(ulong* handles, uint count, void* start, void* end);
    [LibraryImport("advapi32.dll")] private static partial uint CloseTrace(ulong trace);
    [LibraryImport("advapi32.dll")] private static partial uint EventAccessControl(Guid* provider, uint operation, void* sid, uint rights, byte allow);
}
