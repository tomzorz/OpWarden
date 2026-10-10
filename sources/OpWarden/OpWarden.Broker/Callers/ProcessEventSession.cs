using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OpWarden.Broker.Callers;

/// <summary>
/// A real-time ETW session on <c>Microsoft-Windows-Kernel-Process</c> that records every
/// process start and exit into the process map (REQ-CALL-1, REQ-CALL-2).
/// </summary>
/// <remarks>
/// Raw ETW through P/Invoke, no package (decided 2026-10-04): StartTrace and EnableTraceEx2
/// set the session up, OpenTrace and a blocking ProcessTrace on a thread of its own deliver
/// events to <see cref="OnEvent"/>, and ControlTrace stops it.
///
/// Starting a session needs an administrator, a member of Performance Log Users, or one of
/// the built-in service accounts, and enabling Kernel-Process needs a grant on the provider
/// besides (section 5, event-access decision). Without either, the broker reports it
/// (REQ-CALL-20) and resolves callers by the live walk alone.
///
/// The session is named per account, so a console broker or a test run never stops the
/// installed service's session when it clears a session a dead broker left behind.
///
/// The event handler only decodes and records (REQ-CALL-3); buffers are sized generously
/// because a slow or starved consumer is how ETW loses events.
/// </remarks>
public sealed unsafe partial class ProcessEventSession : IDisposable
{
    public static readonly string SessionName = $"OpWarden-ProcessMap-{CurrentAccount()}";

    private static ProcessEventSession? _active;

    private readonly ProcessMap _map;
    private readonly Thread _consumer;
    private ulong _session;
    private ulong _trace;
    private long _undecodable;

    private ProcessEventSession(ProcessMap map, ulong session, ulong trace)
    {
        (_map, _session, _trace) = (map, session, trace);
        _consumer = new Thread(Consume) { IsBackground = true, Name = "OpWarden ETW consumer" };
    }

    /// <summary>
    /// Events whose payload did not decode: an unknown event version, or a malformed one.
    /// </summary>
    public long Undecodable => Interlocked.Read(ref _undecodable);

    /// <summary>
    /// What ProcessTrace returned when the consumer thread ended: 0 after a clean stop.
    /// </summary>
    public uint? ConsumerExit { get; private set; }

    /// <summary>
    /// Starts the session, or returns null with the reason when Windows refuses it.
    /// </summary>
    public static ProcessEventSession? TryStart(ProcessMap map, out string? failure)
    {
        if (_active is not null) throw new InvalidOperationException("Only one process-event session runs per broker.");

        var properties = Properties();
        try
        {
            ulong session;
            var status = StartTraceW(&session, SessionName, properties);
            if (status == ErrorAlreadyExists)
            {
                // A broker that died left its session behind; stop it and start afresh.
                StopByName();
                NativeMemory.Free(properties);
                properties = Properties();
                status = StartTraceW(&session, SessionName, properties);
            }

            if (status != 0)
            {
                failure = status == ErrorAccessDenied
                    ? "Windows refused the process-event session (access denied): the broker needs to run as an administrator, a service account, or a member of Performance Log Users. Callers resolve by the live process walk alone, which cannot see through MSYS2 shells."
                    : $"Windows refused the process-event session ({new Win32Exception((int)status).Message}). Callers resolve by the live process walk alone.";
                return null;
            }

            var provider = ProcessEventDecoder.Provider;
            status = EnableTraceEx2(session, &provider, EventControlCodeEnableProvider, TraceLevelInformation, KeywordProcess, 0, 0, null);
            if (status != 0)
            {
                ControlTraceW(session, null, properties, EventTraceControlStop);
                failure = $"Windows refused to enable process events in the session ({new Win32Exception((int)status).Message}).";
                return null;
            }

            fixed (char* name = SessionName)
            {
                var logfile = new EVENT_TRACE_LOGFILEW
                {
                    LoggerName = name,
                    ProcessTraceMode = ProcessTraceModeRealTime | ProcessTraceModeEventRecord,
                    EventRecordCallback = &OnEvent,
                };
                var trace = OpenTraceW(&logfile);
                if (trace == InvalidProcessTraceHandle)
                {
                    var error = Marshal.GetLastPInvokeError();
                    ControlTraceW(session, null, properties, EventTraceControlStop);
                    failure = $"Windows refused to open the process-event session for reading ({new Win32Exception(error).Message}).";
                    return null;
                }

                var started = new ProcessEventSession(map, session, trace);
                _active = started;
                started._consumer.Start();
                failure = null;
                return started;
            }
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    /// <summary>
    /// Events ETW dropped since the session started: each one a caller that may resolve as
    /// unknown (spec section 16).
    /// </summary>
    public uint EventsLost()
    {
        var properties = Properties();
        try
        {
            return ControlTraceW(_session, null, properties, EventTraceControlQuery) == 0 ? properties->EventsLost + properties->RealTimeBuffersLost : 0;
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    /// <summary>
    /// Hands every buffered event to the consumer now, rather than at the next flush timer:
    /// a walk waiting for a parent's events need not sit out the second (REQ-CALL-26).
    /// </summary>
    public void Flush()
    {
        var properties = Properties();
        try
        {
            _ = ControlTraceW(_session, null, properties, EventTraceControlFlush);
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    public void Dispose()
    {
        if (_session == 0) return;
        var properties = Properties();
        try
        {
            ControlTraceW(_session, null, properties, EventTraceControlStop);
        }
        finally
        {
            NativeMemory.Free(properties);
        }

        _consumer.Join(TimeSpan.FromSeconds(5));
        _ = CloseTrace(_trace);
        _session = 0;
        _active = null;
    }

    private void Consume()
    {
        var trace = _trace;
        ConsumerExit = ProcessTrace(&trace, 1, null, null);
    }

    [UnmanagedCallersOnly]
    private static void OnEvent(EVENT_RECORD* record)
    {
        if (_active is not { } session || record->EventHeader.ProviderId != ProcessEventDecoder.Provider) return;

        try
        {
            var payload = new ReadOnlySpan<byte>((void*)record->UserData, record->UserDataLength);
            var version = record->EventHeader.EventDescriptor.Version;
            switch (record->EventHeader.EventDescriptor.Id)
            {
                case ProcessEventDecoder.StartEventId:
                    if (ProcessEventDecoder.DecodeStart(version, payload) is { } entry) session._map.Record(entry);
                    else Interlocked.Increment(ref session._undecodable);
                    break;
                case ProcessEventDecoder.StopEventId:
                    if (ProcessEventDecoder.DecodeStop(version, payload) is { } exit) session._map.RecordExit(exit);
                    else Interlocked.Increment(ref session._undecodable);
                    break;
            }
        }
        catch (Exception)
        {
            // Nothing may escape into ETW's thread; the event counts as undecodable.
            Interlocked.Increment(ref session._undecodable);
        }
    }

    private static string CurrentAccount()
    {
        using var self = System.Security.Principal.WindowsIdentity.GetCurrent();
        return self.User!.Value;
    }

    private static void StopByName()
    {
        var properties = Properties();
        try
        {
            ControlTraceW(0, SessionName, properties, EventTraceControlStop);
        }
        finally
        {
            NativeMemory.Free(properties);
        }
    }

    /// <summary>
    /// EVENT_TRACE_PROPERTIES with room for the session name behind it, as StartTrace and
    /// ControlTrace require. The caller frees it with <c>NativeMemory.Free</c>.
    /// </summary>
    private static EVENT_TRACE_PROPERTIES* Properties()
    {
        var size = (uint)(sizeof(EVENT_TRACE_PROPERTIES) + (SessionName.Length + 1) * sizeof(char) + 2 * 1024 * sizeof(char));
        var properties = (EVENT_TRACE_PROPERTIES*)NativeMemory.AllocZeroed(size);
        properties->Wnode.BufferSize = size;
        properties->Wnode.Flags = WnodeFlagTracedGuid;
        properties->Wnode.ClientContext = 1; // query performance counter timestamps
        properties->LogFileMode = EventTraceRealTimeMode;
        properties->BufferSize = 64; // KB
        properties->MinimumBuffers = 16;
        properties->MaximumBuffers = 64;
        properties->FlushTimer = 1;
        properties->LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
        properties->LogFileNameOffset = 0;
        return properties;
    }

    private const uint ErrorAlreadyExists = 183, ErrorAccessDenied = 5;
    private const uint WnodeFlagTracedGuid = 0x00020000, EventTraceRealTimeMode = 0x00000100;
    private const uint EventTraceControlQuery = 0, EventTraceControlStop = 1, EventTraceControlFlush = 3, EventControlCodeEnableProvider = 1;
    private const byte TraceLevelInformation = 4;
    private const ulong KeywordProcess = 0x10; // WINEVENT_KEYWORD_PROCESS
    private const uint ProcessTraceModeRealTime = 0x00000100, ProcessTraceModeEventRecord = 0x10000000;
    private const ulong InvalidProcessTraceHandle = ulong.MaxValue;

    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER
    {
        public uint BufferSize, ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext, Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
        public nint LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }

    // EVENT_TRACE_LOGFILEW is 448 bytes on x64; only these members matter here, at their
    // documented offsets, and the rest stays zero.
    [StructLayout(LayoutKind.Explicit, Size = 448)]
    private struct EVENT_TRACE_LOGFILEW
    {
        [FieldOffset(8)] public char* LoggerName;
        [FieldOffset(28)] public uint ProcessTraceMode;
        [FieldOffset(424)] public delegate* unmanaged<EVENT_RECORD*, void> EventRecordCallback;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_DESCRIPTOR
    {
        public ushort Id;
        public byte Version, Channel, Level, Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_HEADER
    {
        public ushort Size, HeaderType, Flags, EventProperty;
        public uint ThreadId, ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public uint BufferContext;
        public ushort ExtendedDataCount, UserDataLength;
        public nint ExtendedData, UserData, UserContext;
    }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial uint StartTraceW(ulong* session, string name, EVENT_TRACE_PROPERTIES* properties);
    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial uint ControlTraceW(ulong session, string? name, EVENT_TRACE_PROPERTIES* properties, uint control);
    [LibraryImport("advapi32.dll")] private static partial uint EnableTraceEx2(ulong session, Guid* provider, uint control, byte level, ulong matchAny, ulong matchAll, uint timeout, void* parameters);
    [LibraryImport("advapi32.dll", SetLastError = true)] private static partial ulong OpenTraceW(EVENT_TRACE_LOGFILEW* logfile);
    [LibraryImport("advapi32.dll")] private static partial uint ProcessTrace(ulong* handles, uint count, void* start, void* end);
    [LibraryImport("advapi32.dll")] private static partial uint CloseTrace(ulong trace);
}
