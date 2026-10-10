using System.Runtime.InteropServices;

namespace OpWarden.Broker;

/// <summary>
/// Runs the broker under the service control manager (REQ-TRUST-1), through the Win32
/// service API directly: the hosting package would pull a dependency injection stack
/// into a NativeAOT binary for the sake of three calls.
/// </summary>
/// <remarks>
/// <code>
///   main thread:  Run ─► StartServiceCtrlDispatcher (blocks until the service stops)
///   SCM thread:   ServiceMain ─► start the broker ─► RUNNING ─► wait for stop ─► STOPPED
///   SCM thread:   Handler(STOP | SHUTDOWN) ─► signal the wait
/// </code>
/// </remarks>
internal static unsafe partial class ServiceHost
{
    public const string ServiceName = "OpWarden";

    private static readonly ManualResetEventSlim StopRequested = new();
    private static Func<IAsyncDisposable>? _start;
    private static Action<string>? _log;
    private static nint _statusHandle;
    private static int _exitCode;

    /// <summary>
    /// Hands the process to the service control manager and returns when the service has
    /// stopped. Returns the broker's exit code, or the Win32 error when the process was
    /// not started by the service control manager.
    /// </summary>
    public static int Run(Func<IAsyncDisposable> start, Action<string> log)
    {
        (_start, _log) = (start, log);
        fixed (char* name = ServiceName)
        {
            var table = stackalloc SERVICE_TABLE_ENTRYW[2];
            table[0] = new SERVICE_TABLE_ENTRYW { ServiceName = name, ServiceProc = &ServiceMain };
            table[1] = default;
            if (!StartServiceCtrlDispatcherW(table)) return Marshal.GetLastPInvokeError();
        }

        return _exitCode;
    }

    [UnmanagedCallersOnly]
    private static void ServiceMain(uint argc, char** argv)
    {
        // Nothing may escape a native callback: an exception here would end the process
        // without telling the service control manager anything.
        try
        {
            _statusHandle = RegisterServiceCtrlHandlerExW(argv[0], &Handler, 0);
            if (_statusHandle == 0)
            {
                _log!($"RegisterServiceCtrlHandlerEx failed ({Marshal.GetLastPInvokeError()}).");
                _exitCode = 1;
                return;
            }

            Report(ServiceStartPending);
            IAsyncDisposable broker;
            try
            {
                broker = _start!();
            }
            catch (Exception e)
            {
                _log!($"The broker failed to start: {e}");
                _exitCode = 1;
                Report(ServiceStopped, serviceExitCode: 1);
                return;
            }

            Report(ServiceRunning);
            StopRequested.Wait();
            Report(ServiceStopPending);

            // The SCM thread has no synchronization context and nothing to return to
            // until the broker is down, so blocking here is the point.
            broker.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Report(ServiceStopped);
        }
        catch (Exception e)
        {
            _log?.Invoke($"The service host failed: {e}");
            _exitCode = 1;
            Report(ServiceStopped, serviceExitCode: 1);
        }
    }

    [UnmanagedCallersOnly]
    private static uint Handler(uint control, uint eventType, nint eventData, nint context)
    {
        switch (control)
        {
            case ServiceControlStop or ServiceControlShutdown:
                StopRequested.Set();
                return NoError;
            case ServiceControlInterrogate:
                return NoError;
            default:
                return ErrorCallNotImplemented;
        }
    }

    private static void Report(uint state, uint serviceExitCode = 0)
    {
        if (_statusHandle == 0) return;
        var status = new SERVICE_STATUS
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = state == ServiceRunning ? ServiceAcceptStop | ServiceAcceptShutdown : 0,
            Win32ExitCode = serviceExitCode == 0 ? NoError : ErrorServiceSpecificError,
            ServiceSpecificExitCode = serviceExitCode,
            WaitHint = state is ServiceStartPending or ServiceStopPending ? 30_000u : 0,
        };
        if (!SetServiceStatus(_statusHandle, &status)) _log?.Invoke($"SetServiceStatus({state}) failed ({Marshal.GetLastPInvokeError()}).");
    }

    private const uint ServiceWin32OwnProcess = 0x10;
    private const uint ServiceStopped = 1, ServiceStartPending = 2, ServiceStopPending = 3, ServiceRunning = 4;
    private const uint ServiceAcceptStop = 0x1, ServiceAcceptShutdown = 0x4;
    private const uint ServiceControlStop = 1, ServiceControlInterrogate = 4, ServiceControlShutdown = 5;
    private const uint NoError = 0, ErrorCallNotImplemented = 120, ErrorServiceSpecificError = 1066;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_TABLE_ENTRYW
    {
        public char* ServiceName;
        public delegate* unmanaged<uint, char**, void> ServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool StartServiceCtrlDispatcherW(SERVICE_TABLE_ENTRYW* table);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial nint RegisterServiceCtrlHandlerExW(char* serviceName, delegate* unmanaged<uint, uint, nint, nint, uint> handler, nint context);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetServiceStatus(nint statusHandle, SERVICE_STATUS* status);
}
