// OpWarden spike: can a service under a virtual account start a process in the
// interactive session? (REQ-TRUST-3)
//
// The question is whether NT SERVICE\<name>, once granted SeTcbPrivilege through
// LsaAddAccountRights, can call WTSQueryUserToken and CreateProcessAsUser. Without
// the grant the call should fail with ERROR_PRIVILEGE_NOT_HELD (1314); with it, the
// child should start in the console session as the signed-in user.
//
// Modes:
//   service          run as the service (what the SCM starts)
//   grant <account>  add SeTcbPrivilege to the account (elevated)
//   revoke <account> remove it again (elevated)
//   grant-etw <account>  let the account enable Kernel-Process events (elevated)
//   marker           the child: record who and where it is, then exit
//
// Everything is written to spike.log beside the executable. Raw Win32, no packages:
// the service plumbing is about sixty lines and a package would be a dependency
// conversation for a throwaway.

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OpWarden.SpikeSessionSpawn;

internal static unsafe partial class Program
{
    private const string ServiceName = "OpWardenSpike";

    private static string LogPath => Path.Combine(AppContext.BaseDirectory, "spike.log");

    private static int Main(string[] args)
    {
        try
        {
            return args.FirstOrDefault() switch
            {
                "service" => RunService(),
                "grant" when args.Length == 2 => ChangeRight(args[1], add: true),
                "revoke" when args.Length == 2 => ChangeRight(args[1], add: false),
                "grant-etw" when args.Length == 2 => GrantEtw(args[1]),
                "marker" => Marker(),
                _ => Usage(),
            };
        }
        catch (Exception e)
        {
            Log($"fatal: {e}");
            Console.Error.WriteLine(e);
            return 1;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: opwarden-spike-spawn service | grant <account> | revoke <account> | grant-etw <account> | marker");
        return 2;
    }

    // ---- the experiment ----------------------------------------------------

    private static void Experiment()
    {
        Log($"--- service run as {WindowsIdentity.GetCurrent().Name}, pid {Environment.ProcessId}");
        Log($"privileges: {string.Join(", ", ListPrivileges())}");
        Log($"enable SeTcbPrivilege: {EnablePrivilege("SeTcbPrivilege")}");

        var session = WTSGetActiveConsoleSessionId();
        Log($"active console session: {session}");

        if (!WTSQueryUserToken(session, out var userToken))
        {
            var error = Marshal.GetLastPInvokeError();
            Log($"WTSQueryUserToken FAILED: {error} ({new Win32Exception(error).Message})");
            return;
        }

        Log("WTSQueryUserToken ok");
        try
        {
            if (!DuplicateTokenEx(userToken, MaximumAllowed, null, SecurityImpersonation, TokenPrimary, out var primary))
            {
                Log($"DuplicateTokenEx FAILED: {LastError()}");
                return;
            }

            try
            {
                StartMarker(primary);
            }
            finally
            {
                CloseHandle(primary);
            }
        }
        finally
        {
            CloseHandle(userToken);
        }
    }

    private static void StartMarker(nint primaryToken)
    {
        void* environment = null;
        if (!CreateEnvironmentBlock(&environment, primaryToken, false)) Log($"CreateEnvironmentBlock failed (continuing without): {LastError()}");

        var exe = Environment.ProcessPath!;
        var commandLine = $"\"{exe}\" marker\0".ToCharArray();
        var desktop = "winsta0\\default\0".ToCharArray();
        try
        {
            fixed (char* cmd = commandLine)
            fixed (char* desk = desktop)
            {
                var startup = new STARTUPINFOW { cb = (uint)sizeof(STARTUPINFOW), lpDesktop = desk };
                PROCESS_INFORMATION info;
                var ok = CreateProcessAsUserW(primaryToken, null, cmd, null, null, false, CreateUnicodeEnvironment | CreateNoWindow, environment, Path.GetDirectoryName(exe), &startup, &info);
                if (!ok)
                {
                    Log($"CreateProcessAsUser FAILED: {LastError()}");
                    return;
                }

                Log($"CreateProcessAsUser ok: child pid {info.dwProcessId}");
                WaitForSingleObject(info.hProcess, 10_000);
                CloseHandle(info.hThread);
                CloseHandle(info.hProcess);
            }
        }
        finally
        {
            if (environment is not null) DestroyEnvironmentBlock(environment);
        }
    }

    private static int Marker()
    {
        ProcessIdToSessionId((uint)Environment.ProcessId, out var session);
        Log($"marker: running as {WindowsIdentity.GetCurrent().Name} in session {session}, pid {Environment.ProcessId}");
        return 0;
    }

    // ---- LSA rights ---------------------------------------------------------

    private static int ChangeRight(string account, bool add)
    {
        var sid = new NTAccount(account).Translate(typeof(SecurityIdentifier)) as SecurityIdentifier
                  ?? throw new InvalidOperationException($"No SID for {account}.");
        var sidBytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(sidBytes, 0);

        var attributes = new LSA_OBJECT_ATTRIBUTES { Length = (uint)sizeof(LSA_OBJECT_ATTRIBUTES) };
        Check(LsaOpenPolicy(null, &attributes, PolicyCreateAccount | PolicyLookupNames, out var policy), "LsaOpenPolicy");
        try
        {
            fixed (char* name = "SeTcbPrivilege")
            fixed (byte* sidPointer = sidBytes)
            {
                var right = new LSA_UNICODE_STRING { Length = 14 * 2, MaximumLength = 14 * 2, Buffer = name };
                Check(add ? LsaAddAccountRights(policy, sidPointer, &right, 1) : LsaRemoveAccountRights(policy, sidPointer, false, &right, 1),
                      add ? "LsaAddAccountRights" : "LsaRemoveAccountRights");
            }
        }
        finally
        {
            LsaClose(policy);
        }

        var line = $"{(add ? "granted" : "revoked")} SeTcbPrivilege {(add ? "to" : "from")} {account} ({sid.Value})";
        Log(line);
        Console.WriteLine(line);
        return 0;
    }

    private static void Check(uint status, string call)
    {
        if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status), $"{call} failed (NTSTATUS 0x{status:X8})");
    }

    // ---- token helpers ------------------------------------------------------

    private static List<string> ListPrivileges()
    {
        var names = new List<string>();
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var token)) return [$"OpenProcessToken failed: {LastError()}"];
        try
        {
            GetTokenInformation(token, TokenPrivilegesClass, null, 0, out var needed);
            var buffer = new byte[needed];
            fixed (byte* p = buffer)
            {
                if (!GetTokenInformation(token, TokenPrivilegesClass, p, needed, out _)) return [$"GetTokenInformation failed: {LastError()}"];
                var count = *(uint*)p;
                var entries = (LUID_AND_ATTRIBUTES*)(p + 4);
                var chars = stackalloc char[64];
                for (var i = 0; i < count; i++)
                {
                    var length = 64u;
                    var luid = entries[i].Luid;
                    var name = LookupPrivilegeNameW(null, &luid, chars, &length) ? new string(chars, 0, (int)length) : "?";
                    names.Add((entries[i].Attributes & PrivilegeEnabled) != 0 ? name + "(enabled)" : name);
                }
            }
        }
        finally
        {
            CloseHandle(token);
        }

        return names;
    }

    private static string EnablePrivilege(string privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery | TokenAdjustPrivileges, out var token)) return $"OpenProcessToken failed: {LastError()}";
        try
        {
            if (!LookupPrivilegeValueW(null, privilege, out var luid)) return $"LookupPrivilegeValue failed: {LastError()}";
            var state = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Privilege = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = PrivilegeEnabled } };
            AdjustTokenPrivileges(token, false, &state, 0, null, null);
            var error = Marshal.GetLastPInvokeError();
            return error == 0 ? "ok" : $"not held ({error})";
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string LastError()
    {
        var error = Marshal.GetLastPInvokeError();
        return $"{error} ({new Win32Exception(error).Message})";
    }

    private static void Log(string line)
    {
        try
        {
            File.AppendAllText(LogPath, $"{DateTime.UtcNow:O} {line}{Environment.NewLine}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"log write failed ({e.Message}): {line}");
        }
    }

    // ---- service plumbing ---------------------------------------------------

    private static nint _statusHandle;

    private static int RunService()
    {
        fixed (char* name = ServiceName + "\0")
        {
            var table = stackalloc SERVICE_TABLE_ENTRYW[2];
            table[0] = new SERVICE_TABLE_ENTRYW { lpServiceName = name, lpServiceProc = &ServiceMain };
            table[1] = default;
            if (!StartServiceCtrlDispatcherW(table))
            {
                Console.Error.WriteLine($"Not started by the service control manager: {LastError()}");
                return 1;
            }
        }

        return 0;
    }

    [UnmanagedCallersOnly]
    private static void ServiceMain(uint argc, char** argv)
    {
        fixed (char* name = ServiceName + "\0")
        {
            _statusHandle = RegisterServiceCtrlHandlerExW(name, &Handler, null);
        }

        SetState(ServiceRunning);
        try
        {
            Experiment();
            EtwExperiment();
        }
        catch (Exception e)
        {
            Log($"experiment threw: {e}");
        }

        SetState(ServiceStopped);
    }

    [UnmanagedCallersOnly]
    private static uint Handler(uint control, uint eventType, void* eventData, void* context) => 0;

    private static void SetState(uint state)
    {
        var status = new SERVICE_STATUS { dwServiceType = ServiceWin32OwnProcess, dwCurrentState = state };
        SetServiceStatus(_statusHandle, &status);
    }

    // ---- interop ------------------------------------------------------------

    private const uint ServiceWin32OwnProcess = 0x10, ServiceRunning = 4, ServiceStopped = 1;
    private const uint TokenQuery = 0x0008, TokenAdjustPrivileges = 0x0020, MaximumAllowed = 0x02000000;
    private const int SecurityImpersonation = 2, TokenPrimary = 1, TokenPrivilegesClass = 3;
    private const uint PrivilegeEnabled = 0x2, CreateUnicodeEnvironment = 0x400, CreateNoWindow = 0x08000000;
    private const uint PolicyCreateAccount = 0x10, PolicyLookupNames = 0x800;

    [StructLayout(LayoutKind.Sequential)] private struct SERVICE_TABLE_ENTRYW { public char* lpServiceName; public delegate* unmanaged<uint, char**, void> lpServiceProc; }
    [StructLayout(LayoutKind.Sequential)] private struct SERVICE_STATUS { public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint; }
    [StructLayout(LayoutKind.Sequential)] private struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
    [StructLayout(LayoutKind.Sequential)] private struct LSA_UNICODE_STRING { public ushort Length, MaximumLength; public char* Buffer; }
    [StructLayout(LayoutKind.Sequential)] private struct LSA_OBJECT_ATTRIBUTES { public uint Length; public nint RootDirectory, ObjectName; public uint Attributes; public nint SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public nint hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public uint cb; public char* lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2; public nint lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool StartServiceCtrlDispatcherW(SERVICE_TABLE_ENTRYW* table);
    [LibraryImport("advapi32.dll", SetLastError = true)] private static partial nint RegisterServiceCtrlHandlerExW(char* name, delegate* unmanaged<uint, uint, void*, void*, uint> handler, void* context);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetServiceStatus(nint handle, SERVICE_STATUS* status);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool OpenProcessToken(nint process, uint access, out nint token);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetTokenInformation(nint token, int infoClass, byte* info, uint length, out uint returned);
    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool LookupPrivilegeValueW(string? system, string name, out LUID luid);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool LookupPrivilegeNameW(char* system, LUID* luid, char* name, uint* length);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool AdjustTokenPrivileges(nint token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, TOKEN_PRIVILEGES* state, uint length, TOKEN_PRIVILEGES* previous, uint* returned);
    [LibraryImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool DuplicateTokenEx(nint token, uint access, void* attributes, int level, int type, out nint duplicate);
    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool CreateProcessAsUserW(nint token, string? application, char* commandLine, void* processAttributes, void* threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, void* environment, string? directory, STARTUPINFOW* startup, PROCESS_INFORMATION* info);
    [LibraryImport("advapi32.dll")] private static partial uint LsaOpenPolicy(void* system, LSA_OBJECT_ATTRIBUTES* attributes, uint access, out nint policy);
    [LibraryImport("advapi32.dll")] private static partial uint LsaAddAccountRights(nint policy, byte* sid, LSA_UNICODE_STRING* rights, uint count);
    [LibraryImport("advapi32.dll")] private static partial uint LsaRemoveAccountRights(nint policy, byte* sid, [MarshalAs(UnmanagedType.U1)] bool all, LSA_UNICODE_STRING* rights, uint count);
    [LibraryImport("advapi32.dll")] private static partial uint LsaClose(nint policy);
    [LibraryImport("advapi32.dll")] private static partial uint LsaNtStatusToWinError(uint status);
    [LibraryImport("wtsapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool WTSQueryUserToken(uint session, out nint token);
    [LibraryImport("kernel32.dll")] private static partial uint WTSGetActiveConsoleSessionId();
    [LibraryImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool ProcessIdToSessionId(uint pid, out uint session);
    [LibraryImport("kernel32.dll")] private static partial nint GetCurrentProcess();
    [LibraryImport("kernel32.dll")] private static partial uint WaitForSingleObject(nint handle, uint milliseconds);
    [LibraryImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint handle);
    [LibraryImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool CreateEnvironmentBlock(void** environment, nint token, [MarshalAs(UnmanagedType.Bool)] bool inherit);
    [LibraryImport("userenv.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static partial bool DestroyEnvironmentBlock(void* environment);
}
