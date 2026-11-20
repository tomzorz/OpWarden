using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;

namespace OpWarden.Shim;

/// <summary>
/// Starts the op CLI so that the desktop app's biometric prompt names OpWarden rather than
/// the caller's shell (REQ-SHIM-11 to REQ-SHIM-14). The shim executable is installed twice:
/// as op.exe it is the shim, and as OpWarden.exe it is the launcher.
/// </summary>
/// <remarks>
/// The desktop app walks the op CLI's running ancestors upward and names the last one it
/// reaches, by file name. So the op CLI has to start under a process named OpWarden.exe whose
/// own parent has already exited:
///
/// <code>
///   shim ──starts──▶ relay ──starts──▶ launcher ──starts──▶ op CLI
///   (op.exe)         (OpWarden.exe     (OpWarden.exe
///    │                relay)            run)
///    │                exits at once,    waits for the go byte,
///    │                exit code = the   returns the op CLI's
///    │                launcher's ID     exit code as its own
///    │
///    └─ waits for the relay, opens the launcher by that ID, writes the go byte
/// </code>
///
/// The go pipe also carries the shim's lifetime. The launcher reads it again while the op CLI
/// runs, and end-of-file means the shim is gone, so the launcher ends the op CLI instead of
/// leaving it behind: a tree kill aimed at the shim cannot walk past the exited relay.
/// </remarks>
internal static class Launcher
{
    public const string FileName = "OpWarden.exe";

    private static readonly byte[] GoSignal = [1];

    /// <summary>
    /// True when this process runs under the launcher's file name rather than the shim's.
    /// </summary>
    public static bool IsThisProcess => string.Equals(Path.GetFileName(Environment.ProcessPath), FileName, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The shim's half: starts the op CLI under the launcher, or prints why it could not and
    /// returns null. With <paramref name="redirectStdout"/>, the op CLI's standard output
    /// arrives on <see cref="LaunchedOp.StandardOutput"/>; otherwise every standard stream is
    /// the shim's own, inherited through both launcher processes.
    /// </summary>
    public static async Task<LaunchedOp?> StartAsync(string opPath, string[] args, bool redirectStdout)
    {
        var launcher = Path.Combine(AppContext.BaseDirectory, FileName);
        if (!File.Exists(launcher))
        {
            Console.Error.WriteLine($"opwarden: the launcher is missing at {launcher}; reinstall OpWarden. The op CLI was not run.");
            return null;
        }

        var go = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        Process relay;
        try
        {
            relay = Process.Start(StartInfo(launcher, redirectStdout, ["relay", go.GetClientHandleAsString(), opPath, .. args]))
                ?? throw new Win32Exception($"Process.Start returned no process for {launcher}");

            // The shim's own copy of the read end has to go: while it exists, writing the go
            // byte succeeds whether or not the launcher is alive to read it.
            go.DisposeLocalCopyOfClientHandle();
        }
        catch (Win32Exception e)
        {
            Console.Error.WriteLine($"opwarden: could not start the launcher at {launcher} ({e.Message}).");
            await go.DisposeAsync();
            return null;
        }

        // Ctrl+C reaches the op CLI through the shared console. The shim waits it out so the
        // op CLI's exit code still comes back.
        Console.CancelKeyPress += (_, e) => e.Cancel = true;

        await relay.WaitForExitAsync();
        var parent = OpenLauncher(relay.ExitCode);
        if (parent is not null)
        {
            try
            {
                // The launcher blocks on this byte, so it was alive when OpenLauncher opened it by
                // ID unless the write fails: then no reader is left, and the handle may name a
                // process that took over the ID.
                await go.WriteAsync(GoSignal);
                await go.FlushAsync();
                return new LaunchedOp(relay, parent, go);
            }
            catch (IOException)
            {
                parent.Dispose();
            }
        }

        Console.Error.WriteLine("opwarden: the launcher exited before it could start the op CLI.");
        await go.DisposeAsync();
        relay.Dispose();
        return null;
    }

    /// <summary>
    /// The launcher's entry point. <c>relay</c> starts the launcher process that runs the op
    /// CLI and exits; <c>run</c> is that process.
    /// </summary>
    public static async Task<int> MainAsync(string[] args) => args switch
    {
        ["relay", var go, var opPath, .. var opArgs] => Relay(go, opPath, opArgs),
        ["run", var go, var opPath, .. var opArgs] => await RunAsync(go, opPath, opArgs),
        _ => Usage(),
    };

    /// <summary>
    /// Opens the launcher process whose ID the relay returned as its exit code, holding the
    /// handle so the exit code outlives the exit. Zero or a negative code means the relay
    /// failed, and the relay has said why on standard error.
    /// </summary>
    private static Process? OpenLauncher(int processId)
    {
        if (processId <= 0) return null;

        try
        {
            var parent = Process.GetProcessById(processId);
            _ = parent.SafeHandle;
            return parent;
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or Win32Exception)
        {
            // The launcher is already gone. StartAsync reports it.
            return null;
        }
    }

    /// <summary>
    /// Starts the launcher process that runs the op CLI, and exits at once, which leaves that
    /// process without a running parent. Its process ID is the exit code: the one value the
    /// shim can read from a process whose standard streams all belong to the op CLI.
    /// </summary>
    private static int Relay(string go, string opPath, string[] opArgs)
    {
        try
        {
            using var launcher = Process.Start(StartInfo(Environment.ProcessPath!, redirectStdout: false, ["run", go, opPath, .. opArgs]))
                ?? throw new Win32Exception($"Process.Start returned no process for {Environment.ProcessPath}");
            return launcher.Id;
        }
        catch (Win32Exception e)
        {
            Console.Error.WriteLine($"opwarden: the launcher could not start a copy of itself ({e.Message}).");
            return 0;
        }
    }

    /// <summary>
    /// The op CLI's parent. Starts the op CLI once the shim writes the go byte, which the shim
    /// does only after the relay has exited, and returns the op CLI's exit code as its own.
    /// </summary>
    private static async Task<int> RunAsync(string goHandle, string opPath, string[] opArgs)
    {
        // Never disposed: a read is still pending on it when the op CLI exits, and closing a
        // synchronous pipe handle under a pending read can block. Process exit closes it.
        var go = new AnonymousPipeClientStream(PipeDirection.In, goHandle);
        var signal = new byte[1];
        if (await go.ReadAsync(signal) == 0) return Program.ExitOpLaunchFailed;

        Console.CancelKeyPress += (_, e) => e.Cancel = true;

        Process op;
        try
        {
            op = Process.Start(StartInfo(opPath, redirectStdout: false, opArgs)) ?? throw new Win32Exception($"Process.Start returned no process for {opPath}");
        }
        catch (Win32Exception e)
        {
            Console.Error.WriteLine($"opwarden: could not start the op CLI at {opPath} ({e.Message}).");
            return Program.ExitOpLaunchFailed;
        }

        using (op)
        {
            // The shim writes nothing after the go byte, so this read ends only when the shim
            // closes its end, which it does once this process has exited. Ending first means the
            // shim is gone.
            var exited = op.WaitForExitAsync();
            if (await Task.WhenAny(exited, go.ReadAsync(signal).AsTask()) != exited) op.Kill(entireProcessTree: true);

            await exited;
            return op.ExitCode;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: OpWarden relay|run <go pipe handle> <op CLI path> <op arguments...>. The shim starts this; it is not meant to be run by hand.");
        return 2;
    }

    private static ProcessStartInfo StartInfo(string path, bool redirectStdout, IEnumerable<string> arguments)
    {
        // ArgumentList re-quotes the arguments canonically at every hop, so the op CLI receives
        // exactly the argv the classifier saw. Forwarding the raw command line instead would let
        // a quoting quirk mean one thing to .NET's parser and another to Go's.
        var startInfo = new ProcessStartInfo(path) { UseShellExecute = false, RedirectStandardOutput = redirectStdout };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        return startInfo;
    }
}

/// <summary>
/// The op CLI running under the launcher: its standard output when the shim redirected it, and
/// its exit code, which the launcher process returns as its own.
/// </summary>
internal sealed class LaunchedOp(Process relay, Process launcher, AnonymousPipeServerStream go) : IAsyncDisposable
{
    /// <summary>
    /// The op CLI's standard output. The relay was started with it redirected, and both
    /// launcher processes and the op CLI inherit the write end, so it ends once all have exited.
    /// </summary>
    public Stream StandardOutput => relay.StandardOutput.BaseStream;

    public async Task<int> WaitForExitAsync()
    {
        await launcher.WaitForExitAsync();
        return launcher.ExitCode;
    }

    public async ValueTask DisposeAsync()
    {
        // Closing the go pipe tells a launcher that still runs that the shim is gone.
        await go.DisposeAsync();
        launcher.Dispose();
        relay.Dispose();
    }
}
