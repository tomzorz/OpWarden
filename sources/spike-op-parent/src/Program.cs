// OpWarden spike: what does the 1Password desktop app name in its prompt, and how far
// does one approval reach, when the op CLI starts under a parent of our choosing?
//
// The op CLI tells the desktop app which process invoked it, and the desktop app picks
// the name its Windows Hello prompt shows. With the shim as the op CLI's parent the
// prompt still names a process further up, so the question is which shape of ancestry
// makes it name us instead.
//
// Modes:
//   direct <op path> <op arguments...>
//       start the op CLI as a child and wait: op <- this <- the calling shell
//   severed <op path> <op arguments...>
//       the same, from a copy of this executable whose own parent has already exited:
//       op <- this <- (nothing alive)
//   relay, orphan
//       the two internal steps of `severed`
//
// The op CLI's standard output is read and thrown away, so no account data reaches the
// terminal or a results file. No packages and no Win32: Process.Start is the whole
// mechanism.

using System.Diagnostics;
using System.Globalization;

namespace OpWarden.SpikeOpParent;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            return args switch
            {
                ["direct", var opPath, .. var opArguments] => await RunOp(opPath, opArguments),
                ["severed", _, ..] => await Severed(args[1..]),
                ["relay", _, ..] => Relay(args[1..]),
                ["orphan", var relayId, var opPath, .. var opArguments] => await Orphan(int.Parse(relayId, CultureInfo.InvariantCulture), opPath, opArguments),
                _ => Usage(),
            };
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"opwarden-spike-file: {e.Message}");
            return 1;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("usage: opwarden-spike-file direct|severed <op path> <op arguments...>");
        return 2;
    }

    /// <summary>
    /// Starts the op CLI as a child of this process, discards what it prints, and reports
    /// how it ended and how long it took. A call that waited on a prompt takes seconds.
    /// </summary>
    private static async Task<int> RunOp(string opPath, string[] opArguments)
    {
        var startInfo = new ProcessStartInfo(opPath) { UseShellExecute = false, RedirectStandardOutput = true };
        foreach (var argument in opArguments) startInfo.ArgumentList.Add(argument);

        Console.WriteLine($"op CLI parent: {Path.GetFileName(Environment.ProcessPath)} ({Environment.ProcessId})");
        var clock = Stopwatch.StartNew();
        using var op = Process.Start(startInfo) ?? throw new InvalidOperationException($"Process.Start returned no process for {opPath}.");
        var discarded = (await op.StandardOutput.ReadToEndAsync()).Length;
        await op.WaitForExitAsync();

        Console.WriteLine($"op CLI exit code {op.ExitCode} after {clock.ElapsedMilliseconds} ms, {discarded} characters of output discarded");
        return op.ExitCode;
    }

    /// <summary>
    /// Runs the op CLI under an orphan: a copy of this executable whose parent, the relay,
    /// has exited. This process is not an ancestor of the op CLI; it only waits and echoes.
    /// </summary>
    private static async Task<int> Severed(string[] opCommand)
    {
        // The relay's standard output is a pipe that the orphan and the op CLI inherit, so
        // reading it to the end both shows the orphan's report and waits for all three.
        using var relay = Process.Start(SelfStartInfo(redirectOutput: true, ["relay", .. opCommand])) ?? throw new InvalidOperationException("Process.Start returned no process for the relay.");
        while (await relay.StandardOutput.ReadLineAsync() is { } line) Console.WriteLine(line);
        return 0;
    }

    private static int Relay(string[] opCommand)
    {
        // Start the orphan and leave at once: exiting is this step's whole job.
        using var orphan = Process.Start(SelfStartInfo(redirectOutput: false, ["orphan", Environment.ProcessId.ToString(CultureInfo.InvariantCulture), .. opCommand])) ?? throw new InvalidOperationException("Process.Start returned no process for the orphan.");
        return 0;
    }

    private static async Task<int> Orphan(int relayId, string opPath, string[] opArguments)
    {
        // The op CLI must not start while the relay still runs, or the ancestry is not severed yet.
        try
        {
            using var relay = Process.GetProcessById(relayId);
            await relay.WaitForExitAsync();
        }
        catch (ArgumentException)
        {
            // GetProcessById throws when no such process runs: the relay is already gone.
        }

        Console.WriteLine($"relay {relayId} has exited");
        return await RunOp(opPath, opArguments);
    }

    private static ProcessStartInfo SelfStartInfo(bool redirectOutput, string[] arguments)
    {
        var startInfo = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, RedirectStandardOutput = redirectOutput };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        return startInfo;
    }
}
