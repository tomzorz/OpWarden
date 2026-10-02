using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using OpWarden.Core.Pipe;

namespace OpWarden.Shim;

/// <summary>
/// The shim: named op.exe and placed on PATH ahead of the op CLI. It asks the broker
/// for a verdict and then runs the op CLI, prints cached output, or refuses.
/// </summary>
internal static class Program
{
    // sysexits(3) codes, so a script can tell OpWarden's refusals from the op CLI's own
    // failures, which exit 1.
    private const int ExitDenied = 77;            // EX_NOPERM
    private const int ExitBrokerUnavailable = 69; // EX_UNAVAILABLE
    private const int ExitOpLaunchFailed = 71;    // EX_OSERR

    private const int ConnectTimeoutMilliseconds = 2000;

    // The capture travels base64-encoded inside one JSON frame, which inflates it by a
    // third; half the frame limit leaves room for that.
    private const int CaptureLimit = PipeProtocol.MaxFrameBytes / 2;

    private static async Task<int> Main(string[] args)
    {
        var request = ShimRequestBuilder.Build(args, ReadEnvironment());
        var pipeName = PipeProtocol.ResolvePipeName();

        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        VerdictResponse? verdict;
        try
        {
            await pipe.ConnectAsync(ConnectTimeoutMilliseconds);
            await PipeProtocol.WriteAsync(pipe, request, CancellationToken.None);
            verdict = await PipeProtocol.ReadVerdictAsync(pipe, CancellationToken.None);
        }
        catch (Exception e) when (e is TimeoutException or IOException or InvalidDataException or JsonException)
        {
            return Unavailable(pipeName, e.Message);
        }

        // REQ-SHIM-6: no verdict is a deny.
        if (verdict is null) return Unavailable(pipeName, "the broker closed the connection without a verdict");

        if (verdict.Verdict == Verdict.Deny)
        {
            Console.Error.WriteLine(verdict.Message is { Length: > 0 } reason ? $"opwarden: denied: {reason}" : "opwarden: denied.");
            return ExitDenied;
        }

        if (verdict.Cached is { } cached)
        {
            await using var stdout = Console.OpenStandardOutput();
            await stdout.WriteAsync(cached.Bytes);
            return 0;
        }

        if (!IsRunnableOpPath(verdict.OpPath, out var problem)) return Unavailable(pipeName, problem);

        return PipeProtocol.ExpectsCapture(request, verdict)
            ? await RunCapturingAsync(verdict.OpPath, args, pipe)
            : await RunAsync(verdict.OpPath, args);
    }

    /// <summary>
    /// Runs the op CLI with every standard stream inherited, so terminal detection and
    /// the desktop app's biometric flow behave exactly as without the shim (REQ-SHIM-4).
    /// </summary>
    private static async Task<int> RunAsync(string opPath, string[] args)
    {
        using var child = Start(opPath, args, redirectStdout: false);
        if (child is null) return ExitOpLaunchFailed;

        await child.WaitForExitAsync();
        return child.ExitCode;
    }

    /// <summary>
    /// Runs the op CLI for an allowed read: standard output is relayed and copied at
    /// the same time, and the copy goes to the broker once the op CLI exits (REQ-SHIM-9).
    /// </summary>
    private static async Task<int> RunCapturingAsync(string opPath, string[] args, Stream pipe)
    {
        using var child = Start(opPath, args, redirectStdout: true);
        if (child is null) return ExitOpLaunchFailed;

        var buffer = new byte[16 * 1024];
        using var capture = new MemoryStream();
        var truncated = false;
        await using (var stdout = Console.OpenStandardOutput())
        {
            var relaying = true;
            var source = child.StandardOutput.BaseStream;
            int read;
            while ((read = await source.ReadAsync(buffer)) > 0)
            {
                if (relaying)
                {
                    try
                    {
                        await stdout.WriteAsync(buffer.AsMemory(0, read));
                        await stdout.FlushAsync();
                    }
                    catch (IOException)
                    {
                        // The reader went away (`op read … | head -c1`). Keep draining so the
                        // op CLI is not blocked on a full pipe, as it would not be without the shim.
                        relaying = false;
                    }
                }

                if (truncated || capture.Length + read > CaptureLimit) truncated = true;
                else capture.Write(buffer, 0, read);
            }
        }

        await child.WaitForExitAsync();

        var output = truncated ? [] : capture.ToArray();
        try
        {
            await PipeProtocol.WriteAsync(pipe, new ReadCapture(child.ExitCode, output, truncated), CancellationToken.None);
        }
        catch (IOException e)
        {
            // The read already happened and printed; losing the copy costs the broker an
            // alias pair and a cache entry, not the caller its result.
            Console.Error.WriteLine($"opwarden: could not hand the read output to the broker ({e.Message}).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
            CryptographicOperations.ZeroMemory(capture.GetBuffer());
            CryptographicOperations.ZeroMemory(buffer);
        }

        return child.ExitCode;
    }

    private static Process? Start(string opPath, string[] args, bool redirectStdout)
    {
        // ArgumentList re-quotes the arguments canonically, so the op CLI receives exactly
        // the argv the classifier saw. Forwarding the raw command line instead would let
        // a quoting quirk mean one thing to .NET's parser and another to Go's.
        var startInfo = new ProcessStartInfo(opPath) { UseShellExecute = false, RedirectStandardOutput = redirectStdout };
        foreach (var arg in args) startInfo.ArgumentList.Add(arg);

        try
        {
            var child = Process.Start(startInfo) ?? throw new Win32Exception($"Process.Start returned no process for {opPath}");

            // Ctrl+C reaches the op CLI through the shared console. The shim waits it
            // out so the op CLI's exit code still comes back.
            Console.CancelKeyPress += (_, e) => e.Cancel = true;
            return child;
        }
        catch (Win32Exception e)
        {
            Console.Error.WriteLine($"opwarden: could not start the op CLI at {opPath} ({e.Message}).");
            return null;
        }
    }

    /// <summary>
    /// Checks the op CLI path the broker sent. The shim must never run itself or another
    /// OpWarden shim: either loops back to the broker for every hop, forever.
    /// </summary>
    private static bool IsRunnableOpPath([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? opPath, out string problem)
    {
        problem = "";
        if (opPath is null || !Path.IsPathFullyQualified(opPath)) problem = $"the broker sent no absolute op CLI path ('{opPath}')";
        else if (!File.Exists(opPath)) problem = $"the configured op CLI does not exist at {opPath}";
        else if (string.Equals(Path.GetFullPath(opPath), Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) problem = $"the configured op CLI path {opPath} is this shim";
        else if (FileVersionInfo.GetVersionInfo(opPath).ProductName == ShimProductName) problem = $"the configured op CLI path {opPath} is an OpWarden shim";

        return problem.Length == 0;
    }

    private const string ShimProductName = "OpWarden";

    private static Dictionary<string, string> ReadEnvironment()
    {
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && entry.Value is string value) environment[key] = value;
        }

        return environment;
    }

    private static int Unavailable(string pipeName, string reason)
    {
        Console.Error.WriteLine($"opwarden: the OpWarden broker is unavailable on pipe '{pipeName}' ({reason}); the op CLI was not run.");
        return ExitBrokerUnavailable;
    }
}
