using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using OpWarden.Broker;
using OpWarden.Core.Pipe;

namespace OpWarden.Tests;

/// <summary>
/// Runs the built shim as a real process against a real <see cref="ShimPipeServer"/>
/// on a pipe name of its own. The verdict is the test's to choose: the rule engine and
/// the prompt flow that will make that choice in the broker are not under test here.
/// </summary>
internal sealed class ShimHarness : IAsyncDisposable
{
    private readonly ShimPipeServer _server;
    private readonly TaskCompletionSource<ReadCapture> _capture = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private ShimHarness(Func<ShimRequest, VerdictResponse> verdict)
    {
        _server = new ShimPipeServer(
            PipeName,
            (request, _) =>
            {
                Requests.Enqueue(request);
                return ValueTask.FromResult(verdict(request));
            },
            (_, capture, _) =>
            {
                _capture.TrySetResult(capture);
                return ValueTask.CompletedTask;
            },
            ConnectionErrors.Enqueue);
        _server.Start();
    }

    public string PipeName { get; } = $"OpWarden-test-{Guid.NewGuid():N}";

    public ConcurrentQueue<ShimRequest> Requests { get; } = new();

    public ConcurrentQueue<Exception> ConnectionErrors { get; } = new();

    public static ShimHarness Start(Func<ShimRequest, VerdictResponse> verdict) => new(verdict);

    public Task<ReadCapture> CaptureAsync() => _capture.Task.WaitAsync(TimeSpan.FromSeconds(10));

    public Task<ShimRun> RunAsync(IEnumerable<string> args, IReadOnlyDictionary<string, string>? environment = null, string? stdin = null, string? shimPath = null) =>
        RunShimAsync(PipeName, args, environment, stdin, shimPath);

    public ValueTask DisposeAsync() => _server.DisposeAsync();

    public static async Task<ShimRun> RunShimAsync(string pipeName, IEnumerable<string> args, IReadOnlyDictionary<string, string>? environment = null, string? stdin = null, string? shimPath = null)
    {
        var startInfo = new ProcessStartInfo(shimPath ?? BuiltExecutables.Shim)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args) startInfo.ArgumentList.Add(arg);
        startInfo.Environment[PipeProtocol.PipeNameVariable] = pipeName;
        foreach (var (name, value) in environment ?? new Dictionary<string, string>()) startInfo.Environment[name] = value;

        using var shim = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start the shim at {BuiltExecutables.Shim}.");
        var stdout = shim.StandardOutput.ReadToEndAsync();
        var stderr = shim.StandardError.ReadToEndAsync();
        if (stdin is not null) await shim.StandardInput.WriteAsync(stdin);
        shim.StandardInput.Close();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await shim.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            shim.Kill(entireProcessTree: true);
            throw new TimeoutException($"The shim did not exit within 30 seconds (args: {string.Join(' ', startInfo.ArgumentList)}).");
        }

        return new ShimRun(shim.ExitCode, await stdout, await stderr, shim.ExitTime - shim.StartTime);
    }
}

internal sealed record ShimRun(int ExitCode, string Stdout, string Stderr, TimeSpan Elapsed);

internal static class BuiltExecutables
{
    public static string Shim => Locate("OpWarden.Shim", Path.Combine("win-x64", "op.exe"));

    public static string Probe => Locate("OpWarden.Probe", "OpWarden.Probe.exe");

    // The tests run from <solution>\OpWarden.Tests\bin\<configuration>\<tfm>\, and the
    // project references build the shim and the probe into the same shape beside them.
    private static string Locate(string project, string relativePath)
    {
        var tfm = new DirectoryInfo(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory));
        var configuration = tfm.Parent!;
        var solution = configuration.Parent!.Parent!.Parent!;
        var path = Path.Combine(solution.FullName, project, "bin", configuration.Name, tfm.Name, relativePath);
        return File.Exists(path) ? path : throw new FileNotFoundException($"{project} has not been built: expected {path}.", path);
    }
}
