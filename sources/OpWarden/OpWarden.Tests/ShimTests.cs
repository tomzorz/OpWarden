using System.Diagnostics;
using System.Text;
using System.Text.Json;
using OpWarden.Core;
using OpWarden.Core.Pipe;

namespace OpWarden.Tests;

/// <summary>
/// The shim end to end: real shim process, real pipe server, and the probe standing
/// where the op CLI would. Covers REQ-SHIM-2 to REQ-SHIM-10.
/// </summary>
public sealed class ShimTests : IDisposable
{
    private const int ExitDenied = 77;
    private const int ExitBrokerUnavailable = 69;

    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("opwarden-shim-");

    private string ArgvFile => Path.Combine(_directory.FullName, "argv.json");

    public void Dispose() => _directory.Delete(recursive: true);

    [Fact]
    public async Task Allow_runs_the_op_cli_with_the_arguments_unchanged()
    {
        string[] args = ["item", "get", "My Item", "--vault", "V", "quote\"inside", @"trailing\", @"back\\slash\""q", "", "árvíztűrő", "--fields=label=password"];
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(BuiltExecutables.Probe));

        var run = await harness.RunAsync(args, ProbeEnvironment());

        Assert.Equal(0, run.ExitCode);
        Assert.Equal(args, ReceivedArguments());
    }

    [Fact]
    public async Task The_op_cli_exit_code_becomes_the_shim_exit_code()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(BuiltExecutables.Probe));

        var run = await harness.RunAsync(["whoami"], ProbeEnvironment(("PROBE_EXIT", "3")));

        Assert.Equal(3, run.ExitCode);
    }

    [Theory]
    [InlineData("whoami")]
    [InlineData("read")]
    public async Task Standard_input_output_and_error_reach_the_op_cli(string command)
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(BuiltExecutables.Probe));

        var run = await harness.RunAsync([command, "op://v/i/f"], ProbeEnvironment(("PROBE_ECHO_STDIN", "1"), ("PROBE_STDERR", "a warning")), stdin: "piped input\n");

        Assert.Equal("piped input\n", run.Stdout);
        Assert.Contains("a warning", run.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deny_does_not_run_the_op_cli_and_exits_non_zero()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.Deny("no rule allows this"));

        var run = await harness.RunAsync(["read", "op://v/i/f"], ProbeEnvironment(("PROBE_STDOUT", "s3cret")));

        Assert.Equal(ExitDenied, run.ExitCode);
        Assert.Equal("", run.Stdout);
        Assert.Contains("no rule allows this", run.Stderr, StringComparison.Ordinal);
        Assert.False(File.Exists(ArgvFile));
    }

    [Fact]
    public async Task An_unreachable_broker_is_a_deny_that_names_opwarden()
    {
        var run = await ShimHarness.RunShimAsync($"OpWarden-test-nobody-{Guid.NewGuid():N}", ["read", "op://v/i/f"], ProbeEnvironment());

        Assert.Equal(ExitBrokerUnavailable, run.ExitCode);
        Assert.Equal("", run.Stdout);
        Assert.Contains("OpWarden", run.Stderr, StringComparison.Ordinal);
        Assert.Single(run.Stderr.Trim().Split('\n'));
    }

    [Fact]
    public async Task A_broker_that_fails_mid_request_is_a_deny()
    {
        await using var harness = ShimHarness.Start(_ => throw new InvalidOperationException("rule store unreadable"));

        var run = await harness.RunAsync(["read", "op://v/i/f"], ProbeEnvironment());

        Assert.Equal(ExitBrokerUnavailable, run.ExitCode);
        Assert.False(File.Exists(ArgvFile));
        Assert.Contains(harness.ConnectionErrors, e => e.Message == "rule store unreadable");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task An_allowed_read_is_relayed_and_its_copy_reaches_the_broker(int exitCode)
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(BuiltExecutables.Probe));

        var run = await harness.RunAsync(["read", "op://v/i/f"], ProbeEnvironment(("PROBE_STDOUT", "s3cret\n"), ("PROBE_EXIT", exitCode.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        var capture = await harness.CaptureAsync();

        Assert.Equal(exitCode, run.ExitCode);
        Assert.Equal("s3cret\n", run.Stdout);
        Assert.Equal("s3cret\n"u8.ToArray(), capture.Output);
        Assert.Equal(exitCode, capture.ExitCode);
        Assert.False(capture.Truncated);
    }

    [Fact]
    public async Task Cached_output_is_printed_without_running_the_op_cli()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.FromCache("from the cache\n"u8.ToArray()));

        var run = await harness.RunAsync(["read", "op://v/i/f"], ProbeEnvironment());

        Assert.Equal(0, run.ExitCode);
        Assert.Equal("from the cache\n", run.Stdout);
        Assert.False(File.Exists(ArgvFile));
    }

    [Fact]
    public async Task The_broker_receives_the_classified_request()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.Deny("inspecting"));

        await harness.RunAsync(["item", "get", "Item", "--vault", "V", "--fields", "password"]);

        var request = Assert.Single(harness.Requests);
        Assert.Equal(PipeProtocol.Version, request.ProtocolVersion);
        Assert.Equal(["item", "get", "Item", "--vault", "V", "--fields", "password"], request.Arguments);
        Assert.Equal("item get", request.Command);
        Assert.Equal(OpAction.Read, request.Action);
        Assert.Equal(new SecretPath("V", "Item", "password"), request.Path);
    }

    [Fact]
    public async Task Run_requests_carry_references_from_the_environment()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.Deny("inspecting"));

        await harness.RunAsync(["run", "--", "cmd"], new Dictionary<string, string> { ["OPWARDEN_TEST_DB"] = "op://v/db/password" });

        var request = Assert.Single(harness.Requests);
        Assert.Equal(OpAction.Run, request.Action);
        Assert.Contains(new SecretPath("v", "db", "password"), request.SecretReferences);
    }

    [Fact]
    public async Task The_shim_refuses_to_run_itself_as_the_op_cli()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(BuiltExecutables.Shim));

        var run = await harness.RunAsync(["whoami"]);

        Assert.Equal(ExitBrokerUnavailable, run.ExitCode);
        Assert.Contains("this shim", run.Stderr, StringComparison.Ordinal);
        Assert.Single(harness.Requests);
    }

    [Fact]
    public async Task The_shim_refuses_another_opwarden_shim_as_the_op_cli()
    {
        var copy = Path.Combine(_directory.FullName, "op.exe");
        foreach (var file in Directory.GetFiles(Path.GetDirectoryName(BuiltExecutables.Shim)!)) File.Copy(file, Path.Combine(_directory.FullName, Path.GetFileName(file)));
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(copy));

        var run = await harness.RunAsync(["whoami"]);

        Assert.Equal(ExitBrokerUnavailable, run.ExitCode);
        Assert.Contains("OpWarden shim", run.Stderr, StringComparison.Ordinal);
        Assert.Single(harness.Requests);
    }

    [Theory]
    [InlineData("op.exe")]
    [InlineData(@"C:\definitely\not\here\op.exe")]
    public async Task The_shim_refuses_an_op_cli_path_it_cannot_trust(string opPath)
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(opPath));

        var run = await harness.RunAsync(["whoami"]);

        Assert.Equal(ExitBrokerUnavailable, run.ExitCode);
    }

    [Fact]
    public async Task A_burst_of_shims_each_gets_its_verdict()
    {
        await using var harness = ShimHarness.Start(_ => VerdictResponse.FromCache("ok"u8.ToArray()));

        var runs = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => harness.RunAsync(["read", "op://v/i/f"])));

        Assert.All(runs, run => Assert.Equal("ok", run.Stdout));
        Assert.Equal(12, harness.Requests.Count);
    }

    [Fact]
    public async Task The_real_op_cli_reports_its_version_through_the_shim()
    {
        var realOp = FindRealOpCli();
        Assert.SkipWhen(realOp is null, "No op CLI on PATH.");
        await using var harness = ShimHarness.Start(_ => VerdictResponse.RunOp(realOp!));

        var run = await harness.RunAsync(["--version"]);

        Assert.Equal(0, run.ExitCode);
        Assert.Matches(@"^\d+\.\d+\.\d+", run.Stdout);
        Assert.Equal(OpAction.Meta, Assert.Single(harness.Requests).Action);
    }

    /// <summary>
    /// REQ-SHIM-8 against the published NativeAOT shim, which is what ships: a debug
    /// build's JIT start-up says nothing about the budget. Set OPWARDEN_AOT_SHIM to the
    /// published op.exe to run it.
    /// </summary>
    [Fact]
    public async Task The_published_shim_answers_a_cached_verdict_within_50_milliseconds()
    {
        var aotShim = Environment.GetEnvironmentVariable("OPWARDEN_AOT_SHIM");
        Assert.SkipWhen(string.IsNullOrEmpty(aotShim), "OPWARDEN_AOT_SHIM is not set.");
        await using var harness = ShimHarness.Start(_ => VerdictResponse.FromCache("ok"u8.ToArray()));
        await harness.RunAsync(["read", "op://v/i/f"], shimPath: aotShim);

        var timings = new List<TimeSpan>();
        for (var i = 0; i < 20; i++) timings.Add((await harness.RunAsync(["read", "op://v/i/f"], shimPath: aotShim)).Elapsed);
        var median = timings.Order().ElementAt(timings.Count / 2);

        TestContext.Current.SendDiagnosticMessage($"AOT shim, cached verdict: median {median.TotalMilliseconds:F1} ms over {timings.Count} runs.");
        Assert.True(median < TimeSpan.FromMilliseconds(50), $"Median {median.TotalMilliseconds:F1} ms exceeds the 50 ms budget.");
    }

    private Dictionary<string, string> ProbeEnvironment(params (string Name, string Value)[] settings)
    {
        var environment = new Dictionary<string, string> { ["PROBE_ARGV_FILE"] = ArgvFile };
        foreach (var (name, value) in settings) environment[name] = value;
        return environment;
    }

    private string[] ReceivedArguments() => JsonSerializer.Deserialize<string[]>(File.ReadAllText(ArgvFile, Encoding.UTF8))!;

    private static string? FindRealOpCli() =>
        (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Select(directory => Path.Combine(directory, "op.exe"))
            .FirstOrDefault(path => File.Exists(path) && FileVersionInfo.GetVersionInfo(path).ProductName != "OpWarden");
}
