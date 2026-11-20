using System.Text.Json;

// Test executable standing where the op CLI would. It imitates nothing: it reports what
// the shim delivered to it. Driven by environment variables, because the shim forwards
// the environment untouched and the arguments are the thing under test.
//
//   PROBE_ARGV_FILE   write the received arguments here as a JSON array
//   PROBE_PID_FILE    write this process's ID here, so a test can see where the shim started it
//   PROBE_STDOUT      print this to standard output
//   PROBE_STDERR      print this to standard error
//   PROBE_ECHO_STDIN  when "1", copy standard input to standard output
//   PROBE_EXIT        exit with this code (default 0)

if (Environment.GetEnvironmentVariable("PROBE_ARGV_FILE") is { Length: > 0 } argvFile)
{
    await File.WriteAllTextAsync(argvFile, JsonSerializer.Serialize(args, ProbeJsonContext.Default.StringArray));
}

if (Environment.GetEnvironmentVariable("PROBE_PID_FILE") is { Length: > 0 } pidFile)
{
    await File.WriteAllTextAsync(pidFile, Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
}

await using var stdout = Console.OpenStandardOutput();
if (Environment.GetEnvironmentVariable("PROBE_STDOUT") is { Length: > 0 } text) await stdout.WriteAsync(System.Text.Encoding.UTF8.GetBytes(text));
if (Environment.GetEnvironmentVariable("PROBE_ECHO_STDIN") == "1")
{
    await using var stdin = Console.OpenStandardInput();
    await stdin.CopyToAsync(stdout);
}

if (Environment.GetEnvironmentVariable("PROBE_STDERR") is { Length: > 0 } error) await Console.Error.WriteAsync(error);

return int.TryParse(Environment.GetEnvironmentVariable("PROBE_EXIT"), out var code) ? code : 0;

[System.Text.Json.Serialization.JsonSerializable(typeof(string[]))]
internal sealed partial class ProbeJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
