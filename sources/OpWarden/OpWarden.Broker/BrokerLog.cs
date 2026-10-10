namespace OpWarden.Broker;

/// <summary>
/// The service broker's diagnostic log: connection errors and start failures, which the
/// console broker writes to standard error. Never secrets, and never audit events, which
/// belong to the audit log.
/// </summary>
internal sealed class BrokerLog(string path)
{
    // ceiling: one rotation of 1 MB keeps the last few thousand errors, which is plenty
    // for diagnosing; switch to the event log if anyone needs history.
    private const long MaxBytes = 1024 * 1024;

    private readonly Lock _lock = new();

    public void Write(string message)
    {
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                if (File.Exists(path) && new FileInfo(path).Length > MaxBytes) File.Move(path, path + ".1", overwrite: true);
                File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // The log is the place failures go; with the log itself failing, standard
                // error is the last resort, read by nobody under the service.
                Console.Error.WriteLine($"{message} (and the broker log failed: {e.Message})");
            }
        }
    }
}
