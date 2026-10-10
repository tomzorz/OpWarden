using System.IO;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent's log, in the user's local application data: the install directory
/// is read-only to the user, and a WinExe has no console.
/// </summary>
internal static class AgentLog
{
    private static readonly Lock Gate = new();

    private static readonly string LogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpWarden", "session-agent.log");

    public static void Write(string line)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
                File.AppendAllText(LogPath, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}");
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Nowhere left to report it.
        }
    }
}
