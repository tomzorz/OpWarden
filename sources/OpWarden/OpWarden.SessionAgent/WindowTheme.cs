using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace OpWarden.SessionAgent;

/// <summary>
/// Gives a window with standard chrome a title bar that matches the app theme: Windows
/// draws it light unless asked otherwise.
/// </summary>
internal static unsafe partial class WindowTheme
{
    private const int ImmersiveDarkMode = 20, ImmersiveDarkModeBefore20H1 = 19;

    public static void Follow(Window window) => window.SourceInitialized += (_, _) => Apply(window);

    public static void Apply(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == 0) return;
        var dark = AppsUseDarkTheme ? 1 : 0;
        if (DwmSetWindowAttribute(handle, ImmersiveDarkMode, &dark, sizeof(int)) != 0) _ = DwmSetWindowAttribute(handle, ImmersiveDarkModeBefore20H1, &dark, sizeof(int));
    }

    private static bool AppsUseDarkTheme =>
        Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is int light && light == 0;

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint window, int attribute, void* value, int size);
}

/// <summary>
/// Changing rules takes an elevated administrator (REQ-TRUST-5), so the rules window
/// restarts itself elevated to edit, and only then.
/// </summary>
internal static class Elevation
{
    public static bool IsElevated
    {
        get
        {
            using var self = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(self).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>
    /// Starts the elevated rules editor on the same pipes. False when the user declined
    /// the elevation prompt.
    /// </summary>
    public static bool StartRulesEditor(AgentOptions options)
    {
        try
        {
            using var editor = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"--manage {options.PipeArguments}") { UseShellExecute = true, Verb = "runas" });
            return editor is not null;
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED: the user said no to the elevation prompt.
            return false;
        }
    }
}
