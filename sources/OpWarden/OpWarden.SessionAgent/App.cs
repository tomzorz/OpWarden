using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace OpWarden.SessionAgent;

/// <summary>
/// The WPF application: the palette for the current Windows app theme, then the
/// components' default styles.
/// </summary>
internal sealed class App : Application
{
    public App()
    {
        Resources.MergedDictionaries.Add(Theme.PaletteForSystem());
        Resources.MergedDictionaries.Add(new ResourceDictionary { Source = Theme.ComponentsUri });
        DispatcherUnhandledException += OnUnhandledException;
    }

    private static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // A broken window must not take the prompts down with it: log it, keep running.
        AgentLog.Write($"unhandled UI exception: {e.Exception}");
        e.Handled = true;
    }
}

/// <summary>
/// Picks the palette that matches Windows' app theme, and swaps it when that changes.
/// </summary>
internal static class Theme
{
    public static readonly Uri ComponentsUri = new("/OpWarden.SessionAgent;component/Themes/Components.xaml", UriKind.Relative);

    private static readonly Uri DarkPaletteUri = new("/OpWarden.SessionAgent;component/Themes/Palette.Dark.xaml", UriKind.Relative);
    private static readonly Uri LightPaletteUri = new("/OpWarden.SessionAgent;component/Themes/Palette.Light.xaml", UriKind.Relative);

    private static bool AppsUseLightTheme =>
        Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is not int light || light != 0;

    public static ResourceDictionary PaletteForSystem() => new() { Source = AppsUseLightTheme ? LightPaletteUri : DarkPaletteUri };

    /// <summary>
    /// Replaces the palette in place; everything that reads it through DynamicResource
    /// repaints.
    /// </summary>
    public static void Refresh(Application app) => app.Resources.MergedDictionaries[0] = PaletteForSystem();
}
