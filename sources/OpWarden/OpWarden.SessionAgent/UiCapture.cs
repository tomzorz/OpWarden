using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace OpWarden.SessionAgent;

/// <summary>
/// With OPWARDEN_UI_SCREENSHOTS naming a folder, each window saves a PNG of itself once it
/// has rendered. It renders offscreen, so it works while the workstation is locked, which
/// is when screen grabs come out black.
/// </summary>
internal static class UiCapture
{
    private static readonly string? Folder = Environment.GetEnvironmentVariable("OPWARDEN_UI_SCREENSHOTS") is { Length: > 0 } folder ? folder : null;

    public static void WhenRequested(Window window, string name)
    {
        if (Folder is null) return;
        window.ContentRendered += (_, _) => Save(window, name);
    }

    private static void Save(Window window, string name)
    {
        try
        {
            // The window template's root covers exactly the client area. The window itself
            // also counts the title bar it does not render, and its content sits inside a
            // margin, which renders offset.
            if (VisualTreeHelper.GetChildrenCount(window) == 0 || VisualTreeHelper.GetChild(window, 0) is not FrameworkElement root || root.ActualWidth <= 0) return;
            var dpi = VisualTreeHelper.GetDpi(root);
            var bitmap = new RenderTargetBitmap(
                (int)Math.Ceiling(root.ActualWidth * dpi.DpiScaleX),
                (int)Math.Ceiling(root.ActualHeight * dpi.DpiScaleY),
                dpi.PixelsPerInchX,
                dpi.PixelsPerInchY,
                PixelFormats.Pbgra32);
            bitmap.Render(root);

            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            Directory.CreateDirectory(Folder!);
            using var file = File.Create(Path.Combine(Folder!, $"{name}-{DateTime.Now:HHmmss-fff}.png"));
            encoder.Save(file);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AgentLog.Write($"could not save the {name} screenshot: {e.Message}");
        }
    }
}
