using System.Windows;

namespace OpWarden.SessionAgent;

/// <summary>
/// A monitor's work area in physical pixels, and its scale: physical pixels per DIP.
/// </summary>
internal sealed record MonitorArea(Rect WorkArea, double Scale);

/// <summary>
/// Where an origin window sits: the frame it shows, in physical pixels, and the monitor it
/// mostly covers.
/// </summary>
internal sealed record OriginGeometry(Rect Frame, MonitorArea Monitor);

/// <summary>
/// Where toasts go (REQ-RULE-42 to REQ-RULE-44). A toast is a window whose frame sits
/// inside a transparent inset, room for the frame's shadow. The rules place frames, so they
/// take each window's size and inset in DIPs, and return each window's top-left corner in
/// physical pixels. Toasts come newest first; the newest sits nearest the edge they stack
/// from.
/// </summary>
/// <remarks>
/// <code>
///   ┌──────────────────┐  an older toast
///   └──────────────────┘
///   ┌──────────────────┐  the newest toast: as wide as the window, no gap below
///   ╞══════════════════╡  the origin window's top edge
///   │                  │
/// </code>
/// </remarks>
internal static class ToastPlacement
{
    /// <summary>
    /// How far a frame in a corner keeps from the area's top and right edges, in DIPs.
    /// </summary>
    public const double CornerInset = 16;

    /// <summary>
    /// The narrowest frame a toast on a window takes, in DIPs; a narrower window gets the
    /// toast centred over it.
    /// </summary>
    public const double NarrowestFrameOnWindow = 320;

    /// <summary>
    /// The window width, in DIPs, that gives a toast's frame the origin window's width.
    /// </summary>
    public static double WidthOnWindow(OriginGeometry origin, Thickness inset)
    {
        var scale = origin.Monitor.Scale;
        var widest = Math.Max(NarrowestFrameOnWindow, origin.Monitor.WorkArea.Width / scale);
        return Math.Clamp(origin.Frame.Width / scale, NarrowestFrameOnWindow, widest) + inset.Left + inset.Right;
    }

    /// <summary>
    /// Toasts stacked upward from the origin window's top edge, the newest touching it, or
    /// null when they do not all fit between that edge and the top of the work area.
    /// </summary>
    public static IReadOnlyList<Point>? OnWindow(OriginGeometry origin, IReadOnlyList<Size> newestFirst, Thickness inset)
    {
        var (area, scale) = (origin.Monitor.WorkArea, origin.Monitor.Scale);
        var corners = new List<Point>(newestFirst.Count);
        var frameBottom = origin.Frame.Top;
        foreach (var size in newestFirst)
        {
            var frame = FrameSize(size, inset, scale);
            var frameTop = frameBottom - frame.Height;
            if (Math.Round(frameTop) < area.Top) return null;

            var frameLeft = Math.Clamp(origin.Frame.Left + ((origin.Frame.Width - frame.Width) / 2), area.Left, Math.Max(area.Left, area.Right - frame.Width));
            corners.Add(new Point(frameLeft - (inset.Left * scale), frameTop - (inset.Top * scale)));
            frameBottom = frameTop - ((inset.Top + inset.Bottom) * scale);
        }

        return corners;
    }

    /// <summary>
    /// Toasts stacked downward from the top-right corner of the part of the origin window
    /// inside its work area, the newest in the corner: the place for a window that leaves
    /// no room above itself, such as a maximized or full-screen one.
    /// </summary>
    public static IReadOnlyList<Point> InCorner(OriginGeometry origin, IReadOnlyList<Size> newestFirst, Thickness inset)
    {
        var (area, scale) = (origin.Monitor.WorkArea, origin.Monitor.Scale);
        var visible = Rect.Intersect(origin.Frame, area);
        if (visible.IsEmpty) visible = area;

        var corners = new List<Point>(newestFirst.Count);
        var frameTop = visible.Top + (CornerInset * scale);
        foreach (var size in newestFirst)
        {
            var frameLeft = Math.Max(area.Left, visible.Right - (CornerInset * scale) - FrameSize(size, inset, scale).Width);
            corners.Add(new Point(frameLeft - (inset.Left * scale), frameTop - (inset.Top * scale)));
            frameTop += size.Height * scale;
        }

        return corners;
    }

    /// <summary>
    /// Toasts stacked upward from the bottom-right corner of the work area, the newest in
    /// the corner, just above the notification area: the place for toasts without an origin
    /// window.
    /// </summary>
    public static IReadOnlyList<Point> AboveNotificationArea(MonitorArea monitor, IReadOnlyList<Size> newestFirst)
    {
        var corners = new List<Point>(newestFirst.Count);
        var bottom = monitor.WorkArea.Bottom;
        foreach (var size in newestFirst)
        {
            var top = bottom - (size.Height * monitor.Scale);
            corners.Add(new Point(monitor.WorkArea.Right - (size.Width * monitor.Scale), top));
            bottom = top;
        }

        return corners;
    }

    private static Size FrameSize(Size window, Thickness inset, double scale) =>
        new((window.Width - inset.Left - inset.Right) * scale, (window.Height - inset.Top - inset.Bottom) * scale);
}
