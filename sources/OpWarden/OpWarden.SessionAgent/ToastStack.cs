using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// Shows the toasts and keeps them in place: a read's toasts sit on the window the read
/// came from, the rest stack upward from the corner above the notification area, newest
/// nearest the edge, a few at most (REQ-RULE-41 to REQ-RULE-46).
/// </summary>
internal sealed class ToastStack
{
    private const int MaxOpen = 4;

    // ceiling: polling, which treats every kind of window alike, a console window too (it
    // names its shell as owner while conhost runs it). It runs only while a toast has an
    // origin window, when the countdown animation renders a frame every 16 ms anyway. A
    // WinEvent hook on location changes is the upgrade if a toast trailing a dragged
    // window by up to 30 ms ever shows.
    private static readonly TimeSpan FollowInterval = TimeSpan.FromMilliseconds(30);

    private readonly Action _openAuditLog;
    private readonly List<ToastWindow> _open = [];
    private readonly DispatcherTimer _follow;

    // Where each origin window sat when its toasts were last placed; null while it could
    // hold none (REQ-RULE-45).
    private readonly Dictionary<nint, OriginGeometry?> _placedOn = [];
    private bool _placing;

    public ToastStack(Action openAuditLog)
    {
        _openAuditLog = openAuditLog;
        _follow = new DispatcherTimer { Interval = FollowInterval };
        _follow.Tick += (_, _) => Follow();
    }

    /// <summary>
    /// Shows a read, folding it into the newest toast from the same window when it
    /// continues that burst (REQ-RULE-39).
    /// </summary>
    public void ShowRead(ReadAllowed read)
    {
        var origin = OriginWindow.Find(read.Ancestors);
        if (_open.LastOrDefault(t => t.Read is not null && t.Origin == origin) is { Read: { } current } toast && current.Absorb(read) is { } merged)
        {
            toast.ShowRead(merged);
            return;
        }

        var window = new ToastWindow(_openAuditLog) { Origin = origin };
        window.ShowRead(ReadToast.Start(read));
        Open(window);
    }

    public void ShowNotice(ShowNotice notice)
    {
        var window = new ToastWindow(_openAuditLog);
        window.ShowNotice(notice);
        Open(window);
    }

    private void Open(ToastWindow toast)
    {
        toast.Closed += (_, _) =>
        {
            _open.Remove(toast);
            Place();
        };
        toast.SizeChanged += (_, _) => Place();
        _open.Add(toast);
        while (_open.Count > MaxOpen) _open[0].Close();

        // Off screen until it has a size to place it by.
        toast.Left = SystemParameters.VirtualScreenLeft - 10_000;
        toast.Show();
        Native.PlayNotificationSound();
        Place();
    }

    /// <summary>
    /// Places the toasts again when an origin window moved, changed size, or came or went
    /// from view since the last placement.
    /// </summary>
    private void Follow()
    {
        foreach (var origin in _open.Select(t => t.Origin).Where(o => o != 0).Distinct())
        {
            if (Equals(GeometryOf(origin), _placedOn.GetValueOrDefault(origin))) continue;
            Place();
            return;
        }
    }

    private void Place()
    {
        // Measuring and moving toasts resizes them, which calls back here.
        if (_placing) return;
        _placing = true;
        try
        {
            _placedOn.Clear();
            var unplaced = new List<ToastWindow>();
            foreach (var group in _open.GroupBy(t => t.Origin))
            {
                var newestFirst = group.Reverse().ToList();
                OriginGeometry? origin = null;
                if (group.Key != 0) _placedOn[group.Key] = origin = GeometryOf(group.Key);
                if (origin is not null) PlaceOn(origin, newestFirst);
                else unplaced.AddRange(newestFirst);
            }

            PlaceAboveNotificationArea([.. unplaced.OrderByDescending(t => _open.IndexOf(t))]);
            _follow.IsEnabled = _placedOn.Count > 0;
        }
        finally
        {
            _placing = false;
        }
    }

    /// <summary>
    /// Puts one window's toasts on its top edge, at its width, or in its top-right corner
    /// when they do not fit above it (REQ-RULE-42, REQ-RULE-43). Whether they fit is worked
    /// out at the width they would take before any toast is resized, so a toast that stays
    /// in the corner never flickers through the window's width.
    /// </summary>
    private static void PlaceOn(OriginGeometry origin, List<ToastWindow> newestFirst)
    {
        var inset = newestFirst[0].FrameInset;
        var widthOnWindow = ToastPlacement.WidthOnWindow(origin, inset);
        var fits = ToastPlacement.OnWindow(origin, [.. newestFirst.Select(t => t.SizeAt(widthOnWindow))], inset) is not null;
        var sizes = Measure(newestFirst, fits ? widthOnWindow : ToastWindow.StandardWidth);
        var onWindow = fits ? ToastPlacement.OnWindow(origin, sizes, inset) : null;
        var corners = onWindow ?? ToastPlacement.InCorner(origin, sizes, inset);
        for (var i = 0; i < newestFirst.Count; i++)
        {
            newestFirst[i].SitsOnWindow = onWindow is not null && i == 0;
            Native.MoveWindow(HandleOf(newestFirst[i]), corners[i]);
        }
    }

    /// <summary>
    /// Stacks toasts without a usable origin window above the notification area (REQ-RULE-44).
    /// </summary>
    private static void PlaceAboveNotificationArea(List<ToastWindow> newestFirst)
    {
        if (newestFirst.Count == 0) return;
        var corners = ToastPlacement.AboveNotificationArea(Native.PrimaryMonitorArea(), Measure(newestFirst, ToastWindow.StandardWidth));
        for (var i = 0; i < newestFirst.Count; i++)
        {
            newestFirst[i].SitsOnWindow = false;
            Native.MoveWindow(HandleOf(newestFirst[i]), corners[i]);
        }
    }

    /// <summary>
    /// Gives each toast a width and returns the sizes the toasts then take, in DIPs.
    /// </summary>
    private static List<Size> Measure(List<ToastWindow> toasts, double width)
    {
        foreach (var toast in toasts) toast.Width = width;
        return [.. toasts.Select(t =>
        {
            t.UpdateLayout();
            return new Size(t.ActualWidth, t.ActualHeight);
        })];
    }

    /// <summary>
    /// Where an origin window sits now, or null when no toast can sit on it: the window is
    /// gone, minimized, hidden, or on another virtual desktop (REQ-RULE-44, REQ-RULE-45).
    /// </summary>
    private static OriginGeometry? GeometryOf(nint window) =>
        Native.IsWindow(window) && Native.IsWindowVisible(window) && !Native.IsIconic(window) && !Native.IsCloaked(window) && Native.VisibleFrameOf(window) is { } frame
            ? new OriginGeometry(frame, Native.MonitorAreaOf(window))
            : null;

    private static nint HandleOf(Window toast) => new WindowInteropHelper(toast).Handle;
}
