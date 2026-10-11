using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Threading;
using OpWarden.Core.Management;

namespace OpWarden.SessionAgent;

/// <summary>
/// What OpWarden is doing right now: the link to the broker, what the broker reports, and
/// the last few invocations. It opens above the notification area and refreshes itself
/// while it stays open.
/// </summary>
public partial class StatusWindow : Window
{
    private const int RecentCount = 8;

    /// <summary>
    /// How far the window keeps from the work area's edges in its corner, in DIPs.
    /// </summary>
    private const double CornerGap = 12;

    private readonly ManagementClient _management;
    private readonly Action _openAuditLog;
    private readonly Action _openRules;
    private readonly Func<Task> _flushCache;
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromSeconds(5) };
    private readonly RecentInvocations _recent = new(RecentCount);
    private AuditLogReader? _audit;
    private string? _dataDirectory;

    // In the corner above the notification area until the user moves the window.
    private bool _inCorner = true;
    private bool _moving;

    internal StatusWindow(ManagementClient management, BrokerLink link, Action openAuditLog, Action openRules, Func<Task> flushCache)
    {
        InitializeComponent();
        (_management, _openAuditLog, _openRules, _flushCache) = (management, openAuditLog, openRules, flushCache);
        ShowLink(link);
        Loaded += (_, _) =>
        {
            Place();
            LocationChanged += (_, _) =>
            {
                if (!_moving) _inCorner = false;
            };
            Refresh();
        };
        // SizeChanged comes before WPF resizes the window to its new content, so the window
        // is placed once that has happened, not on the stale size.
        SizeChanged += (_, _) => _ = Dispatcher.InvokeAsync(Place, DispatcherPriority.Loaded);
        _refresh.Tick += (_, _) => Refresh();
        _refresh.Start();
        Closed += (_, _) => _refresh.Stop();
        WindowTheme.Follow(this);
        UiCapture.WhenRequested(this, "status");
    }

    internal void ShowLink(BrokerLink link)
    {
        LinkText.Text = link.Description;
        LinkGlyph.SetResourceReference(System.Windows.Shapes.Shape.FillProperty, link.BrushKey);
    }

    internal async void Refresh()
    {
        var response = await _management.TrySendAsync(new GetStatus()).ConfigureAwait(true);
        if (response.Status is not { } status)
        {
            ErrorText.Text = response.Error ?? "The broker sent no status.";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        ErrorText.Visibility = Visibility.Collapsed;
        _dataDirectory = status.DataDirectory;
        AccountText.Text = status.Account;
        EventsText.Text = status.ProcessEventsAvailable ? "Flowing" : "Unavailable: callers behind MSYS2 shells resolve as unknown";
        CacheText.Text = status.CacheEntries.ToString(CultureInfo.CurrentCulture);
        FlushButton.IsEnabled = status.CacheEntries > 0;
        StartedText.Text = $"{status.StartedAt.ToLocalTime():yyyy-MM-dd HH:mm} (version {status.Version})";
        DataText.Text = status.DataDirectory;
        DataText.ToolTip = status.DataDirectory;

        // One reader for the window's life: each refresh reads only what the broker appended.
        _audit ??= new AuditLogReader(Path.Combine(status.DataDirectory, "audit.jsonl"));
        try
        {
            _recent.Add(_audit.ReadNew());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            ErrorText.Text = $"The audit log cannot be read: {e.Message}";
            ErrorText.Visibility = Visibility.Visible;
        }

        RecentList.ItemsSource = _recent.NewestFirst;
        RecentSummaryText.Text = _recent.Summary;
    }

    /// <summary>
    /// Where the window's frame goes, in physical pixels: in the corner above the
    /// notification area while it stays there, and otherwise where it is, moved back inside
    /// the work area when it would leave it. A window taller than the work area keeps its
    /// title bar on screen.
    /// </summary>
    internal static Point FrameTopLeft(Rect frame, MonitorArea monitor, bool inCorner, double cornerGap)
    {
        var area = monitor.WorkArea;
        var gap = cornerGap * monitor.Scale;
        var (x, y) = inCorner ? (area.Right - frame.Width - gap, area.Bottom - frame.Height - gap) : (frame.X, frame.Y);
        return new Point(Math.Max(area.Left, Math.Min(x, area.Right - frame.Width)), Math.Max(area.Top, Math.Min(y, area.Bottom - frame.Height)));
    }

    /// <summary>
    /// Keeps the window in the corner above the notification area until the user moves it,
    /// and inside the work area of its monitor after that. The recent invocations arrive
    /// after the window opens, so it grows upward as they fill in, never under the taskbar.
    /// </summary>
    private void Place()
    {
        var handle = new WindowInteropHelper(this).Handle;
        if (!IsLoaded || Native.VisibleFrameOf(handle) is not { } frame || Native.WindowRectOf(handle) is not { } window) return;

        var monitor = _inCorner ? Native.PrimaryMonitorArea() : Native.MonitorAreaOf(handle);
        var target = FrameTopLeft(frame, monitor, _inCorner, CornerGap);
        _moving = true;
        try
        {
            Native.MoveWindow(handle, window.TopLeft + (target - frame.TopLeft));
        }
        finally
        {
            _moving = false;
        }
    }

    private async void OnFlushClick(object sender, RoutedEventArgs e) => await _flushCache().ConfigureAwait(true);

    private void OnOpenDataClick(object sender, RoutedEventArgs e)
    {
        if (_dataDirectory is null) return;
        using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_dataDirectory}\"") { UseShellExecute = true });
    }

    private void OnAuditClick(object sender, RoutedEventArgs e) => _openAuditLog();

    private void OnRulesClick(object sender, RoutedEventArgs e) => _openRules();
}

/// <summary>
/// One line of the status window's recent invocations.
/// </summary>
public sealed record RecentInvocation(DateTimeOffset Timestamp, string Caller, string Secret, string Outcome)
{
    public static RecentInvocation From(AuditRow row) =>
        new(row.Timestamp, row.Caller, row.Secret.Length > 0 ? row.Secret : row.ArgumentsText, $"{row.Verdict.ToLowerInvariant()} ({row.Reason})");
}

/// <summary>
/// The status window's last few invocations and how many the audit log holds in all, kept
/// up to date from the entries the audit reader hands over.
/// </summary>
internal sealed class RecentInvocations(int capacity)
{
    private readonly Queue<RecentInvocation> _newestLast = new();

    public int Total { get; private set; }

    public IReadOnlyList<RecentInvocation> NewestFirst => [.. _newestLast.Reverse()];

    /// <summary>
    /// What the list leaves out, or nothing when it shows every invocation.
    /// </summary>
    public string Summary => Total > capacity ? string.Format(CultureInfo.CurrentCulture, "Showing the last {0} of {1:N0} invocations.", capacity, Total) : "";

    public void Add(IEnumerable<AuditRow> rows)
    {
        foreach (var row in rows.Where(r => r.Event == "invocation"))
        {
            Total++;
            _newestLast.Enqueue(RecentInvocation.From(row));
            if (_newestLast.Count > capacity) _newestLast.Dequeue();
        }
    }
}

/// <summary>
/// Shows a UTC timestamp in local time.
/// </summary>
public sealed class LocalTime : IValueConverter
{
    public static LocalTime Converter { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is DateTimeOffset at ? at.ToLocalTime().DateTime : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
