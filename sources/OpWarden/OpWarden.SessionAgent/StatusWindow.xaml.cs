using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Data;
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

    private readonly ManagementClient _management;
    private readonly Action _openAuditLog;
    private readonly Action _openRules;
    private readonly Func<Task> _flushCache;
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromSeconds(5) };
    private string? _dataDirectory;

    internal StatusWindow(ManagementClient management, BrokerLink link, Action openAuditLog, Action openRules, Func<Task> flushCache)
    {
        InitializeComponent();
        (_management, _openAuditLog, _openRules, _flushCache) = (management, openAuditLog, openRules, flushCache);
        ShowLink(link);
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - ActualWidth - 12;
            Top = area.Bottom - ActualHeight - 12;
            Refresh();
        };
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
        RecentList.ItemsSource = RecentInvocations(status.DataDirectory);
    }

    private static IReadOnlyList<RecentInvocation> RecentInvocations(string dataDirectory)
    {
        try
        {
            return [.. new AuditLogReader(Path.Combine(dataDirectory, "audit.jsonl")).ReadNew()
                .Where(row => row.Event == "invocation")
                .TakeLast(RecentCount)
                .Reverse()
                .Select(row => new RecentInvocation(row.Timestamp, row.Caller, row.Secret.Length > 0 ? row.Secret : row.ArgumentsText, $"{row.Verdict.ToLowerInvariant()} ({row.Reason})"))];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
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
public sealed record RecentInvocation(DateTimeOffset Timestamp, string Caller, string Secret, string Outcome);

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
