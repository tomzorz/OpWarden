using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using OpWarden.Core.Management;

namespace OpWarden.SessionAgent;

/// <summary>
/// The audit log, newest first, following new entries as the broker appends them. The
/// session agent reads the file itself, which REQ-TRUST-2 allows; the broker only says
/// where it is.
/// </summary>
public partial class AuditWindow : StandardWindow
{
    // ceiling: keeps the newest few thousand rows in memory; page through the file if
    // anyone needs months of history on screen.
    private const int MaxRows = 5000;

    private readonly ManagementClient _management;
    private readonly DispatcherTimer _follow = new() { Interval = TimeSpan.FromSeconds(1) };
    private ObservableCollection<AuditRow> _rows = [];
    private ICollectionView? _view;
    private AuditLogReader? _reader;

    internal AuditWindow(ManagementClient management)
    {
        InitializeComponent();
        _management = management;
        FilterBox.TextChanged += (_, _) => Refilter();
        ProblemsOnly.Checked += (_, _) => Refilter();
        ProblemsOnly.Unchecked += (_, _) => Refilter();
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
        _follow.Tick += (_, _) => Follow();
        Closed += (_, _) => _follow.Stop();
        UiCapture.WhenRequested(this, "audit");
    }

    private async Task LoadAsync()
    {
        var response = await _management.TrySendAsync(new GetStatus()).ConfigureAwait(true);
        if (response.Status is not { } status)
        {
            SummaryText.Text = response.Error ?? "The broker did not say where its audit log is.";
            return;
        }

        _reader = new AuditLogReader(Path.Combine(status.DataDirectory, "audit.jsonl"));
        if (Read() is not { } initial) return;

        // All at once: adding thousands of rows one by one re-sorts the view each time.
        _rows = new ObservableCollection<AuditRow>(initial.TakeLast(MaxRows));
        _view = CollectionViewSource.GetDefaultView(_rows);
        _view.SortDescriptions.Add(new SortDescription(nameof(AuditRow.Timestamp), ListSortDirection.Descending));
        _view.Filter = row => Shows((AuditRow)row);
        Records.ItemsSource = _view;
        Summarize();
        _follow.Start();
    }

    private void Follow()
    {
        if (Read() is not { Count: > 0 } appended) return;
        foreach (var row in appended) _rows.Add(row);
        while (_rows.Count > MaxRows) _rows.RemoveAt(0);
        Summarize();
    }

    private IReadOnlyList<AuditRow>? Read()
    {
        try
        {
            return _reader?.ReadNew();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            SummaryText.Text = $"Cannot read {_reader?.FilePath}: {e.Message}";
            return null;
        }
    }

    private bool Shows(AuditRow row) => (ProblemsOnly.IsChecked != true || row.IsProblem) && row.Matches(FilterBox.Text.Trim());

    private void Refilter()
    {
        _view?.Refresh();
        Summarize();
    }

    private void Summarize()
    {
        var shown = _view?.Cast<object>().Count() ?? 0;
        SummaryText.Text = shown == _rows.Count ? $"{_rows.Count} entries" : $"{shown} of {_rows.Count} entries";
    }

    private void OnOpenFolderClick(object sender, RoutedEventArgs e)
    {
        if (_reader is null) return;
        using var _ = Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_reader.FilePath}\"") { UseShellExecute = true });
    }
}
