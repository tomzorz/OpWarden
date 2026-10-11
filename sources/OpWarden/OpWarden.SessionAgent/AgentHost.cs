using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using OpWarden.Core.Agent;
using OpWarden.Core.Management;

namespace OpWarden.SessionAgent;

public enum LinkState
{
    Waiting,
    Connected,
    Refused,
}

/// <summary>
/// How the session agent stands with the broker.
/// </summary>
public sealed record BrokerLink(LinkState State, string? Reason = null)
{
    public static BrokerLink Waiting { get; } = new(LinkState.Waiting);

    public static BrokerLink Connected { get; } = new(LinkState.Connected);

    public static BrokerLink Refused(string reason) => new(LinkState.Refused, reason);

    public string Description => State switch
    {
        LinkState.Connected => "Connected to the broker",
        LinkState.Refused => $"Refused by the broker: {Reason}",
        _ => "Waiting for the broker",
    };
}

/// <summary>
/// The session agent at work: the broker connection, the tray icon and its menu, the
/// prompt, the toasts, and the windows the menu opens. Everything here runs on the UI
/// thread; the connection hands its messages over through the dispatcher.
/// </summary>
internal sealed class AgentHost : IDisposable
{
    private readonly App _app;
    private readonly AgentOptions _options;
    private readonly AgentConnection _connection;
    private readonly ManagementClient _management;
    private readonly ToastStack _toasts;
    private readonly CancellationTokenSource _stopping = new();
    private TrayIcon? _tray;
    private Task? _connectionLoop;
    private PromptWindow? _prompt;
    private StatusWindow? _status;
    private AuditWindow? _audit;
    private RulesWindow? _rules;
    private BrokerLink _link = BrokerLink.Waiting;

    public AgentHost(App app, AgentOptions options)
    {
        (_app, _options) = (app, options);
        _management = new ManagementClient(options.ManagementPipe);
        _toasts = new ToastStack(OpenAuditLog);
        _connection = new AgentConnection(
            options.AgentPipe,
            message => _app.Dispatcher.InvokeAsync(() => Handle(message)),
            connected => _app.Dispatcher.InvokeAsync(() => OnConnectionChanged(connected)));
    }

    public void Start()
    {
        _tray = new TrayIcon();
        _tray.Clicked += OpenStatus;
        _tray.MenuRequested += ShowMenu;
        _tray.WorkstationLocked += () => _connection.Send(new WorkstationLocked());
        _tray.ThemeChanged += () =>
        {
            Theme.Refresh(_app);
            foreach (Window window in _app.Windows) WindowTheme.Apply(window);
            ShowLink();
        };
        ShowLink();
        _connectionLoop = Task.Run(() => _connection.RunAsync(_stopping.Token));

        foreach (var window in _options.Open)
        {
            Action open = window switch
            {
                "status" => OpenStatus,
                "audit" => OpenAuditLog,
                "rules" => OpenRules,
                _ => () => AgentLog.Write($"--open {window}: no such window; status, audit and rules are"),
            };
            open();
        }
    }

    public void Dispose()
    {
        _stopping.Cancel();
        _connectionLoop?.Wait(TimeSpan.FromSeconds(2));
        _tray?.Dispose();
        _stopping.Dispose();
    }

    private void Handle(AgentMessage message)
    {
        switch (message)
        {
            // The broker resends the prompt on screen when the agent reconnects.
            case ShowPrompt show when _prompt?.PromptId == show.PromptId:
                break;
            case ShowPrompt show:
                DismissPrompt();
                _prompt = new PromptWindow(show, _connection.Send);
                _prompt.Show();
                break;
            case ClosePrompt close when _prompt?.PromptId == close.PromptId:
                DismissPrompt();
                break;
            case ShowNotice notice:
                _toasts.ShowNotice(notice);
                break;
            case ReadAllowed read:
                _toasts.ShowRead(read);
                break;
            case AgentRefused refused:
                _link = BrokerLink.Refused(refused.Reason);
                ShowLink();
                break;
        }
    }

    private void OnConnectionChanged(bool connected)
    {
        if (connected)
        {
            _link = BrokerLink.Connected;
        }
        else
        {
            // A refusal outlives the disconnect that follows it; a broker that went away
            // took its prompt with it.
            if (_link.State != LinkState.Refused) _link = BrokerLink.Waiting;
            DismissPrompt();
        }

        ShowLink();
    }

    private void DismissPrompt()
    {
        _prompt?.CloseForBroker();
        _prompt = null;
    }

    private void ShowLink()
    {
        var color = _app.TryFindResource(BrokerLinkGlyph.BrushKeyFor(_link.State)) is SolidColorBrush brush ? brush.Color : Colors.Gray;
        _tray?.Show(color, $"OpWarden: {_link.Description}");
        _status?.ShowLink(_link);
    }

    private void ShowMenu()
    {
        var menu = new ContextMenu { Placement = PlacementMode.MousePoint };
        menu.Items.Add(MenuEntry("Status", OpenStatus));
        menu.Items.Add(MenuEntry("Audit log", OpenAuditLog));
        menu.Items.Add(MenuEntry("Rules", OpenRules));
        menu.Items.Add(new Separator());
        menu.Items.Add(MenuEntry("Flush cache", () => _ = FlushCacheAsync()));

        // Without the foreground, a tray menu stays open after a click elsewhere.
        menu.Opened += (_, _) =>
        {
            if (PresentationSource.FromVisual(menu) is HwndSource source) Native.SetForegroundWindow(source.Handle);
        };
        menu.IsOpen = true;
    }

    private static MenuItem MenuEntry(string header, Action act)
    {
        var item = new MenuItem { Header = header };
        item.Click += (_, _) => act();
        return item;
    }

    private void OpenStatus()
    {
        if (Reopen(_status)) return;
        _status = new StatusWindow(_management, _link, OpenAuditLog, OpenRules, FlushCacheAsync);
        _status.Closed += (_, _) => _status = null;
        _status.Show();
        _status.Activate();
    }

    private void OpenAuditLog()
    {
        if (Reopen(_audit)) return;
        _audit = new AuditWindow(_management);
        _audit.Closed += (_, _) => _audit = null;
        _audit.Show();
        _audit.Activate();
    }

    private void OpenRules()
    {
        if (Reopen(_rules)) return;
        _rules = new RulesWindow(_management, _options);
        _rules.Closed += (_, _) => _rules = null;
        _rules.Show();
        _rules.Activate();
    }

    private static bool Reopen(Window? window)
    {
        if (window is null) return false;
        if (window.WindowState == WindowState.Minimized) window.WindowState = WindowState.Normal;
        window.Activate();
        return true;
    }

    /// <summary>
    /// Empties the cache (REQ-CACHE-8) and says how it went.
    /// </summary>
    private async Task FlushCacheAsync()
    {
        var response = await _management.TrySendAsync(new FlushCache()).ConfigureAwait(true);
        var outcome = response.Error ?? (response.Flushed == 1 ? "Deleted 1 cached value." : $"Deleted {response.Flushed ?? 0} cached values.");
        _toasts.ShowNotice(new ShowNotice("OpWarden cache", outcome));
        _status?.Refresh();
    }
}
