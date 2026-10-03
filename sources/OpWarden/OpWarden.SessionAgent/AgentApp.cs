using System.Collections.Concurrent;
using OpWarden.Core.Agent;
using static OpWarden.SessionAgent.Native;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent's UI thread: a hidden host window that receives broker messages
/// from the connection thread, the tray icon, and at most one prompt window.
/// </summary>
internal sealed unsafe class AgentApp : Window
{
    private const string HostClass = "OpWardenAgentHost";
    private const uint WmAgentMessage = WM_APP + 1, WmTray = WM_APP + 2, WmConnection = WM_APP + 3;
    private const uint TrayId = 1;
    private const nuint ExitCommand = 1;

    private readonly ConcurrentQueue<AgentMessage> _inbox = new();
    private readonly AgentConnection _connection;
    private PromptWindow? _prompt;
    private bool _connected;

    public AgentApp(string pipeName)
    {
        _connection = new AgentConnection(
            pipeName,
            message =>
            {
                _inbox.Enqueue(message);
                PostMessageW(Handle, WmAgentMessage, 0, 0);
            },
            connected => PostMessageW(Handle, WmConnection, connected ? 1 : 0, 0));
    }

    public int Run()
    {
        RegisterClass(HostClass, 0);
        RegisterClass(PromptWindow.ClassName, COLOR_WINDOW + 1);
        Create(HostClass, 0, "OpWarden session agent", 0, 0, 0, 0, 0);
        UpdateTray(NIM_ADD);

        // REQ-CACHE-7: the broker flushes the cache when this session locks.
        if (!WTSRegisterSessionNotification(Handle, NOTIFY_FOR_THIS_SESSION)) AgentLog.Write("could not subscribe to session lock events; the cache will not flush on lock");

        using var stopping = new CancellationTokenSource();
        var connection = Task.Run(() => _connection.RunAsync(stopping.Token));

        MSG message;
        while (GetMessageW(&message, 0, 0, 0) > 0)
        {
            // Tab and Esc inside the prompt.
            if (_prompt is not null && IsDialogMessageW(_prompt.Handle, &message)) continue;
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        stopping.Cancel();
        connection.Wait(TimeSpan.FromSeconds(2));
        return 0;
    }

    protected override nint? OnMessage(uint message, nint wParam, nint lParam)
    {
        switch (message)
        {
            case WmAgentMessage:
                while (_inbox.TryDequeue(out var received)) Dispatch(received);
                return 0;
            case WmConnection:
                _connected = wParam != 0;
                UpdateTray(NIM_MODIFY);

                // A broker that went away took its prompt with it.
                if (!_connected) DismissPrompt();
                return 0;
            case WM_WTSSESSION_CHANGE when wParam == WTS_SESSION_LOCK:
                _connection.Send(new WorkstationLocked());
                return 0;
            case WmTray when (uint)lParam is WM_RBUTTONUP or WM_CONTEXTMENU:
                ShowTrayMenu();
                return 0;
            case WM_DESTROY:
                WTSUnRegisterSessionNotification(Handle);
                UpdateTray(NIM_DELETE);
                PostQuitMessage(0);
                return 0;
            default:
                return null;
        }
    }

    private void Dispatch(AgentMessage message)
    {
        switch (message)
        {
            // The broker can resend the prompt on screen when the agent reconnects.
            case ShowPrompt show when _prompt?.PromptId == show.PromptId:
                break;
            case ShowPrompt show:
                DismissPrompt();
                _prompt = new PromptWindow(show, _connection.Send);
                break;
            case ClosePrompt close when _prompt?.PromptId == close.PromptId:
                DismissPrompt();
                break;
            case ShowNotice notice:
                Balloon(notice.Title, notice.Text);
                break;
        }
    }

    private void DismissPrompt()
    {
        if (_prompt is null) return;
        DestroyWindow(_prompt.Handle);
        _prompt = null;
    }

    private void UpdateTray(uint action)
    {
        var data = TrayData(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        CopyTo(_connected ? "OpWarden: connected to the broker" : "OpWarden: waiting for the broker", data.szTip, 128);
        Shell_NotifyIconW(action, &data);
    }

    private void Balloon(string title, string text)
    {
        var data = TrayData(NIF_INFO);
        data.dwInfoFlags = NIIF_INFO;
        CopyTo(title, data.szInfoTitle, 64);
        CopyTo(text, data.szInfo, 256);
        Shell_NotifyIconW(NIM_MODIFY, &data);
    }

    private NOTIFYICONDATAW TrayData(uint flags) => new()
    {
        cbSize = (uint)sizeof(NOTIFYICONDATAW),
        hWnd = Handle,
        uID = TrayId,
        uFlags = flags,
        uCallbackMessage = WmTray,
        hIcon = LoadIconW(0, IDI_SHIELD),
    };

    private void ShowTrayMenu()
    {
        var menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, ExitCommand, "Exit OpWarden session agent");
        POINT cursor;
        GetCursorPos(&cursor);

        // Without this the menu does not close when the user clicks elsewhere.
        SetForegroundWindow(Handle);
        var command = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD, cursor.X, cursor.Y, 0, Handle, 0);
        DestroyMenu(menu);
        if ((nuint)command == ExitCommand) DestroyWindow(Handle);
    }
}
