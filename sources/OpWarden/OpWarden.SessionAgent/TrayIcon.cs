using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using static OpWarden.SessionAgent.Native;

namespace OpWarden.SessionAgent;

/// <summary>
/// The notification-area icon, and the hidden window that hears what the icon, the
/// session and Windows' theme have to say.
/// </summary>
/// <remarks>
/// The window is a hidden top-level one, not message-only: message-only windows miss the
/// WM_SETTINGCHANGE broadcast that announces a theme change. Explorer forgets every icon
/// when it restarts and says so with "TaskbarCreated", which puts this one back.
/// </remarks>
internal sealed unsafe class TrayIcon : IDisposable
{
    private const uint CallbackMessage = WM_APP + 2;
    private const uint IconId = 1;

    private static readonly uint TaskbarCreated = RegisterWindowMessageW("TaskbarCreated");

    private readonly HwndSource _window;
    private nint _icon;
    private string _tip = "OpWarden";
    private bool _added;

    public TrayIcon()
    {
        _window = new HwndSource(new HwndSourceParameters("OpWarden session agent") { WindowStyle = 0, Width = 0, Height = 0 });
        _window.AddHook(OnMessage);

        // REQ-CACHE-7: the broker flushes the cache when this session locks.
        if (!WTSRegisterSessionNotification(_window.Handle, NOTIFY_FOR_THIS_SESSION)) AgentLog.Write("could not subscribe to session lock events; the cache will not flush on lock");
    }

    public event Action? Clicked;

    public event Action? MenuRequested;

    public event Action? WorkstationLocked;

    public event Action? ThemeChanged;

    /// <summary>
    /// The hidden window, which the tray menu must own the foreground through.
    /// </summary>
    public nint Handle => _window.Handle;

    /// <summary>
    /// Shows the icon in <paramref name="color"/> with <paramref name="tip"/> as its tooltip.
    /// </summary>
    public void Show(Color color, string tip)
    {
        var previous = _icon;
        _icon = TrayGlyph.Create(color);
        _tip = tip;
        Apply(_added ? NIM_MODIFY : NIM_ADD);
        _added = true;
        if (previous != 0) DestroyIcon(previous);
    }

    public void Dispose()
    {
        WTSUnRegisterSessionNotification(_window.Handle);
        if (_added) Apply(NIM_DELETE);
        if (_icon != 0) DestroyIcon(_icon);
        _window.Dispose();
    }

    private void Apply(uint action)
    {
        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)sizeof(NOTIFYICONDATAW),
            hWnd = _window.Handle,
            uID = IconId,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = CallbackMessage,
            hIcon = _icon,
        };
        CopyTo(_tip, data.szTip, 128);
        Shell_NotifyIconW(action, &data);
    }

    private nint OnMessage(nint hwnd, int message, nint wParam, nint lParam, ref bool handled)
    {
        var id = (uint)message;
        if (id == CallbackMessage)
        {
            switch ((uint)lParam)
            {
                case WM_LBUTTONUP:
                    Clicked?.Invoke();
                    break;
                case WM_RBUTTONUP or WM_CONTEXTMENU:
                    MenuRequested?.Invoke();
                    break;
            }

            handled = true;
        }
        else if (id == WM_WTSSESSION_CHANGE && wParam == WTS_SESSION_LOCK)
        {
            WorkstationLocked?.Invoke();
        }
        else if (id == WM_SETTINGCHANGE && lParam != 0 && Marshal.PtrToStringUni(lParam) == "ImmersiveColorSet")
        {
            ThemeChanged?.Invoke();
        }
        else if (id == TaskbarCreated && _added)
        {
            Apply(NIM_ADD);
        }

        return 0;
    }
}

/// <summary>
/// The tray icon's picture: a shield in the colour of the broker's state, rendered at the
/// size Windows draws small icons, so it stays sharp at every scale.
/// </summary>
internal static class TrayGlyph
{
    private static readonly Geometry Shield = Geometry.Parse("M 8,0.8 L 14.6,3.3 L 14.6,8 C 14.6,11.9 11.8,14.6 8,15.4 C 4.2,14.6 1.4,11.9 1.4,8 L 1.4,3.3 Z");
    private static readonly Geometry Keyhole = Geometry.Parse("M 8,5 A 1.7,1.7 0 1 1 7.99,5 Z M 7.2,7.6 L 8.8,7.6 L 9.2,11 L 6.8,11 Z");

    public static nint Create(Color color)
    {
        var size = GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem());
        var visual = new DrawingVisual();
        using (var drawing = visual.RenderOpen())
        {
            drawing.PushTransform(new ScaleTransform(size / 16.0, size / 16.0));
            drawing.DrawGeometry(new SolidColorBrush(color), null, Shield);
            drawing.DrawGeometry(Brushes.White, null, Keyhole);
            drawing.Pop();
        }

        var rendered = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        rendered.Render(visual);

        // Icons want straight alpha; the renderer produces premultiplied.
        var straight = new FormatConvertedBitmap(rendered, PixelFormats.Bgra32, null, 0);
        var pixels = new byte[size * size * 4];
        straight.CopyPixels(pixels, size * 4, 0);
        return CreateIcon(size, pixels);
    }
}
