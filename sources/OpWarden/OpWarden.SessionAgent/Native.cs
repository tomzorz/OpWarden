using System.Runtime.InteropServices;
using System.Windows;
using Microsoft.Win32.SafeHandles;

namespace OpWarden.SessionAgent;

/// <summary>
/// The Win32 calls WPF does not cover: the notification-area icon, session lock events,
/// turning a rendered glyph into an icon handle, other processes' windows and the monitors
/// they sit on, and the notification sound.
/// </summary>
/// <remarks>
/// The agent is per-monitor DPI aware (app.manifest), so every coordinate here is in
/// physical pixels.
/// </remarks>
internal static unsafe partial class Native
{
    public const uint WM_SETTINGCHANGE = 0x001A, WM_CONTEXTMENU = 0x007B, WM_LBUTTONUP = 0x0202, WM_RBUTTONUP = 0x0205, WM_APP = 0x8000;
    public const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIF_MESSAGE = 1, NIF_ICON = 2, NIF_TIP = 4;
    public const uint WM_WTSSESSION_CHANGE = 0x02B1, NOTIFY_FOR_THIS_SESSION = 0;
    public const nint WTS_SESSION_LOCK = 0x7;
    public const int SM_CXSMICON = 49;

    private const int GWL_EXSTYLE = -20, WS_EX_TOOLWINDOW = 0x80;
    private const uint GW_OWNER = 4;
    private const int DWMWA_EXTENDED_FRAME_BOUNDS = 9, DWMWA_CLOAKED = 14;
    private const uint MONITOR_DEFAULTTOPRIMARY = 1, MONITOR_DEFAULTTONEAREST = 2;
    private const int MDT_EFFECTIVE_DPI = 0;
    private const uint SWP_NOSIZE = 0x1, SWP_NOZORDER = 0x4, SWP_NOACTIVATE = 0x10;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SND_ASYNC = 0x1, SND_NODEFAULT = 0x2, SND_ALIAS = 0x10000, SND_SYSTEM = 0x200000;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;

        public readonly Rect ToRect() => new(Left, Top, Right - Left, Bottom - Top);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X, Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public uint cbSize;
        public RECT rcMonitor, rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public nint hWnd;
        public uint uID, uFlags, uCallbackMessage;
        public nint hIcon;
        public fixed char szTip[128];
        public uint dwState, dwStateMask;
        public fixed char szInfo[256];
        public uint uVersion;
        public fixed char szInfoTitle[64];
        public uint dwInfoFlags;
        public Guid guidItem;
        public nint hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        public int fIcon;
        public uint xHotspot, yHotspot;
        public nint hbmMask, hbmColor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPV5HEADER
    {
        public uint bV5Size;
        public int bV5Width, bV5Height;
        public ushort bV5Planes, bV5BitCount;
        public uint bV5Compression, bV5SizeImage;
        public int bV5XPelsPerMeter, bV5YPelsPerMeter;
        public uint bV5ClrUsed, bV5ClrImportant, bV5RedMask, bV5GreenMask, bV5BlueMask, bV5AlphaMask, bV5CSType;
        public fixed int bV5Endpoints[9];
        public uint bV5GammaRed, bV5GammaGreen, bV5GammaBlue, bV5Intent, bV5ProfileData, bV5ProfileSize, bV5Reserved;
    }

    [LibraryImport("shell32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool Shell_NotifyIconW(uint message, NOTIFYICONDATAW* data);
    [LibraryImport("wtsapi32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool WTSRegisterSessionNotification(nint hwnd, uint flags);
    [LibraryImport("wtsapi32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool WTSUnRegisterSessionNotification(nint hwnd);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] public static partial uint RegisterWindowMessageW(string name);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetForegroundWindow(nint hwnd);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool DestroyIcon(nint icon);
    [LibraryImport("user32.dll")] public static partial uint GetDpiForSystem();
    [LibraryImport("user32.dll")] public static partial int GetSystemMetricsForDpi(int index, uint dpi);
    [LibraryImport("user32.dll")] private static partial nint CreateIconIndirect(ICONINFO* info);
    [LibraryImport("user32.dll")] private static partial nint GetDC(nint hwnd);
    [LibraryImport("user32.dll")] private static partial int ReleaseDC(nint hwnd, nint dc);
    [LibraryImport("gdi32.dll")] private static partial nint CreateDIBSection(nint dc, BITMAPV5HEADER* header, uint usage, void** bits, nint section, uint offset);
    [LibraryImport("gdi32.dll")] private static partial nint CreateBitmap(int width, int height, uint planes, uint bitsPerPixel, void* bits);
    [LibraryImport("gdi32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool DeleteObject(nint obj);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool EnumWindows(delegate* unmanaged<nint, nint, int> callback, nint state);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool IsWindow(nint window);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool IsWindowVisible(nint window);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool IsIconic(nint window);
    [LibraryImport("user32.dll")] public static partial uint GetWindowThreadProcessId(nint window, out int processId);
    [LibraryImport("user32.dll")] private static partial nint GetWindow(nint window, uint command);
    [LibraryImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] private static partial nint GetWindowLongPtr(nint window, int index);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetWindowRect(nint window, out RECT rect);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetWindowPos(nint window, nint insertAfter, int x, int y, int width, int height, uint flags);
    [LibraryImport("user32.dll")] private static partial nint MonitorFromWindow(nint window, uint flags);
    [LibraryImport("user32.dll")] private static partial nint MonitorFromPoint(POINT point, uint flags);
    [LibraryImport("user32.dll", EntryPoint = "GetMonitorInfoW")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetMonitorInfo(nint monitor, MONITORINFO* info);
    [LibraryImport("shcore.dll")] private static partial int GetDpiForMonitor(nint monitor, int type, out uint dpiX, out uint dpiY);
    [LibraryImport("dwmapi.dll")] private static partial int DwmGetWindowAttribute(nint window, int attribute, void* value, int size);
    [LibraryImport("kernel32.dll")] private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [LibraryImport("winmm.dll", EntryPoint = "PlaySoundW", StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool PlaySound(string sound, nint module, uint flags);

    /// <summary>
    /// Every top-level window, front to back as the desktop stacks them.
    /// </summary>
    public static List<nint> TopLevelWindows()
    {
        var windows = new List<nint>();
        var state = GCHandle.Alloc(windows);
        try
        {
            _ = EnumWindows(&CollectWindow, GCHandle.ToIntPtr(state));
        }
        finally
        {
            state.Free();
        }

        return windows;
    }

    [UnmanagedCallersOnly]
    private static int CollectWindow(nint window, nint state)
    {
        ((List<nint>)GCHandle.FromIntPtr(state).Target!).Add(window);
        return 1;
    }

    /// <summary>
    /// True for a window that is a tool palette, or that another window owns, such as a
    /// dialog: never the window a person would call the app's.
    /// </summary>
    public static bool IsToolOrOwned(nint window) => (GetWindowLongPtr(window, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0 || GetWindow(window, GW_OWNER) != 0;

    /// <summary>
    /// True for a window Windows keeps out of sight while it stays "visible": one on another
    /// virtual desktop, or a suspended app's.
    /// </summary>
    public static bool IsCloaked(nint window)
    {
        int cloaked;
        return DwmGetWindowAttribute(window, DWMWA_CLOAKED, &cloaked, sizeof(int)) == 0 && cloaked != 0;
    }

    /// <summary>
    /// The frame a window shows, without the invisible resize borders that GetWindowRect
    /// counts on Windows 10 and later; null when Windows cannot say.
    /// </summary>
    public static Rect? VisibleFrameOf(nint window)
    {
        RECT frame;
        return DwmGetWindowAttribute(window, DWMWA_EXTENDED_FRAME_BOUNDS, &frame, sizeof(RECT)) == 0 ? frame.ToRect() : null;
    }

    /// <summary>
    /// A window's rectangle as SetWindowPos places it, invisible resize borders included;
    /// null when the window is gone.
    /// </summary>
    public static Rect? WindowRectOf(nint window) => GetWindowRect(window, out var rect) ? rect.ToRect() : null;

    /// <summary>
    /// The work area and scale of the monitor a window mostly covers.
    /// </summary>
    public static MonitorArea MonitorAreaOf(nint window) => AreaOf(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST));

    /// <summary>
    /// The work area and scale of the primary monitor, the one that holds the notification
    /// area.
    /// </summary>
    public static MonitorArea PrimaryMonitorArea() => AreaOf(MonitorFromPoint(default, MONITOR_DEFAULTTOPRIMARY));

    private static MonitorArea AreaOf(nint monitor)
    {
        var info = new MONITORINFO { cbSize = (uint)sizeof(MONITORINFO) };
        _ = GetMonitorInfo(monitor, &info);
        var dpi = GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, out var dpiX, out _) == 0 ? dpiX : 96;
        return new MonitorArea(info.rcWork.ToRect(), dpi / 96.0);
    }

    /// <summary>
    /// Moves a window's top-left corner to a point, without resizing it, raising it, or
    /// giving it focus. A move onto a monitor with another DPI makes WPF rescale the window
    /// and can shift it on the way, so the move is checked and made once more.
    /// </summary>
    public static void MoveWindow(nint window, Point topLeft)
    {
        var (x, y) = ((int)Math.Round(topLeft.X), (int)Math.Round(topLeft.Y));
        for (var attempt = 0; attempt < 2; attempt++)
        {
            if (GetWindowRect(window, out var current) && current.Left == x && current.Top == y) return;
            _ = SetWindowPos(window, 0, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    /// <summary>
    /// When a process started, as a UTC FILETIME, or 0 when it has exited or cannot be
    /// opened.
    /// </summary>
    public static long CreateTimeOf(int processId)
    {
        using var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        return !process.IsInvalid && GetProcessTimes(process, out var created, out _, out _, out _) ? created : 0;
    }

    /// <summary>
    /// Plays the sound Windows plays for its own notifications: whatever the user's sound
    /// scheme sets, nothing under "No sounds", at the system-sounds volume.
    /// </summary>
    public static void PlayNotificationSound() => _ = PlaySound("Notification.Default", 0, SND_ALIAS | SND_ASYNC | SND_NODEFAULT | SND_SYSTEM);

    public static void CopyTo(string text, char* destination, int capacity)
    {
        var length = Math.Min(text.Length, capacity - 1);
        text.AsSpan(0, length).CopyTo(new Span<char>(destination, capacity));
        destination[length] = '\0';
    }

    /// <summary>
    /// An icon from square, top-down, straight-alpha BGRA pixels. The caller destroys it.
    /// </summary>
    public static nint CreateIcon(int size, ReadOnlySpan<byte> bgra)
    {
        var header = new BITMAPV5HEADER
        {
            bV5Size = (uint)sizeof(BITMAPV5HEADER),
            bV5Width = size,
            bV5Height = -size,
            bV5Planes = 1,
            bV5BitCount = 32,
            bV5Compression = 3, // BI_BITFIELDS
            bV5RedMask = 0x00FF0000,
            bV5GreenMask = 0x0000FF00,
            bV5BlueMask = 0x000000FF,
            bV5AlphaMask = 0xFF000000,
        };

        void* bits;
        var screen = GetDC(0);
        var color = CreateDIBSection(screen, &header, 0, &bits, 0, 0);
        _ = ReleaseDC(0, screen);
        if (color == 0) return 0;

        // With an alpha channel the mask is ignored, but it must exist: an all-zero one.
        var mask = new byte[(size + 15) / 16 * 2 * size];
        try
        {
            bgra[..(size * size * 4)].CopyTo(new Span<byte>(bits, size * size * 4));
            fixed (byte* maskBits = mask)
            {
                var monochrome = CreateBitmap(size, size, 1, 1, maskBits);
                try
                {
                    var info = new ICONINFO { fIcon = 1, hbmMask = monochrome, hbmColor = color };
                    return CreateIconIndirect(&info);
                }
                finally
                {
                    _ = DeleteObject(monochrome);
                }
            }
        }
        finally
        {
            _ = DeleteObject(color);
        }
    }
}
