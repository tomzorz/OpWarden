using System.Runtime.InteropServices;

namespace OpWarden.SessionAgent;

/// <summary>
/// The Win32 calls WPF does not cover: the notification-area icon, session lock events,
/// and turning a rendered glyph into an icon handle.
/// </summary>
internal static unsafe partial class Native
{
    public const uint WM_SETTINGCHANGE = 0x001A, WM_CONTEXTMENU = 0x007B, WM_LBUTTONUP = 0x0202, WM_RBUTTONUP = 0x0205, WM_APP = 0x8000;
    public const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIF_MESSAGE = 1, NIF_ICON = 2, NIF_TIP = 4;
    public const uint WM_WTSSESSION_CHANGE = 0x02B1, NOTIFY_FOR_THIS_SESSION = 0;
    public const nint WTS_SESSION_LOCK = 0x7;
    public const int SM_CXSMICON = 49;

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
