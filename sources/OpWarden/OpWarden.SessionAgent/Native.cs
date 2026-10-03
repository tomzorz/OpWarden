using System.Runtime.InteropServices;

namespace OpWarden.SessionAgent;

/// <summary>
/// The Win32 surface the session agent uses. Raw P/Invoke keeps the agent NativeAOT and
/// free of UI dependencies (docs/IMPLEMENTATION.md, "AOT everywhere, for now").
/// </summary>
internal static unsafe partial class Native
{
    public const uint WM_CREATE = 0x0001, WM_DESTROY = 0x0002, WM_CLOSE = 0x0010, WM_SETFONT = 0x0030, WM_COMMAND = 0x0111, WM_TIMER = 0x0113;
    public const uint WM_CTLCOLORSTATIC = 0x0138, WM_CTLCOLORBTN = 0x0135, WM_CONTEXTMENU = 0x007B, WM_RBUTTONUP = 0x0205, WM_LBUTTONUP = 0x0202, WM_APP = 0x8000;
    public const uint WS_OVERLAPPED = 0, WS_CAPTION = 0x00C00000, WS_SYSMENU = 0x00080000, WS_CHILD = 0x40000000, WS_VISIBLE = 0x10000000, WS_TABSTOP = 0x00010000, WS_VSCROLL = 0x00200000;
    public const uint WS_EX_TOPMOST = 0x00000008, WS_EX_CONTROLPARENT = 0x00010000, WS_EX_DLGMODALFRAME = 0x00000001;
    public const uint BS_PUSHBUTTON = 0, BS_AUTOCHECKBOX = 3, SS_LEFT = 0, SS_RIGHT = 2, SS_ENDELLIPSIS = 0x4000, CBS_DROPDOWNLIST = 3;
    public const uint BM_GETCHECK = 0x00F0, BM_SETCHECK = 0x00F1, CB_ADDSTRING = 0x0143, CB_SETCURSEL = 0x014E, CB_GETCURSEL = 0x0147;
    public const int SW_SHOWNOACTIVATE = 4, IDCANCEL = 2, COLOR_WINDOW = 5;
    public const uint SWP_NOSIZE = 0x1, SWP_NOMOVE = 0x2, SWP_NOACTIVATE = 0x10;
    public const uint FLASHW_ALL = 3, FLASHW_TIMERNOFG = 12;
    public const uint SPI_GETNONCLIENTMETRICS = 0x0029, SPI_GETWORKAREA = 0x0030;
    public const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIF_MESSAGE = 1, NIF_ICON = 2, NIF_TIP = 4, NIF_INFO = 0x10, NIIF_INFO = 1;
    public const uint MF_STRING = 0, TPM_RIGHTBUTTON = 2, TPM_RETURNCMD = 0x100;
    public const int TRANSPARENT = 1;
    public static readonly nint HWND_TOPMOST = -1, HWND_MESSAGE = -3, IDI_SHIELD = 32518, IDC_ARROW = 32512;

    [StructLayout(LayoutKind.Sequential)]
    public struct WNDCLASSEXW
    {
        public uint cbSize, style;
        public delegate* unmanaged<nint, uint, nint, nint, nint> lpfnWndProc;
        public int cbClsExtra, cbWndExtra;
        public nint hInstance, hIcon, hCursor, hbrBackground;
        public char* lpszMenuName, lpszClassName;
        public nint hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG
    {
        public nint hwnd;
        public uint message;
        public nint wParam, lParam;
        public uint time;
        public int ptX, ptY, lPrivate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int X, Y;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LOGFONTW
    {
        public int lfHeight, lfWidth, lfEscapement, lfOrientation, lfWeight;
        public byte lfItalic, lfUnderline, lfStrikeOut, lfCharSet, lfOutPrecision, lfClipPrecision, lfQuality, lfPitchAndFamily;
        public fixed char lfFaceName[32];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NONCLIENTMETRICSW
    {
        public uint cbSize;
        public int iBorderWidth, iScrollWidth, iScrollHeight, iCaptionWidth, iCaptionHeight;
        public LOGFONTW lfCaptionFont;
        public int iSmCaptionWidth, iSmCaptionHeight;
        public LOGFONTW lfSmCaptionFont;
        public int iMenuWidth, iMenuHeight;
        public LOGFONTW lfMenuFont, lfStatusFont, lfMessageFont;
        public int iPaddedBorderWidth;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FLASHWINFO
    {
        public uint cbSize;
        public nint hwnd;
        public uint dwFlags, uCount, dwTimeout;
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

    [LibraryImport("user32.dll", SetLastError = true)] public static partial ushort RegisterClassExW(WNDCLASSEXW* wc);
    [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] public static partial nint CreateWindowExW(uint exStyle, string className, string? windowName, uint style, int x, int y, int width, int height, nint parent, nint menu, nint instance, nint param);
    [LibraryImport("user32.dll")] public static partial nint DefWindowProcW(nint hwnd, uint msg, nint wParam, nint lParam);
    [LibraryImport("user32.dll")] public static partial int GetMessageW(MSG* msg, nint hwnd, uint min, uint max);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool TranslateMessage(MSG* msg);
    [LibraryImport("user32.dll")] public static partial nint DispatchMessageW(MSG* msg);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool IsDialogMessageW(nint hwnd, MSG* msg);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool PostMessageW(nint hwnd, uint msg, nint wParam, nint lParam);
    [LibraryImport("user32.dll")] public static partial nint SendMessageW(nint hwnd, uint msg, nint wParam, nint lParam);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] public static partial nint SendMessageW(nint hwnd, uint msg, nint wParam, string lParam);
    [LibraryImport("user32.dll")] public static partial void PostQuitMessage(int exitCode);
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetWindowTextW(nint hwnd, string text);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool ShowWindow(nint hwnd, int command);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool DestroyWindow(nint hwnd);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool EnableWindow(nint hwnd, [MarshalAs(UnmanagedType.Bool)] bool enable);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetWindowPos(nint hwnd, nint after, int x, int y, int cx, int cy, uint flags);
    [LibraryImport("user32.dll")] public static partial nuint SetTimer(nint hwnd, nuint id, uint elapse, nint callback);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool KillTimer(nint hwnd, nuint id);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool FlashWindowEx(FLASHWINFO* info);
    [LibraryImport("user32.dll")] public static partial nint LoadIconW(nint instance, nint name);
    [LibraryImport("user32.dll")] public static partial nint LoadCursorW(nint instance, nint name);
    [LibraryImport("user32.dll")] public static partial nint GetSysColorBrush(int index);
    [LibraryImport("user32.dll")] public static partial uint GetSysColor(int index);
    [LibraryImport("user32.dll")] public static partial uint GetDpiForSystem();
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SystemParametersInfoForDpi(uint action, uint param, void* data, uint winIni, uint dpi);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SystemParametersInfoW(uint action, uint param, void* data, uint winIni);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool AdjustWindowRectExForDpi(RECT* rect, uint style, [MarshalAs(UnmanagedType.Bool)] bool menu, uint exStyle, uint dpi);
    [LibraryImport("user32.dll")] public static partial nint CreatePopupMenu();
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] public static partial bool AppendMenuW(nint menu, uint flags, nuint id, string text);
    [LibraryImport("user32.dll")] public static partial int TrackPopupMenu(nint menu, uint flags, int x, int y, int reserved, nint hwnd, nint rect);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool DestroyMenu(nint menu);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool GetCursorPos(POINT* point);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetForegroundWindow(nint hwnd);
    [LibraryImport("gdi32.dll")] public static partial nint CreateFontIndirectW(LOGFONTW* font);
    [LibraryImport("gdi32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool DeleteObject(nint obj);
    [LibraryImport("gdi32.dll")] public static partial int SetBkMode(nint hdc, int mode);
    [LibraryImport("gdi32.dll")] public static partial uint SetTextColor(nint hdc, uint color);
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)] public static partial nint GetModuleHandleW(string? name);
    [LibraryImport("shell32.dll")][return: MarshalAs(UnmanagedType.Bool)] public static partial bool Shell_NotifyIconW(uint message, NOTIFYICONDATAW* data);

    public static void CopyTo(string text, char* destination, int capacity)
    {
        var length = Math.Min(text.Length, capacity - 1);
        text.AsSpan(0, length).CopyTo(new Span<char>(destination, capacity));
        destination[length] = '\0';
    }
}
