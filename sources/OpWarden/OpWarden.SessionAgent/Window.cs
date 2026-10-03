using System.ComponentModel;
using System.Runtime.InteropServices;
using static OpWarden.SessionAgent.Native;

namespace OpWarden.SessionAgent;

/// <summary>
/// A top-level Win32 window owned by managed code. One window procedure serves every
/// window class here and routes each message to the owning object by handle.
/// </summary>
/// <remarks>
/// Everything runs on the one UI thread, which is what makes the static routing table
/// safe without a lock.
/// </remarks>
internal abstract unsafe class Window
{
    private static readonly Dictionary<nint, Window> Live = [];
    private static Window? _creating;

    public nint Handle { get; private set; }

    public static void RegisterClass(string name, int background)
    {
        fixed (char* className = name)
        {
            var windowClass = new WNDCLASSEXW
            {
                cbSize = (uint)sizeof(WNDCLASSEXW),
                lpfnWndProc = &WindowProcedure,
                hInstance = GetModuleHandleW(null),
                hCursor = LoadCursorW(0, IDC_ARROW),
                hbrBackground = background,
                lpszClassName = className,
                hIcon = LoadIconW(0, IDI_SHIELD),
            };
            if (RegisterClassExW(&windowClass) == 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), $"RegisterClassEx failed for {name}.");
        }
    }

    protected void Create(string className, uint exStyle, string? title, uint style, int x, int y, int width, int height)
    {
        _creating = this;
        try
        {
            Handle = CreateWindowExW(exStyle, className, title, style, x, y, width, height, 0, 0, GetModuleHandleW(null), 0);
        }
        finally
        {
            _creating = null;
        }

        if (Handle == 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), $"CreateWindowEx failed for {className}.");
    }

    /// <summary>
    /// Handles one message. Return null to fall through to the default window procedure.
    /// </summary>
    protected abstract nint? OnMessage(uint message, nint wParam, nint lParam);

    [UnmanagedCallersOnly]
    private static nint WindowProcedure(nint hwnd, uint message, nint wParam, nint lParam)
    {
        if (!Live.TryGetValue(hwnd, out var window) && _creating is { } creating)
        {
            creating.Handle = hwnd;
            Live[hwnd] = window = creating;
        }

        try
        {
            var result = window?.OnMessage(message, wParam, lParam);
            if (message == WM_DESTROY) Live.Remove(hwnd);
            return result ?? DefWindowProcW(hwnd, message, wParam, lParam);
        }
        catch (Exception e)
        {
            // An exception must not cross into user32. Log it and let the default
            // procedure handle the message; a broken prompt then times out into a deny.
            AgentLog.Write($"window procedure failed on message 0x{message:X4}: {e}");
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }
}

/// <summary>
/// The session agent's log: a file beside the executable, because a WinExe has no console.
/// </summary>
internal static class AgentLog
{
    private static readonly Lock Gate = new();

    public static void Write(string line)
    {
        try
        {
            lock (Gate) File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "session-agent.log"), $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Nowhere left to report it.
        }
    }
}
