using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

/// <summary>
/// The real session agent against a test broker: the prompt appears, renders, and a
/// button press reaches the broker. Opt-in, because it puts windows on the desktop:
/// set OPWARDEN_UI_TESTS=1, and OPWARDEN_UI_SCREENSHOTS to a folder for PNGs of each
/// prompt.
/// </summary>
/// <remarks>
/// The button press is a posted BM_CLICK, which is exactly the scripted input that spec
/// section 17 leaves open: this test passing is that open question, demonstrated.
/// </remarks>
public sealed partial class SessionAgentUiTests
{
    private const int ExitDenied = 77;
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");

    [Fact]
    public async Task A_full_prompt_renders_and_allow_once_reaches_the_broker()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("OPWARDEN_UI_TESTS") == "1", "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude);
        using var agent = StartAgent(broker.AgentPipeName);
        try
        {
            var run = broker.RunShimAsync(["read", "op://Private/GitHub/password"]);
            var prompt = await WaitForPromptAsync(agent.Id);
            Screenshot(prompt, "prompt-read.png");

            Click(prompt, "Allow once");

            Assert.Equal(0, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task A_run_prompt_lists_its_references_and_disallow_once_denies()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("OPWARDEN_UI_TESTS") == "1", "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude);
        using var agent = StartAgent(broker.AgentPipeName);
        try
        {
            var envFile = Path.Combine(broker.DataDirectory, "tofu.env");
            await File.WriteAllLinesAsync(envFile, ["PG_USER=op://Infra/postgres/username", "PG_PASSWORD=op://Infra/postgres/password", "HYPERVISOR_TOKEN=op://Infra/hypervisor/api token"], TestContext.Current.CancellationToken);
            var run = broker.RunShimAsync(["run", "--env-file", envFile, "--", "tofu", "plan"]);
            var prompt = await WaitForPromptAsync(agent.Id);
            Screenshot(prompt, "prompt-run.png");

            Click(prompt, "Disallow once");

            Assert.Equal(ExitDenied, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task An_unknown_caller_gets_only_the_once_buttons()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("OPWARDEN_UI_TESTS") == "1", "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(CallerIdentity.Unknown);
        using var agent = StartAgent(broker.AgentPipeName);
        try
        {
            var run = broker.RunShimAsync(["item", "get", "GitHub", "--vault", "Private"]);
            var prompt = await WaitForPromptAsync(agent.Id);
            Screenshot(prompt, "prompt-unknown-caller.png");

            Assert.Equal(0, FindWindowExW(prompt, 0, "Button", "Always allow"));
            Click(prompt, "Disallow once");
            Assert.Equal(ExitDenied, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    private static Process StartAgent(string pipeName) =>
        Process.Start(new ProcessStartInfo(BuiltExecutables.SessionAgent, ["--pipe", pipeName]) { UseShellExecute = false })
        ?? throw new InvalidOperationException("Could not start the session agent.");

    private static async Task<nint> WaitForPromptAsync(int agentProcessId)
    {
        for (var i = 0; i < 100; i++)
        {
            nint window = 0;
            while ((window = FindWindowExW(0, window, "OpWardenPrompt", null)) != 0)
            {
                // Visible means built: the window shows only after its controls exist.
                GetWindowThreadProcessId(window, out var owner);
                if (owner == agentProcessId && IsWindowVisible(window)) return window;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException("The session agent showed no prompt within 10 seconds.");
    }

    private static void Click(nint prompt, string buttonText)
    {
        var button = FindWindowExW(prompt, 0, "Button", buttonText);
        Assert.NotEqual(0, button);
        PostMessageW(button, BM_CLICK, 0, 0);
    }

    /// <summary>
    /// Asks the window to paint itself into a bitmap, which works while the workstation is
    /// locked, unlike a screen grab, and saves it as a PNG.
    /// </summary>
    private static unsafe void Screenshot(nint window, string name)
    {
        if (Environment.GetEnvironmentVariable("OPWARDEN_UI_SCREENSHOTS") is not { Length: > 0 } folder) return;

        GetWindowRect(window, out var rect);
        int width = rect.Right - rect.Left, height = rect.Bottom - rect.Top;
        var screen = GetDC(0);
        var memory = CreateCompatibleDC(screen);
        var bitmap = CreateCompatibleBitmap(screen, width, height);
        var previous = SelectObject(memory, bitmap);
        try
        {
            PrintWindow(window, memory, PW_RENDERFULLCONTENT);

            var info = new BITMAPINFOHEADER { biSize = (uint)sizeof(BITMAPINFOHEADER), biWidth = width, biHeight = -height, biPlanes = 1, biBitCount = 32 };
            var pixels = new byte[width * height * 4];
            fixed (byte* p = pixels)
            {
                if (GetDIBits(memory, bitmap, 0, (uint)height, p, &info, 0) == 0) throw new InvalidOperationException("GetDIBits copied no lines.");
            }

            Directory.CreateDirectory(folder);
            File.WriteAllBytes(Path.Combine(folder, name), Png(pixels, width, height));
        }
        finally
        {
            SelectObject(memory, previous);
            DeleteObject(bitmap);
            DeleteDC(memory);
            _ = ReleaseDC(0, screen);
        }
    }

    // A minimal PNG writer for BGRA pixels: 8-bit RGBA, no filtering, one IDAT chunk.
    private static byte[] Png(byte[] bgra, int width, int height)
    {
        var raw = new byte[height * (width * 4 + 1)];
        for (var y = 0; y < height; y++)
        {
            var row = y * (width * 4 + 1);
            for (var x = 0; x < width; x++)
            {
                var source = (y * width + x) * 4;
                var target = row + 1 + x * 4;
                (raw[target], raw[target + 1], raw[target + 2], raw[target + 3]) = (bgra[source + 2], bgra[source + 1], bgra[source], 255);
            }
        }

        using var compressed = new MemoryStream();
        using (var zlib = new ZLibStream(compressed, CompressionLevel.Optimal, leaveOpen: true)) zlib.Write(raw);

        using var png = new MemoryStream();
        png.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        var header = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(header, width);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4), height);
        (header[8], header[9]) = (8, 6);
        Chunk(png, "IHDR", header);
        Chunk(png, "IDAT", compressed.ToArray());
        Chunk(png, "IEND", []);
        return png.ToArray();
    }

    private static void Chunk(Stream png, string type, byte[] data)
    {
        Span<byte> number = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(number, data.Length);
        png.Write(number);
        var typed = new byte[4 + data.Length];
        System.Text.Encoding.ASCII.GetBytes(type).CopyTo(typed, 0);
        data.CopyTo(typed, 4);
        png.Write(typed);
        BinaryPrimitives.WriteUInt32BigEndian(number, Crc32(typed));
        png.Write(number);
    }

    private static uint Crc32(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var k = 0; k < 8; k++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }

        return ~crc;
    }

    private const uint BM_CLICK = 0x00F5, PW_RENDERFULLCONTENT = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth, biHeight;
        public ushort biPlanes, biBitCount;
        public uint biCompression, biSizeImage;
        public int biXPelsPerMeter, biYPelsPerMeter;
        public uint biClrUsed, biClrImportant;
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial nint FindWindowExW(nint parent, nint after, string? className, string? title);
    [LibraryImport("user32.dll")] private static partial uint GetWindowThreadProcessId(nint window, out int processId);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsWindowVisible(nint window);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool PostMessageW(nint window, uint message, nint wParam, nint lParam);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetWindowRect(nint window, out RECT rect);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool PrintWindow(nint window, nint dc, uint flags);
    [LibraryImport("user32.dll")] private static partial nint GetDC(nint window);
    [LibraryImport("user32.dll")] private static partial int ReleaseDC(nint window, nint dc);
    [LibraryImport("gdi32.dll")] private static partial nint CreateCompatibleDC(nint dc);
    [LibraryImport("gdi32.dll")] private static partial nint CreateCompatibleBitmap(nint dc, int width, int height);
    [LibraryImport("gdi32.dll")] private static partial nint SelectObject(nint dc, nint obj);
    [LibraryImport("gdi32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool DeleteObject(nint obj);
    [LibraryImport("gdi32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool DeleteDC(nint dc);
    [LibraryImport("gdi32.dll")] private static unsafe partial int GetDIBits(nint dc, nint bitmap, uint start, uint lines, byte* bits, BITMAPINFOHEADER* info, uint usage);
}
