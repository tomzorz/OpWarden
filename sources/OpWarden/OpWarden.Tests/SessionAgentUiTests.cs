using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Interop;
using System.Windows.Threading;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;
using OpWarden.SessionAgent;

namespace OpWarden.Tests;

/// <summary>
/// The real session agent against a test broker, driven through UI Automation: prompts
/// appear and a button press reaches the broker, toasts name what was read, count down,
/// and sit on the window the read came from, and the windows the tray opens fill in.
/// Opt-in, because it puts windows on the desktop and, for the hover test, moves the
/// pointer: set OPWARDEN_UI_TESTS=1, and OPWARDEN_UI_SCREENSHOTS to a folder, which the
/// agent then fills with a PNG of each window it shows.
/// </summary>
/// <remarks>
/// The button press is a UI Automation invoke, which is exactly the scripted input that
/// spec section 17 leaves open: these tests passing is that open question, demonstrated.
/// </remarks>
public sealed partial class SessionAgentUiTests
{
    private const int ExitDenied = 77;
    private static readonly CallerIdentity Claude = CallerIdentity.Agent("claude-code");
    private static readonly Rule ClaudeReadsInfra = new(Claude, OpAction.Read, "Infra", null, null, Verdict.Allow);

    // The transparent band ToastWindow.xaml keeps around a toast's frame, in DIPs.
    private const double ToastInsetX = 12, ToastInsetY = 6;

    private static bool Enabled => Environment.GetEnvironmentVariable("OPWARDEN_UI_TESTS") == "1";

    [Fact]
    public async Task A_full_prompt_renders_and_allow_once_reaches_the_broker()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var run = broker.RunShimAsync(["read", "op://Private/GitHub/password"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Invoke(prompt, "AllowOnceButton");

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
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var envFile = Path.Combine(broker.DataDirectory, "tofu.env");
            await File.WriteAllLinesAsync(envFile, ["PG_USER=op://Infra/postgres/username", "PG_PASSWORD=op://Infra/postgres/password", "HYPERVISOR_TOKEN=op://Infra/hypervisor/api token"], TestContext.Current.CancellationToken);
            var run = broker.RunShimAsync(["run", "--env-file", envFile, "--", "tofu", "plan"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Assert.NotNull(prompt.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "Infra / hypervisor / api token")));
            Invoke(prompt, "DisallowOnceButton");

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
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(CallerIdentity.Unknown, sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            var run = broker.RunShimAsync(["item", "get", "GitHub", "--vault", "Private"]);
            var prompt = await WaitForWindowAsync(agent, "PromptWindow");

            Assert.Null(Find(prompt, "AlwaysAllowButton"));
            Invoke(prompt, "DisallowOnceButton");
            Assert.Equal(ExitDenied, (await run).ExitCode);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task A_read_a_rule_lets_through_raises_a_toast_naming_it_that_counts_down()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [ClaudeReadsInfra], sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        try
        {
            await WaitUntilPinnedAsync(broker);
            Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/tofu-state/passphrase"])).ExitCode);

            var toast = await WaitForWindowAsync(agent, "ReadToast");

            Assert.NotNull(toast.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "claude-code read a secret")));
            Assert.NotNull(toast.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.NameProperty, "Infra / tofu-state / passphrase")));

            // REQ-RULE-48: the bar along the top runs down.
            var bar = await WaitForAsync(() => Find(toast, "ToastLifetime"), found => found is not null);
            var before = LifetimeLeft(bar!);
            await Task.Delay(500, TestContext.Current.CancellationToken);
            Assert.InRange(LifetimeLeft(bar!), 0.5, before - 0.02);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task A_read_toast_sits_on_the_window_the_read_came_from_and_follows_it()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");

        // The test process stands in for the terminal: one window, named as the shim's
        // only ancestor (REQ-RULE-40, REQ-RULE-41).
        using var origin = await StandInWindow.ShowAsync();
        ProcessIdentity[] ancestors = [new(Environment.ProcessId, Native.CreateTimeOf(Environment.ProcessId))];
        await using var broker = BrokerHarness.Start(Claude, [ClaudeReadsInfra], sessionAgentPath: BuiltExecutables.SessionAgent, ancestors: ancestors);
        using var agent = StartAgent(broker);
        try
        {
            await WaitUntilPinnedAsync(broker);
            Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/tofu-state/passphrase"])).ExitCode);
            var toast = new nint((await WaitForWindowAsync(agent, "ReadToast")).Current.NativeWindowHandle);

            // REQ-RULE-42: the frame ends on the window's top edge, at the window's width.
            await WaitForAsync(() => (Toast: FrameOf(toast), Origin: Native.VisibleFrameOf(origin.Handle)!.Value), f => SitsOn(f.Toast, f.Origin));

            // REQ-RULE-45: and moves with it.
            origin.MoveBy(60, 40);
            await WaitForAsync(() => (Toast: FrameOf(toast), Origin: Native.VisibleFrameOf(origin.Handle)!.Value), f => SitsOn(f.Toast, f.Origin));
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_pointer_resting_on_a_toast_holds_its_countdown()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [ClaudeReadsInfra], sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker);
        _ = GetCursorPos(out var home);
        try
        {
            await WaitUntilPinnedAsync(broker);
            Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/tofu-state/passphrase"])).ExitCode);
            var toast = await WaitForWindowAsync(agent, "ReadToast");
            var bar = await WaitForAsync(() => Find(toast, "ToastLifetime"), found => found is not null);

            // REQ-RULE-47: on the toast, the count holds; off it, the count runs on.
            var bounds = toast.Current.BoundingRectangle;
            var over = new POINT((int)(bounds.Left + (bounds.Width / 2)), (int)(bounds.Top + (bounds.Height / 2)));
            Assert.SkipUnless(SetCursorPos(over.X, over.Y) && GetCursorPos(out var landed) && landed == over, "The pointer cannot be moved here, as on a locked workstation.");
            await Task.Delay(300, TestContext.Current.CancellationToken);
            var held = LifetimeLeft(bar!);
            await Task.Delay(800, TestContext.Current.CancellationToken);
            Assert.Equal(held, LifetimeLeft(bar!), 0.001);

            _ = SetCursorPos((int)bounds.Left - 200, (int)bounds.Top - 200);
            await Task.Delay(500, TestContext.Current.CancellationToken);
            Assert.True(LifetimeLeft(bar!) < held - 0.02);
        }
        finally
        {
            _ = SetCursorPos(home.X, home.Y);
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_rules_window_lists_the_stored_rules_read_only()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, "Infra", "GitHub", null, Verdict.Allow, CacheTtl.EightHours), new Rule(null, OpAction.Delete, null, null, null, Verdict.Deny)], sessionAgentPath: BuiltExecutables.SessionAgent);
        using var agent = StartAgent(broker, "rules");
        try
        {
            var window = await WaitForWindowAsync(agent, "RulesWindow");
            var rows = await WaitForAsync(() => window.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem)), found => found.Count == 2);

            Assert.Equal(2, rows.Count);
            Assert.NotNull(Find(window, "ElevateButton"));
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_audit_and_status_windows_show_what_the_broker_recorded()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)], sessionAgentPath: BuiltExecutables.SessionAgent);
        Assert.Equal(0, (await broker.RunShimAsync(["read", "op://Infra/postgres/password"])).ExitCode);
        using var agent = StartAgent(broker, "audit", "status");
        try
        {
            var audit = await WaitForWindowAsync(agent, "AuditWindow");
            var rows = await WaitForAsync(() => audit.FindAll(TreeScope.Descendants, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.DataItem)), found => found.Count > 0);
            Assert.NotEmpty(rows.Cast<AutomationElement>());

            var status = await WaitForWindowAsync(agent, "StatusWindow");
            var cached = await WaitForAsync(() => Find(status, "CachedValues"), element => element?.Current.Name == "0");
            Assert.Equal("0", cached!.Current.Name);
        }
        finally
        {
            agent.Kill();
        }
    }

    [Fact]
    public async Task The_status_window_caps_the_recent_invocations_and_stays_clear_of_the_taskbar()
    {
        Assert.SkipUnless(Enabled, "OPWARDEN_UI_TESTS is not 1.");
        await using var broker = BrokerHarness.Start(Claude, [new Rule(Claude, OpAction.Read, null, null, null, Verdict.Allow)], sessionAgentPath: BuiltExecutables.SessionAgent);
        for (var i = 0; i < 10; i++) Assert.Equal(0, (await broker.RunShimAsync(["read", $"op://Infra/postgres/password-{i}"])).ExitCode);
        using var agent = StartAgent(broker, "status");
        try
        {
            var status = await WaitForWindowAsync(agent, "StatusWindow");
            var summary = await WaitForAsync(() => Find(status, "RecentSummary"), element => element?.Current.Name.Length > 0);
            Assert.Equal("Showing the last 8 of 10 invocations.", summary!.Current.Name);

            // The list arrives after the window opens; the window grows upward, not under the taskbar.
            var window = new nint(status.Current.NativeWindowHandle);
            await WaitForAsync(() => FrameAndWorkAreaOf(window), found => found.WorkArea.Contains(found.Frame));
        }
        finally
        {
            agent.Kill();
        }
    }

    private static Process StartAgent(BrokerHarness broker, params string[] open)
    {
        var info = new ProcessStartInfo(BuiltExecutables.SessionAgent) { UseShellExecute = false };
        foreach (var argument in new[] { "--pipe", broker.AgentPipeName, "--manage-pipe", broker.Pipes.Management }) info.ArgumentList.Add(argument);
        foreach (var window in open)
        {
            info.ArgumentList.Add("--open");
            info.ArgumentList.Add(window);
        }

        return Process.Start(info) ?? throw new InvalidOperationException("Could not start the session agent.");
    }

    /// <summary>
    /// The agent's top-level window with this automation ID. Windows are found with Win32
    /// and only then handed to UI Automation: .NET's managed UI Automation client takes tens
    /// of seconds to walk a desktop's top-level windows (45 s for one search on a real
    /// desktop, where .NET Framework's takes 46 ms), but answers in milliseconds for a
    /// window it is handed.
    /// </summary>
    private static async Task<AutomationElement> WaitForWindowAsync(Process agent, string automationId)
    {
        var window = await WaitForAsync(() => WindowsOf(agent.Id).Select(ElementOf).FirstOrDefault(w => w?.Current.AutomationId == automationId), found => found is not null);
        return window!;
    }

    private static List<nint> WindowsOf(int processId)
    {
        var windows = new List<nint>();
        nint window = 0;
        while ((window = FindWindowExW(0, window, null, null)) != 0)
        {
            _ = GetWindowThreadProcessId(window, out var owner);
            if (owner == processId && IsWindowVisible(window)) windows.Add(window);
        }

        return windows;
    }

    private static AutomationElement? ElementOf(nint window)
    {
        try
        {
            return AutomationElement.FromHandle(window);
        }
        catch (ElementNotAvailableException)
        {
            // The window closed between finding it and asking about it.
            return null;
        }
    }

    private static async Task<T> WaitForAsync<T>(Func<T> look, Func<T, bool> done)
    {
        var found = look();
        for (var i = 0; i < 150 && !done(found); i++)
        {
            await Task.Delay(100);
            found = look();
        }

        return done(found) ? found : throw new TimeoutException($"The session agent did not show what was expected within 15 seconds; the last look found {found}.");
    }

    private static async Task WaitUntilPinnedAsync(BrokerHarness broker) =>
        await WaitForAsync(() => broker.AuditEntries("agent-pinned").Count, pins => pins > 0);

    private static AutomationElement? Find(AutomationElement window, string automationId) =>
        window.FindFirst(TreeScope.Descendants, new PropertyCondition(AutomationElement.AutomationIdProperty, automationId));

    private static void Invoke(AutomationElement window, string automationId)
    {
        var button = Find(window, automationId);
        Assert.NotNull(button);
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    /// <summary>
    /// The share of a toast's time on screen still left, as its lifetime bar reports it.
    /// </summary>
    private static double LifetimeLeft(AutomationElement bar) => ((RangeValuePattern)bar.GetCurrentPattern(RangeValuePattern.Pattern)).Current.Value;

    /// <summary>
    /// A toast's frame in physical pixels: its window less the transparent inset.
    /// </summary>
    private static Rect FrameOf(nint toast)
    {
        var window = Native.VisibleFrameOf(toast)!.Value;
        var scale = GetDpiForWindow(toast) / 96.0;
        return new Rect(window.Left + (ToastInsetX * scale), window.Top + (ToastInsetY * scale), window.Width - (2 * ToastInsetX * scale), window.Height - (2 * ToastInsetY * scale));
    }

    /// <summary>
    /// A window's frame and the work area of its monitor, both in physical pixels. The test
    /// process is not DPI aware, so it asks as a per-monitor-aware thread would.
    /// </summary>
    private static (Rect Frame, Rect WorkArea) FrameAndWorkAreaOf(nint window)
    {
        var previous = SetThreadDpiAwarenessContext(PerMonitorAwareV2);
        try
        {
            return (Native.VisibleFrameOf(window)!.Value, Native.MonitorAreaOf(window).WorkArea);
        }
        finally
        {
            _ = SetThreadDpiAwarenessContext(previous);
        }
    }

    private static bool SitsOn(Rect toast, Rect origin) =>
        Math.Abs(toast.Bottom - origin.Top) <= 1 && Math.Abs(toast.Left - origin.Left) <= 1 && Math.Abs(toast.Width - origin.Width) <= 2;

    /// <summary>
    /// A plain top-level window of the test process, on a thread of its own, standing in
    /// for the terminal a read came from.
    /// </summary>
    private sealed class StandInWindow : IDisposable
    {
        private Window? _window;

        public nint Handle { get; private set; }

        public static async Task<StandInWindow> ShowAsync()
        {
            var standIn = new StandInWindow();
            var shown = new TaskCompletionSource();
            var thread = new Thread(() =>
            {
                standIn._window = new Window { Title = "OpWarden test origin", Width = 640, Height = 360, WindowStartupLocation = WindowStartupLocation.CenterScreen, ShowActivated = false };
                standIn._window.Show();
                standIn.Handle = new WindowInteropHelper(standIn._window).Handle;
                shown.SetResult();
                Dispatcher.Run();
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.IsBackground = true;
            thread.Start();
            await shown.Task;
            return standIn;
        }

        public void MoveBy(double right, double down) => _window!.Dispatcher.Invoke(() =>
        {
            _window.Left += right;
            _window.Top += down;
        });

        public void Dispose() => _window?.Dispatcher.InvokeShutdown();
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct POINT(int X, int Y);

    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    private const nint PerMonitorAwareV2 = -4;

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)] private static partial nint FindWindowExW(nint parent, nint after, string? className, string? title);
    [LibraryImport("user32.dll")] private static partial uint GetWindowThreadProcessId(nint window, out int processId);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsWindowVisible(nint window);
    [LibraryImport("user32.dll")] private static partial uint GetDpiForWindow(nint window);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetCursorPos(out POINT point);
    [LibraryImport("user32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetCursorPos(int x, int y);
    [LibraryImport("user32.dll")] private static partial nint SetThreadDpiAwarenessContext(nint context);
}
