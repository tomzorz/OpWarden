using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Media.Animation;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// One toast: a read OpWarden let through without asking, or a notice from the broker.
/// It never takes focus, opens the audit log when clicked, and counts its time on screen
/// down in the bar along its top, holding the count while the pointer rests on it
/// (REQ-RULE-47, REQ-RULE-48).
/// </summary>
public partial class ToastWindow : Window
{
    /// <summary>
    /// The width of a toast that does not take its origin window's width, in DIPs.
    /// </summary>
    internal const double StandardWidth = 400;

    private static readonly TimeSpan ReadLifetime = TimeSpan.FromSeconds(12);
    private static readonly TimeSpan NoticeLifetime = TimeSpan.FromSeconds(30);

    private AnimationClock? _countdown;

    internal ToastWindow(Action clicked)
    {
        InitializeComponent();
        Width = StandardWidth;
        MouseEnter += (_, _) => _countdown?.Controller.Pause();
        MouseLeave += (_, _) => _countdown?.Controller.Resume();
        Frame.MouseLeftButtonUp += (_, e) =>
        {
            if (e.Handled) return;
            clicked();
            Close();
        };
        Closed += (_, _) => _countdown?.Controller.Stop();
        UiCapture.WhenRequested(this, "toast");
    }

    /// <summary>
    /// The window the read came from (REQ-RULE-41), or 0 for a notice and for a read whose
    /// window could not be found.
    /// </summary>
    internal nint Origin { get; init; }

    /// <summary>
    /// The read this toast reports, while it reports one; a burst grows it in place.
    /// </summary>
    internal ReadToast? Read { get; private set; }

    /// <summary>
    /// The transparent band around the frame, in DIPs: room for the frame's shadow.
    /// </summary>
    internal Thickness FrameInset => FrameHost.Margin;

    /// <summary>
    /// True while the toast sits on its origin window's top edge.
    /// </summary>
    internal bool SitsOnWindow
    {
        get => Frame.SitsOnWindow;
        set => Frame.SitsOnWindow = value;
    }

    /// <summary>
    /// The size this toast would take at another width, in DIPs, found without resizing it.
    /// </summary>
    internal Size SizeAt(double width)
    {
        var content = (UIElement)Content;
        content.Measure(new Size(width, double.PositiveInfinity));
        var height = content.DesiredSize.Height;

        // The next layout pass measures it again at its real width.
        content.InvalidateMeasure();
        return new Size(width, height);
    }

    internal void ShowRead(ReadToast toast)
    {
        Read = toast;
        AutomationProperties.SetAutomationId(this, "ReadToast");
        TitleText.Text = toast.Title;
        LinesList.ItemsSource = toast.Lines;
        LinesList.Visibility = Visibility.Visible;
        MessageText.Visibility = Visibility.Collapsed;
        FooterText.Text = toast.Footer(DateTimeOffset.UtcNow);
        Frame.SetResourceReference(ToastFrame.AccentProperty, toast.Source == ReadSource.Cache ? "CachedReadAccentBrush" : "RuleReadAccentBrush");
        CountDown(ReadLifetime);
    }

    internal void ShowNotice(ShowNotice notice)
    {
        AutomationProperties.SetAutomationId(this, "NoticeToast");
        TitleText.Text = notice.Title;
        LinesList.Visibility = Visibility.Collapsed;
        MessageText.Text = notice.Text;
        FooterText.Text = "Click for the audit log";
        Frame.SetResourceReference(ToastFrame.AccentProperty, "NoticeAccentBrush");
        CountDown(NoticeLifetime);
    }

    /// <summary>
    /// Starts the toast's time on screen over: the bar fills and runs down to zero, and the
    /// toast closes when it gets there. The clock is the timer, so the bar and the close
    /// cannot drift apart, and pausing it holds both.
    /// </summary>
    private void CountDown(TimeSpan lifetime)
    {
        _countdown?.Controller.Stop();
        var countdown = new DoubleAnimation(1, 0, lifetime).CreateClock();
        countdown.Completed += (_, _) =>
        {
            if (ReferenceEquals(countdown, _countdown)) Close();
        };
        _countdown = countdown;
        Frame.ApplyAnimationClock(ToastFrame.RemainingLifetimeProperty, countdown);
        if (IsMouseOver) countdown.Controller.Pause();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnPreviewMouseRightButtonUp(MouseButtonEventArgs e)
    {
        // A right click dismisses, as Windows' own notifications do.
        e.Handled = true;
        Close();
    }
}
