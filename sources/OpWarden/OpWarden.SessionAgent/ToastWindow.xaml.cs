using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Threading;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// One toast: a read OpWarden let through without asking, or a notice from the broker.
/// It never takes focus, lives a few seconds unless the pointer rests on it, and opens the
/// audit log when clicked.
/// </summary>
public partial class ToastWindow : Window
{
    private static readonly TimeSpan ReadLifetime = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan NoticeLifetime = TimeSpan.FromSeconds(20);

    private readonly DispatcherTimer _lifetime = new();

    internal ToastWindow(Action clicked)
    {
        InitializeComponent();
        _lifetime.Tick += (_, _) => Close();
        MouseEnter += (_, _) => _lifetime.Stop();
        MouseLeave += (_, _) => _lifetime.Start();
        Frame.MouseLeftButtonUp += (_, e) =>
        {
            if (e.Handled) return;
            clicked();
            Close();
        };
        Closed += (_, _) => _lifetime.Stop();
        UiCapture.WhenRequested(this, "toast");
    }

    /// <summary>
    /// The read this toast reports, while it reports one; a burst grows it in place.
    /// </summary>
    internal ReadToast? Read { get; private set; }

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
        Restart(ReadLifetime);
    }

    internal void ShowNotice(ShowNotice notice)
    {
        AutomationProperties.SetAutomationId(this, "NoticeToast");
        TitleText.Text = notice.Title;
        LinesList.Visibility = Visibility.Collapsed;
        MessageText.Text = notice.Text;
        FooterText.Text = "Click for the audit log";
        Frame.SetResourceReference(ToastFrame.AccentProperty, "NoticeAccentBrush");
        Restart(NoticeLifetime);
    }

    private void Restart(TimeSpan lifetime)
    {
        _lifetime.Stop();
        _lifetime.Interval = lifetime;
        if (!IsMouseOver) _lifetime.Start();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnPreviewMouseRightButtonUp(MouseButtonEventArgs e)
    {
        // A right click dismisses, as Windows' own notifications do.
        e.Handled = true;
        Close();
    }
}
