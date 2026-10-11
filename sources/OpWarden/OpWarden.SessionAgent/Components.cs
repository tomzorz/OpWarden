using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace OpWarden.SessionAgent;

// The agent's building blocks. Each has one purpose, and its default look lives in
// Themes/Components.xaml as an implicit style keyed by its type, so no window wires a style
// up. None of them positions itself: margins and alignment belong to the layouts that hold
// them (Layouts.cs).

/// <summary>
/// A window with standard chrome: the status, audit log and rules windows. It loads its own
/// look, and its title bar follows the app theme.
/// </summary>
public class StandardWindow : Window
{
    public StandardWindow()
    {
        SetResourceReference(StyleProperty, typeof(StandardWindow));
        WindowTheme.Follow(this);
    }
}

/// <summary>
/// The frame of a borderless window: backdrop, border, rounded corners and shadow.
/// </summary>
public sealed class WindowFrame : ContentControl;

/// <summary>
/// What a toast reports, which decides its accent colour.
/// </summary>
public enum ToastKind
{
    CachedRead,
    RuleRead,
    Notice,
}

/// <summary>
/// The frame of a toast, with the bar along its top that runs down with its time on screen,
/// in the accent colour of what the toast reports.
/// </summary>
public sealed class ToastFrame : ContentControl
{
    public static readonly DependencyProperty KindProperty =
        DependencyProperty.Register(nameof(Kind), typeof(ToastKind), typeof(ToastFrame), new PropertyMetadata(ToastKind.Notice));

    public static readonly DependencyProperty RemainingLifetimeProperty =
        DependencyProperty.Register(nameof(RemainingLifetime), typeof(double), typeof(ToastFrame), new PropertyMetadata(1.0));

    public static readonly DependencyProperty SitsOnWindowProperty =
        DependencyProperty.Register(nameof(SitsOnWindow), typeof(bool), typeof(ToastFrame), new PropertyMetadata(false));

    private FrameworkElement? _inside;

    public ToastKind Kind
    {
        get => (ToastKind)GetValue(KindProperty);
        set => SetValue(KindProperty, value);
    }

    /// <summary>
    /// The share of the toast's time on screen still left, from 1 down to 0.
    /// </summary>
    public double RemainingLifetime
    {
        get => (double)GetValue(RemainingLifetimeProperty);
        set => SetValue(RemainingLifetimeProperty, value);
    }

    /// <summary>
    /// True while the toast sits on the top edge of the window its read came from; its
    /// bottom corners are then square, to meet that edge.
    /// </summary>
    public bool SitsOnWindow
    {
        get => (bool)GetValue(SitsOnWindowProperty);
        set => SetValue(SitsOnWindowProperty, value);
    }

    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        if (_inside is not null) _inside.SizeChanged -= OnInsideSizeChanged;
        _inside = GetTemplateChild("PART_Inside") as FrameworkElement;
        if (_inside is not null) _inside.SizeChanged += OnInsideSizeChanged;
        ClipInside();
    }

    private void OnInsideSizeChanged(object sender, SizeChangedEventArgs e) => ClipInside();

    /// <summary>
    /// The lifetime bar runs to the frame's edges, so the inside is clipped to the
    /// outline's rounded top corners. Nothing inside reaches the bottom corners, which turn
    /// square when the toast sits on a window.
    /// </summary>
    private void ClipInside()
    {
        if (_inside is null) return;
        var radius = TryFindResource("ToastFrameInsideRadius") is double value ? value : 0;
        var clip = new RectangleGeometry(new Rect(_inside.RenderSize), radius, radius);
        clip.Freeze();
        _inside.Clip = clip;
    }
}

/// <summary>
/// How much of a toast's time on screen is left, as a bar that runs down to nothing.
/// </summary>
public sealed class ToastLifetimeBar : ProgressBar;

/// <summary>
/// The details of what a window is about, set apart from the window's backdrop: the request
/// a prompt decides, what the broker reports, the selected audit entry or rule.
/// </summary>
public sealed class DetailsPanel : Border;

/// <summary>
/// OpWarden's shield, beside the question a prompt asks.
/// </summary>
public sealed class OpWardenMark : Control;

/// <summary>
/// The shield in the colour of how the session agent stands with the broker.
/// </summary>
public sealed class BrokerLinkGlyph : Control
{
    public static readonly DependencyProperty StateProperty =
        DependencyProperty.Register(nameof(State), typeof(LinkState), typeof(BrokerLinkGlyph), new PropertyMetadata(LinkState.Waiting, (glyph, _) => ((BrokerLinkGlyph)glyph).ShowState()));

    public BrokerLinkGlyph() => ShowState();

    public LinkState State
    {
        get => (LinkState)GetValue(StateProperty);
        set => SetValue(StateProperty, value);
    }

    /// <summary>
    /// The palette brush that colours a state. The tray icon borrows it, so the shield in
    /// the tray and the one in the status window always agree.
    /// </summary>
    public static string BrushKeyFor(LinkState state) => state switch
    {
        LinkState.Connected => "BrokerConnectedBrush",
        LinkState.Refused => "BrokerRefusedBrush",
        _ => "BrokerWaitingBrush",
    };

    private void ShowState() => SetResourceReference(ForegroundProperty, BrushKeyFor(State));
}

/// <summary>
/// What the prompt's decision buttons share: a hover colour beside the background.
/// </summary>
public abstract class DecisionButton : Button
{
    public static readonly DependencyProperty HoverBackgroundProperty =
        DependencyProperty.Register(nameof(HoverBackground), typeof(Brush), typeof(DecisionButton), new PropertyMetadata(null));

    public Brush? HoverBackground
    {
        get => (Brush?)GetValue(HoverBackgroundProperty);
        set => SetValue(HoverBackgroundProperty, value);
    }
}

/// <summary>
/// A prompt decision that lets the invocation run.
/// </summary>
public sealed class AllowDecisionButton : DecisionButton;

/// <summary>
/// A prompt decision that refuses the invocation.
/// </summary>
public sealed class DenyDecisionButton : DecisionButton;

/// <summary>
/// A secondary command in a window, such as refreshing or opening a folder.
/// </summary>
public class CommandButton : Button;

/// <summary>
/// A command that asks for elevation before it acts; it carries the shield.
/// </summary>
public sealed class AdministratorCommandButton : CommandButton;

/// <summary>
/// The close cross of a borderless window.
/// </summary>
public sealed class WindowCloseButton : Button;

/// <summary>
/// Pins one request-tuple field in an <c>always-</c> decision (REQ-RULE-7).
/// </summary>
public sealed class FieldPinCheckBox : CheckBox;

/// <summary>
/// Narrows the records a window shows, such as to the problems only.
/// </summary>
public sealed class RecordFilterToggle : CheckBox;

/// <summary>
/// One option of the prompt's cache-grant choice (REQ-RULE-19).
/// </summary>
public sealed class CacheChoiceSegment : RadioButton;

/// <summary>
/// The free-text filter over a window's records, with a placeholder that says what it
/// matches while it is empty.
/// </summary>
public sealed class RecordFilterBox : TextBox
{
    public static readonly DependencyProperty PlaceholderProperty =
        DependencyProperty.Register(nameof(Placeholder), typeof(string), typeof(RecordFilterBox), new PropertyMetadata(""));

    public string Placeholder
    {
        get => (string)GetValue(PlaceholderProperty);
        set => SetValue(PlaceholderProperty, value);
    }
}

/// <summary>
/// Read-only tabular records: audit entries, stored rules.
/// </summary>
public sealed class RecordGrid : DataGrid;

/// <summary>
/// The title in a window's own header.
/// </summary>
public sealed class WindowTitleText : TextBlock;

/// <summary>
/// The question a prompt asks: who wants to do what.
/// </summary>
public sealed class PromptTitleText : TextBlock;

/// <summary>
/// The time a prompt has left before it denies; urgent in its last seconds.
/// </summary>
public sealed class PromptCountdownText : TextBlock
{
    public static readonly DependencyProperty IsUrgentProperty =
        DependencyProperty.Register(nameof(IsUrgent), typeof(bool), typeof(PromptCountdownText), new PropertyMetadata(false));

    public bool IsUrgent
    {
        get => (bool)GetValue(IsUrgentProperty);
        set => SetValue(IsUrgentProperty, value);
    }
}

/// <summary>
/// The heading over one part of a window.
/// </summary>
public sealed class SectionHeadingText : TextBlock;

/// <summary>
/// The name of a field beside its value.
/// </summary>
public sealed class FieldLabelText : TextBlock;

/// <summary>
/// A vault, item, key, command or path on one line: what is being accessed, set apart from
/// prose.
/// </summary>
public sealed class SecretValueText : TextBlock;

/// <summary>
/// A value shown in full over as many lines as it takes: a caller chain, an invocation.
/// </summary>
public sealed class FullValueText : TextBlock;

/// <summary>
/// One field of a stored rule: a pinned value reads as a value, a wildcard as the
/// placeholder it is.
/// </summary>
public sealed class RuleFieldValueText : TextBlock;

/// <summary>
/// An audit entry's verdict; a deny stands out.
/// </summary>
public sealed class AuditVerdictText : TextBlock;

/// <summary>
/// Why an audit entry got its verdict; an answer from the cache is marked.
/// </summary>
public sealed class AuditReasonText : TextBlock;

/// <summary>
/// Who called, in one column of a list line.
/// </summary>
public sealed class CallerNameText : TextBlock;

/// <summary>
/// Ordinary explanatory text.
/// </summary>
public sealed class BodyText : TextBlock;

/// <summary>
/// Secondary text: hints, timestamps, footers.
/// </summary>
public sealed class HintText : TextBlock;

/// <summary>
/// What went wrong, where the window could not show what it meant to.
/// </summary>
public sealed class ErrorMessageText : TextBlock;

/// <summary>
/// The first line of a toast.
/// </summary>
public sealed class ToastTitleText : TextBlock;
