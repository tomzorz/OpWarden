using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace OpWarden.SessionAgent;

// The agent's building blocks. Each has one purpose, and its default look lives in
// Themes/Components.xaml as an implicit style keyed by its type, so no window wires a style
// up. None of them positions itself: margins and alignment belong to the layouts that hold
// them.

/// <summary>
/// The frame of a borderless window: backdrop, border, rounded corners and shadow.
/// </summary>
public sealed class WindowFrame : ContentControl;

/// <summary>
/// The frame of a toast, with the accent strip that says what kind of event it reports.
/// </summary>
public sealed class ToastFrame : ContentControl
{
    public static readonly DependencyProperty AccentProperty =
        DependencyProperty.Register(nameof(Accent), typeof(Brush), typeof(ToastFrame), new PropertyMetadata(null));

    public Brush? Accent
    {
        get => (Brush?)GetValue(AccentProperty);
        set => SetValue(AccentProperty, value);
    }
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
/// The heading over one part of a window.
/// </summary>
public sealed class SectionHeadingText : TextBlock;

/// <summary>
/// The name of a field beside its value.
/// </summary>
public sealed class FieldLabelText : TextBlock;

/// <summary>
/// A vault, item, key, command or path: what is being accessed, set apart from prose.
/// </summary>
public sealed class SecretValueText : TextBlock;

/// <summary>
/// Ordinary explanatory text.
/// </summary>
public sealed class BodyText : TextBlock;

/// <summary>
/// Secondary text: hints, timestamps, footers.
/// </summary>
public sealed class HintText : TextBlock;

/// <summary>
/// The first line of a toast.
/// </summary>
public sealed class ToastTitleText : TextBlock;
