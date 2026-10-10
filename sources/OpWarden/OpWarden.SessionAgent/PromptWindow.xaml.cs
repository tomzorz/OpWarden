using System.ComponentModel;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Threading;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// The prompt (REQ-RULE-5 to REQ-RULE-7, REQ-RULE-14, REQ-RULE-19): the request, a pin per
/// field for <c>always-</c> decisions, the cache-grant choice, the decision buttons and the
/// time left.
/// </summary>
/// <remarks>
/// It appears topmost without taking focus, so a keystroke meant for a terminal cannot
/// answer it, and it has no default button. Closing it, or pressing Esc after clicking into
/// it, is <c>disallow-once</c>. After a decision the controls lock until the broker closes
/// the prompt.
/// </remarks>
public partial class PromptWindow : Window
{
    private readonly ShowPrompt _prompt;
    private readonly PromptLayout _layout;
    private readonly Action<DecisionMade> _decide;
    private readonly List<PromptField> _fields;
    private readonly List<CacheChoiceSegment> _cacheChoices = [];
    private readonly DispatcherTimer _countdown = new() { Interval = TimeSpan.FromSeconds(1) };
    private bool _decided;
    private bool _closedByBroker;

    internal PromptWindow(ShowPrompt prompt, Action<DecisionMade> decide)
    {
        InitializeComponent();
        _prompt = prompt;
        _layout = PromptLayout.From(prompt);
        _decide = decide;

        TitleText.Text = _layout.Title;
        CommandText.Text = _layout.Command;
        _fields = [.. _layout.Fields.Select((field, i) => new PromptField(field, _layout.OffersAlways, PromptLayout.FieldLabels[i]))];
        FieldList.ItemsSource = _fields;

        ReferenceList.ItemsSource = _layout.References;
        ReferencesNoteText.Text = _layout.ReferencesNote ?? "";
        ReferencesNoteText.Visibility = _layout.ReferencesNote is null ? Visibility.Collapsed : Visibility.Visible;
        ReferencesPanel.Visibility = _layout.References.Count > 0 || _layout.ReferencesNote is not null ? Visibility.Visible : Visibility.Collapsed;
        PinHintText.Visibility = _layout.OffersAlways ? Visibility.Visible : Visibility.Collapsed;

        CachePanel.Visibility = _layout.OffersCacheGrant ? Visibility.Visible : Visibility.Collapsed;
        for (var i = 0; i < PromptLayout.CacheChoices.Length; i++)
        {
            var choice = new CacheChoiceSegment
            {
                Content = PromptLayout.CacheChoices[i].Label,
                GroupName = $"cache-{prompt.PromptId:N}",
                IsChecked = i == 0,
                Margin = new Thickness(i == 0 ? 0 : 6, 0, 0, 0),
            };
            AutomationProperties.SetAutomationId(choice, $"CacheChoice{i}");
            _cacheChoices.Add(choice);
            CacheChoices.Children.Add(choice);
        }

        var always = _layout.OffersAlways ? Visibility.Visible : Visibility.Collapsed;
        AlwaysAllowButton.Visibility = always;
        AlwaysDisallowButton.Visibility = always;

        Loaded += (_, _) => PlaceOnWorkArea();
        _countdown.Tick += (_, _) => Tick();
        Tick();
        _countdown.Start();
        UiCapture.WhenRequested(this, "prompt");
    }

    public Guid PromptId => _prompt.PromptId;

    /// <summary>
    /// Takes the prompt down: the broker decided it is over.
    /// </summary>
    internal void CloseForBroker()
    {
        _closedByBroker = true;
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Only the broker takes a prompt down. The user's close is a disallow-once, which
        // the broker answers by closing the prompt.
        if (!_closedByBroker)
        {
            e.Cancel = true;
            Decide(PromptDecision.DisallowOnce);
        }

        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _countdown.Stop();
        base.OnClosed(e);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Decide(PromptDecision.DisallowOnce);
            e.Handled = true;
        }

        base.OnKeyDown(e);
    }

    /// <summary>
    /// Sends the decision once. Every decision passes through here: the one place an input
    /// check would go if spec section 17's open decision on scripted input lands that way.
    /// </summary>
    private void Decide(PromptDecision decision)
    {
        if (_decided) return;
        if (!_layout.OffersAlways && decision is PromptDecision.AlwaysAllow or PromptDecision.AlwaysDisallow) return;

        var pins = _fields.Select(field => field.IsPinned).ToList();
        var cacheChoice = Math.Max(0, _cacheChoices.FindIndex(choice => choice.IsChecked == true));
        _decided = true;
        _countdown.Stop();
        FieldList.IsEnabled = false;
        CachePanel.IsEnabled = false;
        foreach (var button in new UIElement[] { AllowOnceButton, AlwaysAllowButton, DisallowOnceButton, AlwaysDisallowButton }) button.IsEnabled = false;
        CountdownText.Text = "Sent; waiting for the broker";
        _decide(DecisionBuilder.Build(_prompt, decision, pins, cacheChoice));
    }

    private void Tick()
    {
        if (_decided) return;
        var left = (int)Math.Ceiling((_prompt.Deadline - DateTimeOffset.UtcNow).TotalSeconds);
        CountdownText.Text = left > 0 ? $"{left} s left" : "Timed out";
        if (left <= 10) CountdownText.SetResourceReference(ForegroundProperty, "CountdownUrgentTextBrush");
    }

    private void PlaceOnWorkArea()
    {
        var area = SystemParameters.WorkArea;
        Left = area.Left + (area.Width - ActualWidth) / 2;
        Top = area.Top + (area.Height - ActualHeight) / 3;
    }

    private void OnHeaderMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed) DragMove();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Decide(PromptDecision.DisallowOnce);

    private void OnAllowOnceClick(object sender, RoutedEventArgs e) => Decide(PromptDecision.AllowOnce);

    private void OnAlwaysAllowClick(object sender, RoutedEventArgs e) => Decide(PromptDecision.AlwaysAllow);

    private void OnDisallowOnceClick(object sender, RoutedEventArgs e) => Decide(PromptDecision.DisallowOnce);

    private void OnAlwaysDisallowClick(object sender, RoutedEventArgs e) => Decide(PromptDecision.AlwaysDisallow);
}

/// <summary>
/// One request-tuple field on the prompt, its pin bound two-way.
/// </summary>
public sealed class PromptField
{
    internal PromptField(FieldRow row, bool offersAlways, string fieldName)
    {
        Label = row.Label;
        Value = row.Value;
        Pinnable = row.Pinnable;
        IsPinned = row.Pinnable;
        PinVisibility = offersAlways ? Visibility.Visible : Visibility.Collapsed;
        LabelVisibility = offersAlways ? Visibility.Collapsed : Visibility.Visible;
        PinAutomationId = $"Pin{fieldName}";
    }

    public string Label { get; }

    public string Value { get; }

    public bool Pinnable { get; }

    public bool IsPinned { get; set; }

    public Visibility PinVisibility { get; }

    public Visibility LabelVisibility { get; }

    public string PinAutomationId { get; }
}
