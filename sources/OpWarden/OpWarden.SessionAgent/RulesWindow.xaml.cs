using System.Windows;
using System.Windows.Controls;
using OpWarden.Core;
using OpWarden.Core.Management;
using OpWarden.Core.Rules;

namespace OpWarden.SessionAgent;

/// <summary>
/// The management window (spec glossary): the stored rules with their notices
/// (REQ-RULE-29 to REQ-RULE-31) and the vaults that always prompt.
/// </summary>
/// <remarks>
/// Anyone may look. Changing a rule takes an elevated administrator (REQ-TRUST-5), so an
/// unelevated window offers to restart itself elevated, and only the elevated copy edits.
/// The broker checks the elevation again on every change; this window's buttons are a
/// courtesy, not the control.
/// </remarks>
public partial class RulesWindow : Window
{
    private readonly ManagementClient _management;
    private readonly AgentOptions _options;

    internal RulesWindow(ManagementClient management, AgentOptions options)
    {
        InitializeComponent();
        (_management, _options) = (management, options);
        Editable = Elevation.IsElevated;
        DataContext = this;
        ModeText.Text = Editable
            ? "Elevated: changes apply at once, and the audit log records each one."
            : "Read-only. Changing a rule takes an administrator (REQ-TRUST-5).";
        ElevateButton.Visibility = Editable ? Visibility.Collapsed : Visibility.Visible;
        RemoveButton.IsEnabled = false;
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
        WindowTheme.Follow(this);
        UiCapture.WhenRequested(this, "rules");
    }

    /// <summary>
    /// True in the elevated copy, the only one that offers changes.
    /// </summary>
    public bool Editable { get; }

    private async Task LoadAsync() => Show(await _management.TrySendAsync(new ListRules()).ConfigureAwait(true));

    private void Show(ManagementResponse response)
    {
        StatusText.Text = response.Error ?? "";
        if (response.Rules is not { } rules) return;

        var notices = response.Notices ?? [];
        var rows = rules.Rules.Select(rule => RuleRow.From(rule, [.. notices.Where(n => n.Rule == rule)], Editable)).ToList();
        Records.ItemsSource = rows;
        PromptAlwaysList.ItemsSource = rules.PromptAlwaysVaults;
        PromptAlwaysPanel.Visibility = rules.PromptAlwaysVaults.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        ShowSelected();
        if (StatusText.Text.Length == 0) StatusText.Text = rows.Count == 1 ? "1 rule" : $"{rows.Count} rules";
    }

    private void ShowSelected()
    {
        var row = Records.SelectedItem as RuleRow;
        NoticeList.ItemsSource = row?.Notices;
        NoNoticesText.Text = row is null ? "Select a rule to see what OpWarden noticed about it." : "Nothing to note about this rule.";
        NoNoticesText.Visibility = row is { Notices.Count: > 0 } ? Visibility.Collapsed : Visibility.Visible;
        RemoveButton.IsEnabled = Editable && row is not null;
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e) => ShowSelected();

    private async void OnRemoveClick(object sender, RoutedEventArgs e)
    {
        if (Records.SelectedItem is RuleRow row) Show(await _management.TrySendAsync(new RemoveRule(row.Rule)).ConfigureAwait(true));
    }

    private async void OnAddSuggestionClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is NoticeView { Suggestion: { } rule }) Show(await _management.TrySendAsync(new AddRules([rule])).ConfigureAwait(true));
    }

    private async void OnClearPromptAlwaysClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string vault) Show(await _management.TrySendAsync(new SetPromptAlways(vault, false)).ConfigureAwait(true));
    }

    private async void OnRefreshClick(object sender, RoutedEventArgs e) => await LoadAsync().ConfigureAwait(true);

    private void OnElevateClick(object sender, RoutedEventArgs e)
    {
        if (Elevation.StartRulesEditor(_options)) Close();
    }
}

/// <summary>
/// One stored rule as the rules window lists it; a wildcard field reads "any".
/// </summary>
public sealed record RuleRow(Rule Rule, string Verdict, string Caller, string Action, string Vault, string Item, string Key, string Cache, IReadOnlyList<NoticeView> Notices)
{
    public string NoticeCount => Notices.Count == 0 ? "" : Notices.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);

    internal static RuleRow From(Rule rule, IReadOnlyList<RuleNotice> notices, bool editable) => new(
        rule,
        rule.Verdict == Core.Verdict.Allow ? "allow" : "deny",
        rule.Caller?.Name ?? "any",
        rule.Action?.ToString().ToLowerInvariant() ?? "any",
        rule.Vault ?? "any",
        rule.Item ?? "any",
        rule.Key ?? "any",
        rule.CacheGrant switch
        {
            CacheTtl.FifteenMinutes => "15 min",
            CacheTtl.OneHour => "1 h",
            CacheTtl.EightHours => "8 h",
            _ => "",
        },
        [.. notices.Select(notice => NoticeView.From(notice, editable))]);
}

/// <summary>
/// One notice about a rule (REQ-RULE-29 to REQ-RULE-31), with the matching rule to add
/// when there is exactly one.
/// </summary>
public sealed record NoticeView(string Text, Rule? Suggestion, bool CanApply)
{
    public Visibility SuggestionVisibility => Suggestion is null ? Visibility.Collapsed : Visibility.Visible;

    internal static NoticeView From(RuleNotice notice, bool editable)
    {
        var field = notice.Field switch
        {
            AliasKind.Vault => "vault",
            AliasKind.Item => "item",
            _ => "key",
        };
        var text = notice.Kind switch
        {
            NoticeKind.OtherFormKnown => $"The {field} \"{notice.PinnedValue}\" is also \"{notice.OtherForms[0]}\", and no rule pins that form, so a request naming it that way prompts.",
            NoticeKind.OtherFormAmbiguous => $"The {field} \"{notice.PinnedValue}\" has several other forms ({string.Join(", ", notice.OtherForms)}), so no single matching rule can be offered.",
            _ => $"The {field} is pinned as \"{notice.PinnedValue}\" only. A request naming it by its other form prompts until OpWarden has seen both forms together.",
        };
        return new NoticeView(text, notice.Suggestion, editable);
    }
}
