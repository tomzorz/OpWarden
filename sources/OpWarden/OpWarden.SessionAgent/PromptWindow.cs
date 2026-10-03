using OpWarden.Core.Agent;
using static OpWarden.SessionAgent.Native;

namespace OpWarden.SessionAgent;

/// <summary>
/// The prompt (REQ-RULE-5 to REQ-RULE-7, REQ-RULE-14, REQ-RULE-19): the request, a pin per
/// field for <c>always-</c> decisions, the cache-grant choice, the decision buttons and
/// the time left.
/// </summary>
/// <remarks>
/// It appears topmost without taking focus, so a keystroke meant for a terminal cannot
/// answer it, and it has no default button. Closing it or pressing Esc after clicking
/// into it is <c>disallow-once</c>. After a decision the controls lock until the broker
/// closes the prompt.
/// </remarks>
internal sealed unsafe class PromptWindow : Window
{
    public const string ClassName = "OpWardenPrompt";

    private const int PinBase = 100, CacheId = 200, ButtonBase = 300;
    private const nuint CountdownTimer = 1;

    private static readonly (string Label, PromptDecision Decision)[] AllButtons =
    [
        ("Always allow", PromptDecision.AlwaysAllow),
        ("Always disallow", PromptDecision.AlwaysDisallow),
        ("Allow once", PromptDecision.AllowOnce),
        ("Disallow once", PromptDecision.DisallowOnce),
    ];

    private readonly ShowPrompt _prompt;
    private readonly PromptLayout _layout;
    private readonly Action<DecisionMade> _decide;
    private readonly uint _dpi = GetDpiForSystem();
    private readonly List<nint> _controls = [];
    private readonly nint[] _pins = new nint[5];
    private nint _cache;
    private nint _countdown;
    private nint _font;
    private nint _titleFont;
    private bool _decided;

    public PromptWindow(ShowPrompt prompt, Action<DecisionMade> decide)
    {
        _prompt = prompt;
        _layout = PromptLayout.From(prompt);
        _decide = decide;
        CreateFonts();

        var clientHeight = Build(measureOnly: true);
        var rect = new RECT { Right = Scale(Width), Bottom = clientHeight };
        const uint style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
        const uint exStyle = WS_EX_TOPMOST | WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT;
        AdjustWindowRectExForDpi(&rect, style, false, exStyle, _dpi);
        var (x, y) = CenterOnWorkArea(rect.Right - rect.Left, rect.Bottom - rect.Top);

        Create(ClassName, exStyle, "OpWarden", style, x, y, rect.Right - rect.Left, rect.Bottom - rect.Top);
        Build(measureOnly: false);
        Tick();
        SetTimer(Handle, CountdownTimer, 1000, 0);

        ShowWindow(Handle, SW_SHOWNOACTIVATE);
        SetWindowPos(Handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        var flash = new FLASHWINFO { cbSize = (uint)sizeof(FLASHWINFO), hwnd = Handle, dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG };
        FlashWindowEx(&flash);
    }

    public Guid PromptId => _prompt.PromptId;

    private const int Width = 480, Margin = 16, Line = 22, LabelWidth = 80, ButtonHeight = 28, Gap = 8;

    /// <summary>
    /// Lays the controls out top to bottom, creating them unless only measuring, and
    /// returns the client height in pixels.
    /// </summary>
    private int Build(bool measureOnly)
    {
        var top = Scale(Margin);
        var left = Scale(Margin);
        var inner = Scale(Width - 2 * Margin);
        var line = Scale(Line);

        void Text(string text, int height, nint font, uint extra = 0)
        {
            if (!measureOnly) Add("STATIC", text, SS_LEFT | SS_ENDELLIPSIS | extra, left, top, inner, height, font);
            top += height;
        }

        Text(_layout.Title, Scale(28), _titleFont);
        var countdownWidth = Scale(150);
        if (!measureOnly)
        {
            Add("STATIC", _layout.Command, SS_LEFT | SS_ENDELLIPSIS, left, top, inner - countdownWidth, line, _font);
            _countdown = Add("STATIC", "", SS_RIGHT, left + inner - countdownWidth, top, countdownWidth, line, _font);
        }

        top += line;
        top += Scale(Gap);

        for (var i = 0; i < _layout.Fields.Count; i++)
        {
            var field = _layout.Fields[i];
            if (!measureOnly)
            {
                if (_layout.OffersAlways)
                {
                    // The checkbox is the field label: checked pins the field in an always-
                    // decision, unchecked makes it a wildcard. Unknown fields cannot be pinned.
                    _pins[i] = Add("BUTTON", field.Label, BS_AUTOCHECKBOX | WS_TABSTOP, left, top, Scale(LabelWidth), line, _font);
                    SendMessageW(_pins[i], BM_SETCHECK, field.Pinnable ? 1 : 0, 0);
                    EnableWindow(_pins[i], field.Pinnable);
                }
                else
                {
                    Add("STATIC", field.Label, SS_LEFT, left, top + Scale(3), Scale(LabelWidth), line, _font);
                }

                Add("STATIC", field.Value, SS_LEFT | SS_ENDELLIPSIS, left + Scale(LabelWidth), top + Scale(3), inner - Scale(LabelWidth), line, _font);
            }

            top += line;
        }

        if (_layout.References.Count > 0)
        {
            top += Scale(Gap);
            Text("Secret references:", line, _font);
            foreach (var reference in _layout.References) Text("    " + reference, line, _font);
        }

        if (_layout.ReferencesNote is { } note) Text(note, line * 2, _font);

        if (_layout.OffersAlways) Text("Checked fields are pinned in an always- rule; unchecked fields match anything.", line, _font);

        if (_layout.OffersCacheGrant)
        {
            top += Scale(Gap);
            if (!measureOnly)
            {
                _cache = Add("COMBOBOX", "", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, left, top, Scale(220), Scale(200), _font);
                foreach (var (label, _) in PromptLayout.CacheChoices) SendMessageW(_cache, CB_ADDSTRING, 0, label);
                SendMessageW(_cache, CB_SETCURSEL, 0, 0);
            }

            top += Scale(ButtonHeight);
        }

        top += Scale(Gap * 2);
        var buttons = AllButtons.Where(b => _layout.OffersAlways || b.Decision is PromptDecision.AllowOnce or PromptDecision.DisallowOnce).ToList();
        var buttonWidth = (inner - Scale(Gap) * (buttons.Count - 1)) / buttons.Count;
        for (var i = 0; i < buttons.Count && !measureOnly; i++)
        {
            var id = ButtonBase + (int)buttons[i].Decision;
            Add("BUTTON", buttons[i].Label, BS_PUSHBUTTON | WS_TABSTOP, left + i * (buttonWidth + Scale(Gap)), top, buttonWidth, Scale(ButtonHeight), _font, id);
        }

        return top + Scale(ButtonHeight) + Scale(Margin);
    }

    protected override nint? OnMessage(uint message, nint wParam, nint lParam)
    {
        switch (message)
        {
            case WM_COMMAND:
                var id = (int)(wParam & 0xFFFF);
                if (id is >= ButtonBase and < ButtonBase + 4) Decide((PromptDecision)(id - ButtonBase));
                else if (id == IDCANCEL) Decide(PromptDecision.DisallowOnce);
                return 0;
            case WM_CLOSE:
                Decide(PromptDecision.DisallowOnce);
                return 0;
            case WM_TIMER:
                Tick();
                return 0;
            case WM_CTLCOLORSTATIC:
            case WM_CTLCOLORBTN:
                _ = SetBkMode(wParam, TRANSPARENT);
                return GetSysColorBrush(COLOR_WINDOW);
            case WM_DESTROY:
                KillTimer(Handle, CountdownTimer);
                DeleteObject(_font);
                DeleteObject(_titleFont);
                return 0;
            default:
                return null;
        }
    }

    /// <summary>
    /// Sends the decision once. Every decision passes through here: the one place an
    /// input check would go if spec section 17's open decision on scripted input lands
    /// that way.
    /// </summary>
    private void Decide(PromptDecision decision)
    {
        if (_decided) return;
        if (!_layout.OffersAlways && decision is PromptDecision.AlwaysAllow or PromptDecision.AlwaysDisallow) return;

        var pins = _pins.Select(pin => pin != 0 && SendMessageW(pin, BM_GETCHECK, 0, 0) == 1).ToList();
        var cacheChoice = _cache == 0 ? 0 : (int)SendMessageW(_cache, CB_GETCURSEL, 0, 0);
        _decided = true;
        foreach (var control in _controls) EnableWindow(control, false);
        SetWindowTextW(_countdown, "Sent; waiting for the broker.");
        _decide(DecisionBuilder.Build(_prompt, decision, pins, Math.Max(cacheChoice, 0)));
    }

    private void Tick()
    {
        if (_decided) return;
        var left = (int)Math.Ceiling((_prompt.Deadline - DateTimeOffset.UtcNow).TotalSeconds);
        SetWindowTextW(_countdown, left > 0 ? $"Answer within {left} s" : "Timed out");
    }

    private nint Add(string className, string text, uint style, int x, int y, int width, int height, nint font, int id = 0)
    {
        var control = CreateWindowExW(0, className, text, WS_CHILD | WS_VISIBLE | style, x, y, width, height, Handle, id, GetModuleHandleW(null), 0);
        SendMessageW(control, WM_SETFONT, font, 1);
        _controls.Add(control);
        return control;
    }

    private void CreateFonts()
    {
        var metrics = new NONCLIENTMETRICSW { cbSize = (uint)sizeof(NONCLIENTMETRICSW) };
        SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &metrics, 0, _dpi);
        var message = metrics.lfMessageFont;
        _font = CreateFontIndirectW(&message);
        var title = metrics.lfMessageFont;
        title.lfWeight = 700;
        title.lfHeight = title.lfHeight * 13 / 10;
        _titleFont = CreateFontIndirectW(&title);
    }

    private int Scale(int dip) => dip * (int)_dpi / 96;

    private static (int X, int Y) CenterOnWorkArea(int width, int height)
    {
        var area = default(RECT);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &area, 0);
        return (area.Left + (area.Right - area.Left - width) / 2, area.Top + (area.Bottom - area.Top - height) / 3);
    }
}
