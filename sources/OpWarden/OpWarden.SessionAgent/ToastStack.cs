using System.Windows;
using OpWarden.Core.Agent;

namespace OpWarden.SessionAgent;

/// <summary>
/// Keeps the open toasts stacked upward from the corner above the notification area,
/// newest at the bottom, a few at most.
/// </summary>
internal sealed class ToastStack(Action openAuditLog)
{
    private const int MaxOpen = 4;

    private readonly List<ToastWindow> _open = [];

    /// <summary>
    /// Shows a read, folding it into the newest read toast when it continues that burst.
    /// </summary>
    public void ShowRead(ReadAllowed read)
    {
        if (_open.LastOrDefault(t => t.Read is not null) is { Read: { } current } toast && current.Absorb(read) is { } merged)
        {
            toast.ShowRead(merged);
            return;
        }

        var window = new ToastWindow(openAuditLog);
        window.ShowRead(ReadToast.Start(read));
        Open(window);
    }

    public void ShowNotice(ShowNotice notice)
    {
        var window = new ToastWindow(openAuditLog);
        window.ShowNotice(notice);
        Open(window);
    }

    private void Open(ToastWindow toast)
    {
        toast.Closed += (_, _) =>
        {
            _open.Remove(toast);
            Reflow();
        };
        toast.SizeChanged += (_, _) => Reflow();
        _open.Add(toast);
        while (_open.Count > MaxOpen) _open[0].Close();

        // Off screen until it has a size to place it by.
        toast.Left = SystemParameters.VirtualScreenLeft - 10_000;
        toast.Show();
        Reflow();
    }

    private void Reflow()
    {
        var area = SystemParameters.WorkArea;
        var bottom = area.Bottom;
        for (var i = _open.Count - 1; i >= 0; i--)
        {
            var toast = _open[i];
            toast.Left = area.Right - toast.ActualWidth;
            toast.Top = bottom - toast.ActualHeight;
            bottom = toast.Top;
        }
    }
}
