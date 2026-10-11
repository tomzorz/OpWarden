using System.Runtime.ExceptionServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using OpWarden.SessionAgent;

namespace OpWarden.Tests;

/// <summary>
/// The spacing panel every window lays out with: one gap between neighbours, none for a
/// collapsed child, and the leftover space for the child that fills.
/// </summary>
public sealed class SessionAgentLayoutTests
{
    [Fact]
    public void Children_stack_with_one_gap_between_each_neighbouring_pair() => OnSta(() =>
    {
        var panel = Stack(Orientation.Vertical, 6, Tall(20), Tall(20), Tall(20));

        Lay(panel, new Size(100, double.PositiveInfinity));

        Assert.Equal(72, panel.DesiredSize.Height);
        Assert.Equal([0.0, 26, 52], Slots(panel).Select(slot => slot.Top));
    });

    [Fact]
    public void A_collapsed_child_takes_no_gap() => OnSta(() =>
    {
        var collapsed = Tall(20);
        collapsed.Visibility = Visibility.Collapsed;
        var panel = Stack(Orientation.Vertical, 6, Tall(20), collapsed, Tall(20));

        Lay(panel, new Size(100, double.PositiveInfinity));

        Assert.Equal(46, panel.DesiredSize.Height);
        Assert.Equal(26, Slots(panel)[2].Top);
    });

    [Fact]
    public void A_filling_child_takes_the_space_its_siblings_leave() => OnSta(() =>
    {
        var fill = new Border();
        SpacedStackPanel.SetFill(fill, true);
        var panel = Stack(Orientation.Horizontal, 8, Wide(40), fill, Wide(30));

        Lay(panel, new Size(200, 50));

        Assert.Equal([new Rect(0, 0, 40, 50), new Rect(48, 0, 114, 50), new Rect(170, 0, 30, 50)], Slots(panel));
    });

    /// <summary>
    /// Runs a test on an STA thread, which WPF elements require, and rethrows its failure
    /// here.
    /// </summary>
    private static void OnSta(Action test)
    {
        ExceptionDispatchInfo? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                test();
            }
            catch (Exception e)
            {
                failure = ExceptionDispatchInfo.Capture(e);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        failure?.Throw();
    }

    private static Border Tall(double height) => new() { Height = height };

    private static Border Wide(double width) => new() { Width = width };

    private static SpacedStackPanel Stack(Orientation orientation, double spacing, params UIElement[] children)
    {
        var panel = new SpacedStackPanel { Orientation = orientation, Spacing = spacing };
        foreach (var child in children) panel.Children.Add(child);
        return panel;
    }

    private static void Lay(SpacedStackPanel panel, Size available)
    {
        panel.Measure(available);
        var final = new Size(double.IsInfinity(available.Width) ? panel.DesiredSize.Width : available.Width, double.IsInfinity(available.Height) ? panel.DesiredSize.Height : available.Height);
        panel.Arrange(new Rect(final));
    }

    private static List<Rect> Slots(SpacedStackPanel panel) => [.. panel.Children.Cast<FrameworkElement>().Select(LayoutInformation.GetLayoutSlot)];
}
