using System.Windows;
using System.Windows.Controls;

namespace OpWarden.SessionAgent;

// The layout elements that position the components. Every gap between two components is a
// layout's, so no component carries a margin, and no layout has a look of its own. The gaps
// are tokens in Themes/Components.xaml, each named for the relationship it spaces.

/// <summary>
/// Stacks its children in one direction with the same gap between each neighbouring pair.
/// A collapsed child takes no gap. One child may fill the space the others leave, as a
/// toolbar's summary text does.
/// </summary>
/// <remarks>
/// WPF's panels have no gap of their own; StackPanel would need a margin on every child.
/// </remarks>
public sealed class SpacedStackPanel : Panel
{
    public static readonly DependencyProperty OrientationProperty =
        DependencyProperty.Register(nameof(Orientation), typeof(Orientation), typeof(SpacedStackPanel), new FrameworkPropertyMetadata(Orientation.Vertical, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty SpacingProperty =
        DependencyProperty.Register(nameof(Spacing), typeof(double), typeof(SpacedStackPanel), new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty FillProperty =
        DependencyProperty.RegisterAttached("Fill", typeof(bool), typeof(SpacedStackPanel), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsParentMeasure));

    public Orientation Orientation
    {
        get => (Orientation)GetValue(OrientationProperty);
        set => SetValue(OrientationProperty, value);
    }

    /// <summary>
    /// The gap between neighbouring children, in DIPs.
    /// </summary>
    public double Spacing
    {
        get => (double)GetValue(SpacingProperty);
        set => SetValue(SpacingProperty, value);
    }

    public static bool GetFill(UIElement element) => (bool)element.GetValue(FillProperty);

    /// <summary>
    /// Makes <paramref name="element"/> take the space its siblings leave. The first visible
    /// child that asks gets it.
    /// </summary>
    public static void SetFill(UIElement element, bool value) => element.SetValue(FillProperty, value);

    protected override Size MeasureOverride(Size availableSize)
    {
        var (shown, fill) = Shown();
        var gaps = Spacing * Math.Max(0, shown.Count - 1);
        double along = 0, across = 0;
        foreach (var child in shown.Where(c => c != fill))
        {
            child.Measure(Horizontal ? new Size(double.PositiveInfinity, availableSize.Height) : new Size(availableSize.Width, double.PositiveInfinity));
            along += Along(child.DesiredSize);
            across = Math.Max(across, Across(child.DesiredSize));
        }

        if (fill is not null)
        {
            var left = Math.Max(0, Along(availableSize) - along - gaps);
            fill.Measure(Horizontal ? new Size(left, availableSize.Height) : new Size(availableSize.Width, left));
            along += Along(fill.DesiredSize);
            across = Math.Max(across, Across(fill.DesiredSize));
        }

        return Horizontal ? new Size(along + gaps, across) : new Size(across, along + gaps);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var (shown, fill) = Shown();
        var gaps = Spacing * Math.Max(0, shown.Count - 1);
        var fillLength = Math.Max(0, Along(finalSize) - gaps - shown.Where(c => c != fill).Sum(c => Along(c.DesiredSize)));
        var position = 0.0;
        foreach (var child in shown)
        {
            var length = child == fill ? fillLength : Along(child.DesiredSize);
            child.Arrange(Horizontal ? new Rect(position, 0, length, finalSize.Height) : new Rect(0, position, finalSize.Width, length));
            position += length + Spacing;
        }

        return finalSize;
    }

    private bool Horizontal => Orientation == Orientation.Horizontal;

    private double Along(Size size) => Horizontal ? size.Width : size.Height;

    private double Across(Size size) => Horizontal ? size.Height : size.Width;

    private (List<UIElement> Shown, UIElement? Fill) Shown()
    {
        var shown = InternalChildren.Cast<UIElement>().Where(c => c.Visibility != Visibility.Collapsed).ToList();
        return (shown, shown.FirstOrDefault(GetFill));
    }
}
