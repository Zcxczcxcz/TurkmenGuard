using System.Windows;
using MaterialDesignThemes.Wpf;

namespace TurkmenGuard.Controls;

public partial class StatCard
{
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(nameof(Label), typeof(string), typeof(StatCard));

    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(nameof(Value), typeof(string), typeof(StatCard));

    public static readonly DependencyProperty SubtitleProperty =
        DependencyProperty.Register(nameof(Subtitle), typeof(string), typeof(StatCard));

    public static readonly DependencyProperty IconKindProperty =
        DependencyProperty.Register(nameof(IconKind), typeof(PackIconKind), typeof(StatCard),
            new PropertyMetadata(PackIconKind.Shield));

    public static readonly DependencyProperty ValueBrushProperty =
        DependencyProperty.Register(nameof(ValueBrush), typeof(System.Windows.Media.Brush), typeof(StatCard));

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public string Value
    {
        get => (string)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    public string Subtitle
    {
        get => (string)GetValue(SubtitleProperty);
        set => SetValue(SubtitleProperty, value);
    }

    public PackIconKind IconKind
    {
        get => (PackIconKind)GetValue(IconKindProperty);
        set => SetValue(IconKindProperty, value);
    }

    public System.Windows.Media.Brush ValueBrush
    {
        get => (System.Windows.Media.Brush)GetValue(ValueBrushProperty);
        set => SetValue(ValueBrushProperty, value);
    }

    public StatCard() => InitializeComponent();
}
