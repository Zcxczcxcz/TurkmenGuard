using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace TurkmenGuard.Converters;

public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public class ProtectionBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value is true ? "BrandGreenBrush" : "TextSecondaryBrush";
        return Application.Current.Resources[key] as System.Windows.Media.Brush
               ?? System.Windows.Media.Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>0–100 protection score → semantic brush (red &lt; 50, amber &lt; 80, green ≥ 80).</summary>
public class ScoreToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var score = value is int i ? i : (value is double d ? (int)d : -1);
        var key = score < 0 ? "TextMutedBrush"
            : score < 50 ? "ScoreCriticalBrush"
            : score < 80 ? "ScoreWarningBrush"
            : "ScoreGoodBrush";
        return Application.Current.Resources[key] as System.Windows.Media.Brush
               ?? System.Windows.Media.Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>True → Collapsed, False/null/empty → Visible (hide-when-enabled helper).</summary>
public class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var flag = value is bool b && b;
        return flag ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Non-empty/non-null → Visible, else Collapsed.</summary>
public class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value == null) return Visibility.Collapsed;
        if (value is string s) return string.IsNullOrWhiteSpace(s) ? Visibility.Collapsed : Visibility.Visible;
        return Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Score 0–100 → textual verdict label key suffix.</summary>
public class ScoreToVerdictConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var score = value is int i ? i : -1;
        return score < 0 ? "—"
            : score < 50 ? "AtRisk"
            : score < 80 ? "Fair"
            : "Protected";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
