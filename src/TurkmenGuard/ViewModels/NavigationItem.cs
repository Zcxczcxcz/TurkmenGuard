using MaterialDesignThemes.Wpf;

namespace TurkmenGuard.ViewModels;

public class NavigationItem
{
    public string Key { get; init; } = "";
    public PackIconKind IconKind { get; init; } = PackIconKind.Shield;
    public string Title { get; init; } = "";
}
