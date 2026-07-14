using System.Windows;
using System.Windows.Media;
using MaterialDesignThemes.Wpf;

namespace TurkmenGuard.Services;

/// <summary>
/// Applies corporate / dark / light visual themes at runtime.
/// </summary>
public static class ThemeManager
{
    public static readonly string[] Themes = ["corporate", "dark", "light"];

    public static event Action? ThemeChanged;

    public static void Apply(string theme)
    {
        var helper = new PaletteHelper();
        var materialTheme = helper.GetTheme();
        materialTheme.SetBaseTheme(theme == "light" ? BaseTheme.Light : BaseTheme.Dark);
        helper.SetTheme(materialTheme);
        ApplyBrandColors(theme);
        ThemeChanged?.Invoke();
    }

    private static void ApplyBrandColors(string theme)
    {
        switch (theme)
        {
            case "light":
                SetBrandColor("BrandDarkBlueColor", 0xF0, 0xF4, 0xF8);
                SetBrandColor("CardBackgroundColor", 0xFF, 0xFF, 0xFF);
                SetBrandColor("CardHoverBackgroundColor", 0xF5, 0xF7, 0xFA);
                SetBrandColor("SidebarBackgroundColor", 0xE8, 0xED, 0xF5);
                SetBrandColor("TextPrimaryColor", 0x1A, 0x28, 0x40);
                SetBrandColor("TextSecondaryColor", 0x5A, 0x6A, 0x80);
                SetBrandColor("BorderColor", 0xC8, 0xD4, 0xE0);
                break;
            case "dark":
                SetBrandColor("BrandDarkBlueColor", 0x12, 0x12, 0x12);
                SetBrandColor("CardBackgroundColor", 0x1E, 0x1E, 0x1E);
                SetBrandColor("CardHoverBackgroundColor", 0x28, 0x28, 0x28);
                SetBrandColor("SidebarBackgroundColor", 0x18, 0x18, 0x18);
                SetBrandColor("TextPrimaryColor", 0xE8, 0xEC, 0xF2);
                SetBrandColor("TextSecondaryColor", 0x8A, 0x9A, 0xB0);
                SetBrandColor("BorderColor", 0x33, 0x33, 0x33);
                break;
            default:
                SetBrandColor("BrandDarkBlueColor", 0x0A, 0x14, 0x28);
                SetBrandColor("CardBackgroundColor", 0x12, 0x20, 0x38);
                SetBrandColor("CardHoverBackgroundColor", 0x16, 0x28, 0x44);
                SetBrandColor("SidebarBackgroundColor", 0x0C, 0x18, 0x30);
                SetBrandColor("TextPrimaryColor", 0xE8, 0xEC, 0xF2);
                SetBrandColor("TextSecondaryColor", 0x8A, 0x9A, 0xB0);
                SetBrandColor("BorderColor", 0x1E, 0x34, 0x54);
                break;
        }
    }

    private static void SetBrandColor(string colorKey, byte r, byte g, byte b)
    {
        var color = System.Windows.Media.Color.FromRgb(r, g, b);
        var brushKey = colorKey.Replace("Color", "Brush");
        Application.Current.Resources[colorKey] = color;
        Application.Current.Resources[brushKey] = new SolidColorBrush(color);
    }
}
