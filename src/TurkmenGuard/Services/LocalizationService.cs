using System.Globalization;
using System.Resources;

namespace TurkmenGuard.Services;

public static class LocalizationService
{
    private const string ResourceBase = "TurkmenGuard.Localization.Strings";
    private static readonly ResourceManager Manager = new(ResourceBase, typeof(LocalizationService).Assembly);
    private static string _currentLanguage = "tk";

    public static event Action? LanguageChanged;

    public static string CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            if (_currentLanguage == value) return;
            _currentLanguage = value;
            Thread.CurrentThread.CurrentUICulture = ToCulture(value);
            LanguageChanged?.Invoke();
        }
    }

    private static CultureInfo ToCulture(string lang) => lang switch
    {
        "ru" => new CultureInfo("ru-RU"),
        "en" => new CultureInfo("en-US"),
        _ => new CultureInfo("tk-TM")
    };

    public static string Get(string key)
    {
        try
        {
            var culture = ToCulture(_currentLanguage);
            var value = Manager.GetString(key, culture);
            if (!string.IsNullOrEmpty(value))
                return value;

            value = Manager.GetString(key, CultureInfo.InvariantCulture)
                ?? Manager.GetString(key, new CultureInfo("en-US"));
            return value ?? key;
        }
        catch
        {
            return key;
        }
    }

    public static string Format(string key, params object[] args)
    {
        var template = Get(key);
        try { return string.Format(template, args); }
        catch { return template; }
    }

    public static string AppTitle => Get("AppTitle");
    public static string BrandSubtitle => Get("BrandSubtitle");
    public static string Dashboard => Get("Dashboard");
    public static string FilesScanned => Get("FilesScanned");
    public static string ThreatsFound => Get("ThreatsFound");
    public static string RealTime => Get("RealTime");
    public static string YaraStatus => Get("YaraStatus");
}
