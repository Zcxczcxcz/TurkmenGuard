using System.Windows;
using TurkmenGuard.Services;

namespace TurkmenGuard.Views;

public partial class FirstRunLanguageWindow : Window
{
    private readonly AppSettings _settings;

    public FirstRunLanguageWindow(AppSettings settings)
    {
        _settings = settings;
        InitializeComponent();
        LoadTexts();
        Closing += OnClosing;
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_settings.FirstRun)
        {
            _settings.FirstRun = false;
            SettingsService.Save(_settings);
        }
    }

    private void LoadTexts()
    {
        Title = LocalizationService.AppTitle;
        TitleBlock.Text = LocalizationService.AppTitle;
        SubtitleBlock.Text = LocalizationService.Get("SelectLanguageSubtitle");
        LblTk.Text = LocalizationService.Get("LangTk");
        LblRu.Text = LocalizationService.Get("LangRu");
        LblEn.Text = LocalizationService.Get("LangEn");
        HintBlock.Text = LocalizationService.Get("SelectLanguage");
    }

    private void OnLanguageClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string lang })
            return;

        _settings.Language = lang;
        _settings.FirstRun = false;
        LocalizationService.CurrentLanguage = lang;
        SettingsService.Save(_settings);
        DialogResult = true;
        Close();
    }
}
