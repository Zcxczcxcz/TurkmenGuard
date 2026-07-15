using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TurkmenGuard.Security;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class SettingsViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;
    public event Action? ExitRequested;

    [ObservableProperty] private ComboOption? _selectedLanguageOption;
    [ObservableProperty] private ComboOption? _selectedThemeOption;
    [ObservableProperty] private ComboOption? _selectedScheduleOption;
    [ObservableProperty] private bool _autoQuarantine;
    [ObservableProperty] private bool _autoStart;
    [ObservableProperty] private bool _selfProtection = true;
    [ObservableProperty] private bool _notificationsEnabled = true;
    [ObservableProperty] private bool _processMonitorEnabled;
    [ObservableProperty] private string _excludedExtensions = "";
    [ObservableProperty] private string _excludedFolders = "";
    [ObservableProperty] private string _monitoredFolders = "";
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _languageLabel = "";
    [ObservableProperty] private string _themeLabel = "";
    [ObservableProperty] private string _scheduleLabel = "";
    [ObservableProperty] private string _autoQuarantineLabel = "";
    [ObservableProperty] private string _autoStartLabel = "";
    [ObservableProperty] private string _selfProtectionLabel = "";
    [ObservableProperty] private string _notificationsLabel = "";
    [ObservableProperty] private string _processMonitorLabel = "";
    [ObservableProperty] private string _exclusionsLabel = "";
    [ObservableProperty] private string _extensionsLabel = "";
    [ObservableProperty] private string _foldersLabel = "";
    [ObservableProperty] private string _monitoredFoldersLabel = "";
    [ObservableProperty] private string _saveLabel = "";
    [ObservableProperty] private string _exitLabel = "";
    [ObservableProperty] private string _logsLabel = "";
    [ObservableProperty] private string _logContent = "";
    [ObservableProperty] private string _refreshLogsLabel = "";
    [ObservableProperty] private string _openLogsFolderLabel = "";
    [ObservableProperty] private bool _signatureUpdatesEnabled = true;
    [ObservableProperty] private ComboOption? _selectedUpdateScheduleOption;
    [ObservableProperty] private string _signatureEndpoint = "";
    [ObservableProperty] private bool _checkUpdatesOnStartup = true;
    [ObservableProperty] private string _signatureUpdatesLabel = "";
    [ObservableProperty] private string _signatureUpdatesEnabledLabel = "";
    [ObservableProperty] private string _updateScheduleLabel = "";
    [ObservableProperty] private string _updateEndpointLabel = "";
    [ObservableProperty] private string _checkUpdatesOnStartupLabel = "";
    [ObservableProperty] private string _updateNowLabel = "";
    [ObservableProperty] private string _signatureStatus = "";

    public List<ComboOption> LanguageOptions { get; private set; } = [];
    public List<ComboOption> UpdateScheduleOptions { get; private set; } = [];
    public List<ComboOption> ThemeOptions { get; private set; } = [];
    public List<ComboOption> ScheduleOptions { get; private set; } = [];

    public SettingsViewModel(ApplicationServices services)
    {
        _services = services;
        BuildOptions();
        LoadFromSettings();
        RefreshLabels();
        LoadLogs();
        LocalizationService.LanguageChanged += OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        var lang = SelectedLanguageOption?.Value ?? _services.Settings.Language;
        var theme = SelectedThemeOption?.Value ?? _services.Settings.Theme;
        var schedule = SelectedScheduleOption?.Value ?? _services.Settings.ScanSchedule;
        BuildOptions();
        SelectedLanguageOption = LanguageOptions.FirstOrDefault(o => o.Value == lang);
        SelectedThemeOption = ThemeOptions.FirstOrDefault(o => o.Value == theme);
        SelectedScheduleOption = ScheduleOptions.FirstOrDefault(o => o.Value == schedule);
        RefreshLabels();
        LoadLogs();
    }

    private void BuildOptions()
    {
        LanguageOptions =
        [
            new("tk", LocalizationService.Get("LangTk")),
            new("ru", LocalizationService.Get("LangRu")),
            new("en", LocalizationService.Get("LangEn"))
        ];
        ThemeOptions =
        [
            new("corporate", LocalizationService.Get("ThemeCorporate")),
            new("dark", LocalizationService.Get("ThemeDark")),
            new("light", LocalizationService.Get("ThemeLight"))
        ];
        ScheduleOptions =
        [
            new("never", LocalizationService.Get("ScheduleNever")),
            new("daily", LocalizationService.Get("ScheduleDaily")),
            new("weekly", LocalizationService.Get("ScheduleWeekly")),
            new("monthly", LocalizationService.Get("ScheduleMonthly"))
        ];
        UpdateScheduleOptions =
        [
            new("weekly", LocalizationService.Get("UpdateScheduleWeekly")),
            new("manual", LocalizationService.Get("UpdateScheduleManual"))
        ];
        OnPropertyChanged(nameof(LanguageOptions));
        OnPropertyChanged(nameof(ThemeOptions));
        OnPropertyChanged(nameof(ScheduleOptions));
        OnPropertyChanged(nameof(UpdateScheduleOptions));
    }

    private void RefreshLabels()
    {
        Title = LocalizationService.Get("NavSettings");
        LanguageLabel = LocalizationService.Get("Language");
        ThemeLabel = LocalizationService.Get("Theme");
        ScheduleLabel = LocalizationService.Get("ScanSchedule");
        AutoQuarantineLabel = LocalizationService.Get("AutoQuarantine");
        AutoStartLabel = LocalizationService.Get("AutoStart");
        SelfProtectionLabel = LocalizationService.Get("SelfProtection");
        NotificationsLabel = LocalizationService.Get("Notifications");
        ProcessMonitorLabel = LocalizationService.Get("ProcessMonitor");
        ExclusionsLabel = LocalizationService.Get("Exclusions");
        ExtensionsLabel = LocalizationService.Get("ExcludedExtensions");
        FoldersLabel = LocalizationService.Get("ExcludedFolders");
        MonitoredFoldersLabel = LocalizationService.Get("MonitoredFolders");
        SaveLabel = LocalizationService.Get("Save");
        ExitLabel = LocalizationService.Get("Exit");
        LogsLabel = LocalizationService.Get("ViewLogs");
        RefreshLogsLabel = LocalizationService.Get("RefreshLogs");
        OpenLogsFolderLabel = LocalizationService.Get("OpenLogsFolder");
        SignatureUpdatesLabel = LocalizationService.Get("SignatureUpdates");
        SignatureUpdatesEnabledLabel = LocalizationService.Get("SignatureUpdatesEnabled");
        UpdateScheduleLabel = LocalizationService.Get("UpdateSchedule");
        UpdateEndpointLabel = LocalizationService.Get("UpdateEndpoint");
        CheckUpdatesOnStartupLabel = LocalizationService.Get("CheckUpdatesOnStartup");
        UpdateNowLabel = LocalizationService.Get("UpdateNow");
    }

    public void LoadLogs()
    {
        var content = Logger.ReadRecentLogs();
        LogContent = string.IsNullOrWhiteSpace(content)
            ? LocalizationService.Get("NoLogs")
            : content;
    }

    [RelayCommand]
    private void RefreshLogs() => LoadLogs();

    [RelayCommand]
    private void OpenLogsFolder()
    {
        try
        {
            PathHelper.EnsureDirectories();
            System.Diagnostics.Process.Start("explorer.exe", $"\"{PathHelper.LogsDir}\"");
        }
        catch
        {
            StatusMessage = LocalizationService.Get("OpenLogsFailed");
        }
    }

    private void LoadFromSettings()
    {
        var s = _services.Settings;
        SelectedLanguageOption = LanguageOptions.FirstOrDefault(o => o.Value == s.Language);
        SelectedThemeOption = ThemeOptions.FirstOrDefault(o => o.Value == s.Theme);
        SelectedScheduleOption = ScheduleOptions.FirstOrDefault(o => o.Value == s.ScanSchedule);
        AutoQuarantine = s.AutoQuarantine;
        AutoStart = s.AutoStart;
        SelfProtection = s.SelfProtectionEnabled;
        NotificationsEnabled = s.NotificationsEnabled;
        ProcessMonitorEnabled = s.ProcessMonitorEnabled;
        ExcludedExtensions = string.Join(", ", s.Exclusions.Extensions);
        ExcludedFolders = string.Join(Environment.NewLine, s.Exclusions.Folders);
        MonitoredFolders = string.Join(Environment.NewLine, s.MonitoredFolders);
        SignatureUpdatesEnabled = s.SignatureUpdatesEnabled;
        SelectedUpdateScheduleOption = UpdateScheduleOptions.FirstOrDefault(o => o.Value == s.SignatureUpdateSchedule);
        SignatureEndpoint = s.SignatureUpdateEndpoint;
        CheckUpdatesOnStartup = s.CheckUpdatesOnStartup;
        SignatureStatus = FormatSignatureStatus();
    }

    private string FormatSignatureStatus()
    {
        var count = _services.Scanner.HashSignatureCount;
        var version = _services.Scanner.HashDatabaseVersion;
        var last = _services.Settings.LastSignatureUpdate?.ToLocalTime().ToString("g") ?? "—";
        return LocalizationService.Format("SignatureStatus", count, version, last);
    }

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        SignatureStatus = LocalizationService.Get("UpdateChecking");
        var (ok, msg) = await _services.SignatureUpdates.UpdateNowAsync();
        SignatureStatus = msg;
        if (ok)
            _services.RequestDashboardRefresh();
    }

    [RelayCommand]
    private void Save()
    {
        var s = _services.Settings;
        var prevSchedule = s.ScanSchedule;

        s.Language = SelectedLanguageOption?.Value ?? "tk";
        s.Theme = SelectedThemeOption?.Value ?? "corporate";
        s.ScanSchedule = SelectedScheduleOption?.Value ?? "never";
        s.AutoQuarantine = AutoQuarantine;
        s.AutoStart = AutoStart;
        s.SelfProtectionEnabled = SelfProtection;
        s.NotificationsEnabled = NotificationsEnabled;
        s.ProcessMonitorEnabled = ProcessMonitorEnabled;
        s.SignatureUpdatesEnabled = SignatureUpdatesEnabled;
        s.SignatureUpdateSchedule = SelectedUpdateScheduleOption?.Value ?? "weekly";
        s.SignatureUpdateEndpoint = string.IsNullOrWhiteSpace(SignatureEndpoint)
            ? SignatureUpdateService.DefaultEndpoint
            : SignatureEndpoint.Trim();
        s.CheckUpdatesOnStartup = CheckUpdatesOnStartup;

        if (prevSchedule == "never" && s.ScanSchedule != "never")
            s.LastScheduledScan = DateTime.Now;

        s.Exclusions.Extensions = ExcludedExtensions
            .Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries)
            .Select(e => e.Trim().StartsWith(".") ? e.Trim() : "." + e.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        s.Exclusions.Folders = ExcludedFolders
            .Split([Environment.NewLine, "\n"], StringSplitOptions.RemoveEmptyEntries)
            .Select(f => f.Trim())
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .ToList();

        s.MonitoredFolders = MonitoredFolders
            .Split([Environment.NewLine, "\n"], StringSplitOptions.RemoveEmptyEntries)
            .Select(f => f.Trim())
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .ToList();

        SettingsService.Save(s);
        LocalizationService.CurrentLanguage = s.Language;
        AutoStartService.SetEnabled(s.AutoStart);
        AutoStartService.SyncEnabled(s.AutoStart);

        if (s.SelfProtectionEnabled)
        {
            _services.SelfProtection.SetNotifier(_services.Notifications);
            _services.SelfProtection.Activate();
        }
        else
            _services.SelfProtection.Deactivate();

        _services.ApplySettingsChanges();
        SignatureStatus = FormatSignatureStatus();
        StatusMessage = LocalizationService.Get("SettingsSaved");
    }

    [RelayCommand]
    private void Exit()
    {
        if (System.Windows.MessageBox.Show(
                LocalizationService.Get("ExitConfirm"),
                LocalizationService.AppTitle,
                System.Windows.MessageBoxButton.YesNo) == System.Windows.MessageBoxResult.Yes)
            ExitRequested?.Invoke();
    }
}
