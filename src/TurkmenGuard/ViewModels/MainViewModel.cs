using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MaterialDesignThemes.Wpf;
using TurkmenGuard.Services;
using TurkmenGuard.Views;

namespace TurkmenGuard.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;
    private string _currentNavKey = "dashboard";

    private readonly DashboardViewModel _dashboardVm;
    private readonly ScanViewModel _scanVm;
    private readonly RealTimeViewModel _realTimeVm;
    private readonly QuarantineViewModel _quarantineVm;
    private readonly SettingsViewModel _settingsVm;

    private readonly DashboardView _dashboardView;
    private readonly ScanView _scanView;
    private readonly RealTimeView _realTimeView;
    private readonly QuarantineView _quarantineView;
    private readonly SettingsView _settingsView;

    [ObservableProperty] private UserControl? _currentView;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _versionText = "";
    [ObservableProperty] private NavigationItem? _selectedNav;
    [ObservableProperty] private bool _isProtectionEnabled;

    public List<NavigationItem> NavItems { get; } = [];
    public event Action? ExitRequested;

    public MainViewModel(ApplicationServices services)
    {
        _services = services;

        _dashboardVm = new DashboardViewModel(services);
        _scanVm = new ScanViewModel(services);
        _realTimeVm = new RealTimeViewModel(services);
        _quarantineVm = new QuarantineViewModel(services);
        _settingsVm = new SettingsViewModel(services);

        _dashboardView = new DashboardView(_dashboardVm);
        _dashboardVm.NavigateRequested += NavigateTo;
        _scanView = new ScanView(_scanVm);
        _realTimeView = new RealTimeView(_realTimeVm);
        _quarantineView = new QuarantineView(_quarantineVm);
        _settingsView = new SettingsView(_settingsVm);

        _settingsVm.ExitRequested += OnExitRequested;

        IsProtectionEnabled = _services.RealTimeGuard.IsEnabled;
        _services.RealTimeGuard.ProtectionStateChanged += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                IsProtectionEnabled = _services.RealTimeGuard.IsEnabled));

        BuildNavigation();
        RefreshTexts();
        NavigateTo("dashboard");
        LocalizationService.LanguageChanged += RefreshTexts;
    }

    private void BuildNavigation()
    {
        NavItems.Clear();
        NavItems.AddRange([
            new() { Key = "dashboard", IconKind = PackIconKind.ViewDashboard, Title = LocalizationService.Get("NavDashboard") },
            new() { Key = "scan", IconKind = PackIconKind.Radar, Title = LocalizationService.Get("NavScan") },
            new() { Key = "realtime", IconKind = PackIconKind.ShieldCheck, Title = LocalizationService.Get("NavRealTime") },
            new() { Key = "quarantine", IconKind = PackIconKind.ArchiveLock, Title = LocalizationService.Get("NavQuarantine") },
            new() { Key = "settings", IconKind = PackIconKind.Cog, Title = LocalizationService.Get("NavSettings") },
        ]);
    }

    public void RefreshTexts()
    {
        var key = SelectedNav?.Key ?? _currentNavKey;
        BuildNavigation();
        SelectedNav = NavItems.FirstOrDefault(n => n.Key == key) ?? NavItems.FirstOrDefault();
        StatusText = _services.Scanner.YaraAvailable
            ? LocalizationService.Format("YaraActiveRules", _services.Scanner.YaraRulesLoaded)
            : LocalizationService.Get("YaraFallback");
        VersionText = $"{LocalizationService.Get("Version")} {PathHelper.GetVersion()}";
        OnPropertyChanged(nameof(NavItems));
    }

    [RelayCommand]
    private void Navigate(NavigationItem? item)
    {
        if (item == null) return;
        SelectedNav = item;
        NavigateTo(item.Key);
    }

    private void NavigateTo(string key)
    {
        _currentNavKey = key;
        CurrentView = key switch
        {
            "dashboard" => _dashboardView,
            "scan" => _scanView,
            "realtime" => _realTimeView,
            "quarantine" => _quarantineView,
            "settings" => _settingsView,
            _ => _dashboardView
        };

        if (key == "dashboard")
            _dashboardVm.Refresh();
        else if (key == "settings")
            _settingsVm.LoadLogs();
    }

    private void OnExitRequested() => ExitRequested?.Invoke();
}
