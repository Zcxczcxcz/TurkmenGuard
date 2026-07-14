using CommunityToolkit.Mvvm.ComponentModel;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;

    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private int _quarantineCount;
    [ObservableProperty] private string _protectionStatus = "";
    [ObservableProperty] private string _yaraStatus = "";
    [ObservableProperty] private string _welcomeText = "";
    [ObservableProperty] private string _dashboardTitle = "";
    [ObservableProperty] private string _filesScannedLabel = "";
    [ObservableProperty] private string _threatsFoundLabel = "";
    [ObservableProperty] private string _quarantineLabel = "";
    [ObservableProperty] private string _realTimeLabel = "";
    [ObservableProperty] private string _yaraStatusLabel = "";

    public DashboardViewModel(ApplicationServices services)
    {
        _services = services;
        Refresh();
        LocalizationService.LanguageChanged += Refresh;
        _services.DashboardRefreshRequested += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(Refresh));
    }

    public void Refresh()
    {
        FilesScanned = _services.Settings.TotalFilesScanned;
        ThreatsFound = _services.Settings.TotalThreatsFound;
        QuarantineCount = _services.Quarantine.Entries.Count;
        WelcomeText = LocalizationService.Get("Welcome");
        DashboardTitle = LocalizationService.Dashboard;
        FilesScannedLabel = LocalizationService.FilesScanned;
        ThreatsFoundLabel = LocalizationService.ThreatsFound;
        QuarantineLabel = LocalizationService.Get("InQuarantine");
        RealTimeLabel = LocalizationService.RealTime;
        YaraStatusLabel = LocalizationService.YaraStatus;
        ProtectionStatus = _services.RealTimeGuard.IsEnabled
            ? LocalizationService.Get("ProtectionEnabled")
            : LocalizationService.Get("ProtectionDisabled");

        if (_services.Scanner.ClamAvAvailable)
        {
            var daemon = _services.Scanner.ClamAvDaemonReady
                ? LocalizationService.Get("DaemonOn")
                : LocalizationService.Get("DaemonOff");
            YaraStatus = LocalizationService.Format("ClamAvActiveDetail",
                _services.Scanner.ClamAvVersion,
                _services.Scanner.ClamAvDatabaseCount,
                daemon,
                _services.Scanner.YaraCompiledRules);
        }
        else
        {
            YaraStatus = _services.Scanner.YaraAvailable
                ? LocalizationService.Format("YaraActiveDetail",
                    _services.Scanner.YaraRulesLoaded,
                    _services.Scanner.YaraCompiledRules,
                    _services.Scanner.HashSignatureCount)
                : LocalizationService.Format("ClamAvFallbackDetail",
                    _services.Scanner.HashSignatureCount,
                    _services.Scanner.YaraCompiledRules);
        }
    }
}
