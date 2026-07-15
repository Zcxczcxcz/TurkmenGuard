using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;

    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private int _quarantineCount;
    [ObservableProperty] private int _protectionScore;
    [ObservableProperty] private string _protectionStatus = "";
    [ObservableProperty] private string _yaraStatus = "";
    [ObservableProperty] private string _welcomeText = "";
    [ObservableProperty] private string _dashboardTitle = "";
    [ObservableProperty] private string _filesScannedLabel = "";
    [ObservableProperty] private string _threatsFoundLabel = "";
    [ObservableProperty] private string _quarantineLabel = "";
    [ObservableProperty] private string _realTimeLabel = "";
    [ObservableProperty] private string _yaraStatusLabel = "";
    [ObservableProperty] private string _lastScanLabel = "";
    [ObservableProperty] private string _signatureAgeLabel = "";
    [ObservableProperty] private string _clamAvEngineLabel = "";
    [ObservableProperty] private string _yaraEngineLabel = "";
    [ObservableProperty] private string _hashEngineLabel = "";
    [ObservableProperty] private string _systemHealthLabel = "";
    [ObservableProperty] private string _quickActionsLabel = "";
    [ObservableProperty] private string _enginesLabel = "";
    [ObservableProperty] private bool _isProtectionOn;
    [ObservableProperty] private bool _isScanRunning;
    [ObservableProperty] private string _quickScanBtnLabel = "";
    [ObservableProperty] private string _fullScanBtnLabel = "";
    [ObservableProperty] private string _updateBtnLabel = "";

    public event Action<string>? NavigateRequested;

    public DashboardViewModel(ApplicationServices services)
    {
        _services = services;
        Refresh();
        LocalizationService.LanguageChanged += Refresh;
        _services.DashboardRefreshRequested += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(Refresh));
        _services.Scanner.OnProgress += p => IsScanRunning = p.IsRunning;
    }

    public void Refresh()
    {
        FilesScanned = _services.Settings.TotalFilesScanned;
        ThreatsFound = _services.Settings.TotalThreatsFound;
        QuarantineCount = _services.Quarantine.Entries.Count;
        IsProtectionOn = _services.RealTimeGuard.IsEnabled;
        IsScanRunning = _services.Scanner.IsScanning;

        WelcomeText = LocalizationService.Get("Welcome");
        DashboardTitle = LocalizationService.Dashboard;
        FilesScannedLabel = LocalizationService.FilesScanned;
        ThreatsFoundLabel = LocalizationService.ThreatsFound;
        QuarantineLabel = LocalizationService.Get("InQuarantine");
        RealTimeLabel = LocalizationService.RealTime;
        YaraStatusLabel = LocalizationService.YaraStatus;
        QuickActionsLabel = LocalizationService.Get("QuickActions");
        EnginesLabel = LocalizationService.Get("EngineStatus");
        SystemHealthLabel = LocalizationService.Get("SystemHealth");
        QuickScanBtnLabel = LocalizationService.QuickScan;
        FullScanBtnLabel = LocalizationService.FullScan;
        UpdateBtnLabel = LocalizationService.Get("UpdateSignatures");

        ProtectionStatus = IsProtectionOn
            ? LocalizationService.Get("ProtectionEnabled")
            : LocalizationService.Get("ProtectionDisabled");

        ProtectionScore = ComputeProtectionScore();

        LastScanLabel = _services.Settings.LastManualScan.HasValue
            ? LocalizationService.Format("LastScanAt",
                _services.Settings.LastManualScan.Value.ToString("g"))
            : LocalizationService.Get("LastScanNever");

        SignatureAgeLabel = _services.Settings.LastSignatureUpdate.HasValue
            ? LocalizationService.Format("SignatureAge",
                (DateTime.UtcNow - _services.Settings.LastSignatureUpdate.Value).Days)
            : LocalizationService.Get("SignatureAgeUnknown");

        ClamAvEngineLabel = _services.Scanner.ClamAvAvailable
            ? LocalizationService.Format("ClamAvEngineLine",
                _services.Scanner.ClamAvVersion,
                _services.Scanner.ClamAvDatabaseCount,
                _services.Scanner.ClamAvDaemonReady
                    ? LocalizationService.Get("DaemonOn")
                    : LocalizationService.Get("DaemonOff"))
            : LocalizationService.Get("ClamAvUnavailable");

        YaraEngineLabel = _services.Scanner.YaraAvailable
            ? LocalizationService.Format("YaraEngineLine",
                _services.Scanner.YaraRulesLoaded,
                _services.Scanner.YaraCompiledRules)
            : LocalizationService.Get("YaraUnavailable");

        HashEngineLabel = LocalizationService.Format("HashEngineLine",
            _services.Scanner.HashSignatureCount);

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

    private int ComputeProtectionScore()
    {
        var score = 0;
        if (IsProtectionOn) score += 35;
        if (_services.Scanner.ClamAvDaemonReady) score += 25;
        else if (_services.Scanner.ClamAvAvailable) score += 10;
        if (_services.Scanner.YaraAvailable) score += 20;
        if (_services.Scanner.HashSignatureCount > 100_000) score += 10;
        if (_services.Settings.LastManualScan.HasValue &&
            DateTime.Now - _services.Settings.LastManualScan.Value < TimeSpan.FromDays(7))
            score += 10;
        return Math.Min(100, score);
    }

    [RelayCommand]
    private void ToggleProtection() =>
        _services.SetRealTimeProtection(!IsProtectionOn);

    [RelayCommand]
    private void OpenScan() => NavigateRequested?.Invoke("scan");

    [RelayCommand]
    private async Task QuickScanAsync()
    {
        NavigateRequested?.Invoke("scan");
        if (_services.Scanner.IsScanning) return;
        await _services.Scanner.RunScanAsync(ScanMode.Quick);
        Refresh();
    }

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        var (ok, _) = await _services.SignatureUpdates.UpdateNowAsync();
        if (ok) Refresh();
    }
}
