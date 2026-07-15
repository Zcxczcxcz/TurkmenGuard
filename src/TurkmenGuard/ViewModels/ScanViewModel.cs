using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public class ScanThreatDisplay
{
    public string FilePath { get; init; } = "";
    public string ThreatName { get; init; } = "";
    public string Method { get; init; } = "";
    public string RiskLabel { get; init; } = "";
    public ThreatRiskTier RiskTier { get; init; }
    public ThreatInfo Threat { get; init; } = new();
}

public class ThreatRiskGroup
{
    public ThreatRiskTier Tier { get; init; }
    public string Title { get; init; } = "";
    public string Hint { get; init; } = "";
    public int Count { get; init; }
    public System.Windows.Media.Brush AccentBrush { get; init; } = System.Windows.Media.Brushes.Gray;
    public bool IsExpanded { get; set; }
    public ObservableCollection<ScanThreatDisplay> Items { get; init; } = [];
}

public partial class ScanViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;
    private CancellationTokenSource? _cts;

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private bool _isIndeterminate;
    [ObservableProperty] private string _progressText = "";
    [ObservableProperty] private double _progressValue;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private string _customPath = "";
    [ObservableProperty] private string _filePath = "";
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _quickScanLabel = "";
    [ObservableProperty] private string _fullScanLabel = "";
    [ObservableProperty] private string _customScanLabel = "";
    [ObservableProperty] private string _fileScanLabel = "";
    [ObservableProperty] private string _startLabel = "";
    [ObservableProperty] private string _cancelLabel = "";
    [ObservableProperty] private string _threatsLabel = "";
    [ObservableProperty] private string _resultsLabel = "";
    [ObservableProperty] private string _quarantineLabel = "";
    [ObservableProperty] private string _colFile = "";
    [ObservableProperty] private string _colThreat = "";
    [ObservableProperty] private string _colMethod = "";
    [ObservableProperty] private string _colRisk = "";
    [ObservableProperty] private string _summaryLabel = "";
    [ObservableProperty] private bool _hasResults;

    public ObservableCollection<ScanThreatDisplay> ThreatResults { get; } = [];
    public ObservableCollection<ThreatRiskGroup> ThreatGroups { get; } = [];

    public ScanViewModel(ApplicationServices services)
    {
        _services = services;
        _services.Scanner.OnProgress += OnProgress;
        RefreshLabels();
        LocalizationService.LanguageChanged += OnLanguageChanged;
    }

    private void OnLanguageChanged()
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
            RefreshLabels();
        else
            dispatcher.BeginInvoke(new Action(RefreshLabels));
    }

    private void RefreshLabels()
    {
        Title = LocalizationService.Get("NavScan");
        QuickScanLabel = LocalizationService.Get("QuickScan");
        FullScanLabel = LocalizationService.Get("FullScan");
        CustomScanLabel = LocalizationService.Get("CustomScan");
        FileScanLabel = LocalizationService.Get("FileScan");
        StartLabel = LocalizationService.Get("Start");
        CancelLabel = LocalizationService.Get("Cancel");
        ResultsLabel = LocalizationService.Get("ScanResults");
        QuarantineLabel = LocalizationService.Get("QuarantineAction");
        ColFile = LocalizationService.Get("ColFile");
        ColThreat = LocalizationService.Get("ColThreat");
        ColMethod = LocalizationService.Get("ColMethod");
        ColRisk = LocalizationService.Get("ColRisk");
        UpdateThreatsLabel();
    }

    private void UpdateThreatsLabel()
    {
        if (ThreatResults.Count == 0)
        {
            ThreatsLabel = $"{LocalizationService.Get("ThreatsFound")}: 0";
            SummaryLabel = "";
            return;
        }

        var m = ThreatResults.Count(t => t.RiskTier == ThreatRiskTier.Malware);
        var d = ThreatResults.Count(t => t.RiskTier == ThreatRiskTier.Dangerous);
        var s = ThreatResults.Count(t => t.RiskTier == ThreatRiskTier.Suspicious);
        var l = ThreatResults.Count(t => t.RiskTier == ThreatRiskTier.Low);

        ThreatsLabel = LocalizationService.Format("ThreatsFoundTotal", ThreatResults.Count);
        SummaryLabel = LocalizationService.Format("ThreatRiskSummary", m, d, s, l);
    }

    private DateTime _lastProgressUi = DateTime.MinValue;
    private int _lastClamIncomplete;

    private void OnProgress(ScanProgress p)
    {
        var now = DateTime.UtcNow;
        // Keep UI responsive but avoid flooding the dispatcher during fast scans
        if (p.IsRunning && p.FilesScanned > 0 &&
            (now - _lastProgressUi).TotalMilliseconds < 120 && p.FilesScanned % 5 != 0)
            return;

        _lastProgressUi = now;
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
        {
            ApplyProgress(p);
            return;
        }

        dispatcher.BeginInvoke(new Action(() => ApplyProgress(p)),
            System.Windows.Threading.DispatcherPriority.Background);
    }

    private void ApplyProgress(ScanProgress p)
    {
        IsScanning = p.IsRunning;
        var collecting = p.IsRunning && p.TotalFiles > 0 && p.FilesScanned == 0;
        IsIndeterminate = p.IsRunning && (p.TotalFiles <= 0 || collecting);

        if (collecting)
        {
            ProgressValue = 0;
            ProgressText = LocalizationService.Format("ScanCollecting", p.TotalFiles, Path.GetFileName(p.CurrentFile));
        }
        else if (p.Phase == "retry")
        {
            ProgressText = LocalizationService.Format("ScanRetryPhase", p.FilesScanned);
        }
        else if (p.TotalFiles > 0)
        {
            ProgressValue = Math.Min(100, (double)p.FilesScanned / p.TotalFiles * 100);
            if (p.ElapsedSeconds > 0 && p.IsRunning)
            {
                var elapsedStr = FullScanTimer.FormatDuration(p.ElapsedSeconds);
                if (p.EstimatedRemainingSeconds > 0)
                {
                    var etaStr = FormatEtaRemaining(p.EstimatedRemainingSeconds);
                    ProgressText = LocalizationService.Format("ScanProgressTimer",
                        p.FilesScanned, p.TotalFiles, Path.GetFileName(p.CurrentFile),
                        elapsedStr, etaStr);
                }
                else
                    ProgressText = LocalizationService.Format("ScanProgressElapsed",
                        p.FilesScanned, p.TotalFiles, Path.GetFileName(p.CurrentFile), elapsedStr);
            }
            else
                ProgressText = LocalizationService.Format("ScanProgress", p.FilesScanned, p.TotalFiles, Path.GetFileName(p.CurrentFile));
        }
        else if (p.IsRunning)
        {
            ProgressText = LocalizationService.Format("ScanProgressIndeterminate", p.FilesScanned, Path.GetFileName(p.CurrentFile));
        }

        if (!p.IsRunning)
            _lastClamIncomplete = p.ClamAvIncompleteCount;

        ThreatsFound = p.ThreatsFound;
        UpdateThreatsLabel();
    }

    private static string FormatEtaRemaining(int totalSeconds)
    {
        if (totalSeconds >= 3600)
        {
            var hours = totalSeconds / 3600;
            var minutes = (totalSeconds % 3600 + 59) / 60;
            if (minutes == 0)
                return LocalizationService.Format("ScanEtaHoursOnly", hours);
            return LocalizationService.Format("ScanEtaHoursMinutes", hours, minutes);
        }

        if (totalSeconds >= 60)
            return LocalizationService.Format("ScanEtaMinutes", (totalSeconds + 59) / 60);

        return LocalizationService.Format("ScanEtaSeconds", totalSeconds);
    }

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task QuickScanAsync() => await RunScanAsync(ScanMode.Quick);

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task FullScanAsync() => await RunScanAsync(ScanMode.Full);

    [RelayCommand(CanExecute = nameof(CanCustomScan))]
    private async Task CustomScanAsync()
    {
        if (string.IsNullOrWhiteSpace(CustomPath) || !Directory.Exists(CustomPath))
        {
            ProgressText = LocalizationService.Get("InvalidFolder");
            return;
        }

        await RunCustomScanAsync(async token =>
        {
            var progress = new ScanProgress { IsRunning = true };
            var results = await _services.Scanner.ScanDirectoryAsync(CustomPath, ScanMode.SingleFile, progress, token)
                .ConfigureAwait(false);
            return (results, progress.FilesScanned);
        });
    }

    [RelayCommand(CanExecute = nameof(CanFileScan))]
    private async Task FileScanAsync()
    {
        if (string.IsNullOrWhiteSpace(FilePath) || !File.Exists(FilePath))
        {
            ProgressText = LocalizationService.Get("InvalidFile");
            return;
        }

        await RunCustomScanAsync(async token =>
        {
            var progress = new ScanProgress
            {
                IsRunning = true,
                TotalFiles = 1,
                CurrentFile = FilePath
            };
            OnProgress(progress);

            var result = await _services.Scanner.ScanFileAsync(FilePath, ScanMode.SingleFile, token)
                .ConfigureAwait(false);
            progress.FilesScanned = 1;
            progress.IsRunning = false;
            OnProgress(progress);

            return (result.IsThreat ? new List<ScanResult> { result } : [], 1);
        });
    }

    private async Task RunCustomScanAsync(Func<CancellationToken, Task<(List<ScanResult> Results, int FilesScanned)>> scanFunc)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        IsScanning = true;
        IsIndeterminate = true;
        ThreatsFound = 0;
        ThreatResults.Clear();
        ThreatGroups.Clear();
        HasResults = false;
        SummaryLabel = "";
        ProgressValue = 0;
        ProgressText = LocalizationService.Get("ScanStarting");

        try
        {
            var results = await _services.Scanner.ExecuteLockedScanAsync(scanFunc, _cts.Token)
                .ConfigureAwait(true);
            await PopulateResultsOnUiAsync(results).ConfigureAwait(true);
            ProgressText = results.Count > 0
                ? LocalizationService.Format("ThreatCount", results.Count)
                : LocalizationService.Get("ScanComplete");
            _services.RequestDashboardRefresh();
        }
        catch (OperationCanceledException)
        {
            ProgressText = LocalizationService.Get("ScanCancelled");
        }
        catch (Exception ex)
        {
            Logger.Error($"Custom scan failed: {ex.Message}");
            ProgressText = LocalizationService.Get("ScanError");
        }
        finally
        {
            IsScanning = false;
            IsIndeterminate = false;
        }
    }

    [RelayCommand]
    private void BrowseFolder()
    {
        using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
        {
            dialog.Description = LocalizationService.Get("SelectFolder");
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                CustomPath = dialog.SelectedPath;
        }
    }

    [RelayCommand]
    private void BrowseFile()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = LocalizationService.Get("SelectFile"),
            Filter = LocalizationService.Get("FileFilter")
        };
        if (dialog.ShowDialog() == true)
            FilePath = dialog.FileName;
    }

    [RelayCommand(CanExecute = nameof(CanCancelScan))]
    private void CancelScan()
    {
        _services.Scanner.CancelScan();
        _cts?.Cancel();
    }

    private bool CanCancelScan() => IsScanning;

    [RelayCommand]
    private void QuarantineThreat(ScanThreatDisplay? item)
    {
        if (item == null) return;
        if (!File.Exists(item.FilePath))
        {
            ProgressText = LocalizationService.Get("FileNotFound");
            return;
        }

        _services.Quarantine.QuarantineFile(item.FilePath, item.Threat);
        ThreatResults.Remove(item);
        RebuildThreatGroups();
        ThreatsFound = ThreatResults.Count;
        HasResults = ThreatResults.Count > 0;
        UpdateThreatsLabel();
        ProgressText = LocalizationService.Get("Quarantined");
    }

    private bool CanScan() => !IsScanning;
    private bool CanCustomScan() => !IsScanning && !string.IsNullOrWhiteSpace(CustomPath);
    private bool CanFileScan() => !IsScanning && !string.IsNullOrWhiteSpace(FilePath);

    partial void OnCustomPathChanged(string value) => CustomScanCommand.NotifyCanExecuteChanged();
    partial void OnFilePathChanged(string value) => FileScanCommand.NotifyCanExecuteChanged();
    partial void OnThreatsFoundChanged(int value) => UpdateThreatsLabel();
    partial void OnIsScanningChanged(bool value)
    {
        QuickScanCommand.NotifyCanExecuteChanged();
        FullScanCommand.NotifyCanExecuteChanged();
        CustomScanCommand.NotifyCanExecuteChanged();
        FileScanCommand.NotifyCanExecuteChanged();
        CancelScanCommand.NotifyCanExecuteChanged();
    }

    private async Task RunScanAsync(ScanMode mode)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        IsScanning = true;
        IsIndeterminate = true;
        ThreatsFound = 0;
        ThreatResults.Clear();
        ThreatGroups.Clear();
        HasResults = false;
        SummaryLabel = "";
        ProgressValue = 0;
        ProgressText = LocalizationService.Get("ScanStarting");

        try
        {
            var results = await _services.Scanner.RunScanAsync(mode, _cts.Token)
                .ConfigureAwait(true);
            await PopulateResultsOnUiAsync(results).ConfigureAwait(true);
            if (_lastClamIncomplete > 0)
                ProgressText = LocalizationService.Format("ScanCompleteClamIncomplete", _lastClamIncomplete);
            else
                ProgressText = LocalizationService.Get("ScanComplete");
            _services.RequestDashboardRefresh();
        }
        catch (OperationCanceledException)
        {
            ProgressText = LocalizationService.Get("ScanCancelled");
        }
        catch (Exception ex)
        {
            Logger.Error($"{mode} scan failed: {ex.Message}");
            ProgressText = LocalizationService.Get("ScanError");
        }
        finally
        {
            IsScanning = false;
            IsIndeterminate = false;
        }
    }

    private async Task PopulateResultsOnUiAsync(List<ScanResult> results)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null)
        {
            PopulateResults(results);
            return;
        }

        await dispatcher.InvokeAsync(
            () => PopulateResults(results),
            System.Windows.Threading.DispatcherPriority.Background);
    }

    private void PopulateResults(List<ScanResult> results)
    {
        ThreatResults.Clear();
        foreach (var result in results)
        {
            foreach (var threat in result.Threats)
            {
                var tier = ThreatRiskClassifier.Classify(threat);
                ThreatResults.Add(new ScanThreatDisplay
                {
                    FilePath = result.FilePath,
                    ThreatName = threat.ThreatName,
                    Method = threat.Method.ToString(),
                    RiskTier = tier,
                    RiskLabel = RiskTierLabel(tier),
                    Threat = threat
                });
            }
        }

        RebuildThreatGroups();
        ThreatsFound = ThreatResults.Count;
        HasResults = ThreatResults.Count > 0;
        UpdateThreatsLabel();
    }

    private void RebuildThreatGroups()
    {
        ThreatGroups.Clear();
        foreach (var tier in new[]
                 {
                     ThreatRiskTier.Malware,
                     ThreatRiskTier.Dangerous,
                     ThreatRiskTier.Suspicious,
                     ThreatRiskTier.Low
                 })
        {
            var items = ThreatResults.Where(t => t.RiskTier == tier).ToList();
            if (items.Count == 0)
                continue;

            var group = new ThreatRiskGroup
            {
                Tier = tier,
                Title = LocalizationService.Format("ThreatRiskGroupTitle", RiskTierLabel(tier), items.Count),
                Hint = RiskTierHint(tier),
                Count = items.Count,
                AccentBrush = RiskTierBrush(tier),
                IsExpanded = tier >= ThreatRiskTier.Dangerous,
                Items = new ObservableCollection<ScanThreatDisplay>(items)
            };
            ThreatGroups.Add(group);
        }
    }

    private static string RiskTierLabel(ThreatRiskTier tier) => tier switch
    {
        ThreatRiskTier.Malware => LocalizationService.Get("RiskMalware"),
        ThreatRiskTier.Dangerous => LocalizationService.Get("RiskDangerous"),
        ThreatRiskTier.Suspicious => LocalizationService.Get("RiskSuspicious"),
        _ => LocalizationService.Get("RiskLow")
    };

    private static string RiskTierHint(ThreatRiskTier tier) => tier switch
    {
        ThreatRiskTier.Malware => LocalizationService.Get("RiskMalwareHint"),
        ThreatRiskTier.Dangerous => LocalizationService.Get("RiskDangerousHint"),
        ThreatRiskTier.Suspicious => LocalizationService.Get("RiskSuspiciousHint"),
        _ => LocalizationService.Get("RiskLowHint")
    };

    private static System.Windows.Media.Brush RiskTierBrush(ThreatRiskTier tier) => tier switch
    {
        ThreatRiskTier.Malware => new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xE5, 0x39, 0x35)),
        ThreatRiskTier.Dangerous => new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xFB, 0x8C, 0x00)),
        ThreatRiskTier.Suspicious => new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xF9, 0xA8, 0x25)),
        _ => new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0x78, 0x90, 0x9C))
    };
}
