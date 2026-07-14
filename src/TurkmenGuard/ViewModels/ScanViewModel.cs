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
    public ThreatInfo Threat { get; init; } = new();
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
    [ObservableProperty] private bool _hasResults;

    public ObservableCollection<ScanThreatDisplay> ThreatResults { get; } = [];

    public ScanViewModel(ApplicationServices services)
    {
        _services = services;
        _services.Scanner.OnProgress += OnProgress;
        RefreshLabels();
        LocalizationService.LanguageChanged += RefreshLabels;
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
        UpdateThreatsLabel();
    }

    private void UpdateThreatsLabel() =>
        ThreatsLabel = $"{LocalizationService.Get("ThreatsFound")}: {ThreatsFound}";

    private DateTime _lastProgressUi = DateTime.MinValue;

    private void OnProgress(ScanProgress p)
    {
        var now = DateTime.UtcNow;
        if (p.IsRunning && p.FilesScanned > 0 &&
            (now - _lastProgressUi).TotalMilliseconds < 300 && p.FilesScanned % 10 != 0)
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
        IsIndeterminate = p.IsRunning && p.TotalFiles <= 0;
        if (p.TotalFiles > 0)
        {
            ProgressValue = (double)p.FilesScanned / p.TotalFiles * 100;
            ProgressText = LocalizationService.Format("ScanProgress", p.FilesScanned, p.TotalFiles, Path.GetFileName(p.CurrentFile));
        }
        else if (p.IsRunning)
        {
            ProgressText = LocalizationService.Format("ScanProgressIndeterminate", p.FilesScanned, Path.GetFileName(p.CurrentFile));
        }
        ThreatsFound = p.ThreatsFound;
        UpdateThreatsLabel();
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
            var results = await _services.Scanner.ScanDirectoryAsync(CustomPath, ScanMode.SingleFile, progress, token);
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

            var result = await _services.Scanner.ScanFileAsync(FilePath, ScanMode.SingleFile, token);
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
        ProgressValue = 0;

        try
        {
            using (_services.Scanner.BeginBulkScanSession())
            {
                var (results, filesScanned) = await scanFunc(_cts.Token).ConfigureAwait(true);
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(
                    () => PopulateResults(results),
                    System.Windows.Threading.DispatcherPriority.Background);
                ProgressText = results.Count > 0
                    ? LocalizationService.Format("ThreatCount", results.Count)
                    : LocalizationService.Get("ScanComplete");
                _services.Settings.TotalFilesScanned += filesScanned;
                _services.Settings.TotalThreatsFound += results.Sum(r =>
                    r.Threats.Count(t => t.Severity >= ThreatSeverity.High));
                _services.Settings.LastScheduledScan = DateTime.Now;
                _ = Task.Run(() => SettingsService.Save(_services.Settings));
            }
        }
        catch (OperationCanceledException)
        {
            ProgressText = LocalizationService.Get("ScanCancelled");
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
        ProgressValue = 0;

        try
        {
            var results = await _services.Scanner.RunScanAsync(mode, _cts.Token).ConfigureAwait(true);
            await System.Windows.Application.Current.Dispatcher.InvokeAsync(
                () => PopulateResults(results),
                System.Windows.Threading.DispatcherPriority.Background);
            ProgressText = LocalizationService.Get("ScanComplete");
        }
        catch (OperationCanceledException)
        {
            ProgressText = LocalizationService.Get("ScanCancelled");
        }
        finally
        {
            IsScanning = false;
            IsIndeterminate = false;
        }
    }

    private void PopulateResults(List<ScanResult> results)
    {
        ThreatResults.Clear();
        foreach (var result in results)
        {
            foreach (var threat in result.Threats)
            {
                ThreatResults.Add(new ScanThreatDisplay
                {
                    FilePath = result.FilePath,
                    ThreatName = threat.ThreatName,
                    Method = threat.Method.ToString(),
                    Threat = threat
                });
            }
        }
        ThreatsFound = ThreatResults.Count;
        HasResults = ThreatResults.Count > 0;
        UpdateThreatsLabel();
    }
}
