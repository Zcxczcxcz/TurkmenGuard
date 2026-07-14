using System.Diagnostics;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Multi-stage scan orchestrator: exclusions → ClamAV → YARA → entropy (Full only).
/// </summary>
public class ScannerEngine : IDisposable
{
    private readonly ClamAvEngine _clam = new();
    private readonly YaraScanner _yara = new();
    private readonly HashChecker _hash = new();
    private readonly AppSettings _settings;
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private readonly SemaphoreSlim _fileScanSemaphore = new(1, 1);
    private readonly SemaphoreSlim _bulkParallelism = new(3, 3);
    private readonly object _ctsLock = new();
    private CancellationTokenSource? _scanCts;
    private int _bulkScanDepth;
    private int _isScanning;
    private int _progressCounter;
    private DateTime _lastProgressReport = DateTime.MinValue;

    public event Action<ScanProgress>? OnProgress;
    public event Action<ThreatInfo>? OnThreatDetected;
    public event Action<bool>? BulkScanStateChanged;

    public bool ClamAvAvailable => _clam.IsAvailable;
    public bool ClamAvDaemonReady => _clam.DaemonReady;
    public string ClamAvVersion => _clam.Version;
    public int ClamAvDatabaseCount => _clam.DatabaseCount;
    public string? ClamAvLastError => _clam.LastError;

    public bool YaraAvailable => _yara.IsAvailable;
    public int YaraRulesLoaded => _yara.RulesLoaded;
    public int YaraCompiledRules => _yara.CompiledRuleCount;
    public int HashSignatureCount => _hash.SignatureCount;
    public string HashDatabaseVersion => _hash.DatabaseVersion;
    public string HashDatabaseSource => _hash.DatabaseSource;
    public bool IsScanning => Volatile.Read(ref _isScanning) == 1;
    public bool IsBulkScanActive => Volatile.Read(ref _bulkScanDepth) > 0;

    public ScannerEngine(AppSettings settings)
    {
        _settings = settings;
        Initialize();
    }

    public void Initialize()
    {
        if (_clam.Initialize())
            Logger.Info($"ClamAV engine ready (v{_clam.Version}, {_clam.DatabaseCount} DB files, daemon={_clam.DaemonReady})");
        else
            Logger.Warn($"ClamAV unavailable ({_clam.LastError}); hash + YARA mode");

        _hash.LoadFromEmbedded();
        if (_yara.Initialize(PathHelper.RulesDir))
            Logger.Info($"YARA ready: {_yara.RulesLoaded} files, {_yara.CompiledRuleCount} rules");
        else
            Logger.Warn($"YARA unavailable ({_yara.LastError}).");
    }

    public void ReloadHashDatabase() => _hash.Reload();
    public void CloseHashDatabase() => _hash.CloseDatabase();

    public void ReloadYaraRules()
    {
        if (_yara.Initialize(PathHelper.RulesDir))
            Logger.Info($"YARA reloaded: {_yara.CompiledRuleCount} rules");
    }

    public void ReloadClamAvDatabase()
    {
        _clam.Restart();
        if (_clam.IsAvailable)
            Logger.Info("ClamAV engine restarted after database reload");
    }

    public async Task<ScanResult> ScanFileAsync(string path, ScanMode mode = ScanMode.SingleFile, CancellationToken ct = default)
    {
        if (mode == ScanMode.RealTime && IsBulkScanActive)
            return ScanResult.Clean(path);

        var skipSemaphore = mode == ScanMode.Quick && IsBulkScanActive;

        if (!skipSemaphore)
            await _fileScanSemaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => ScanFileCore(path, mode, ct), ct).ConfigureAwait(false);
        }
        finally
        {
            if (!skipSemaphore)
                _fileScanSemaphore.Release();
        }
    }

    private ScanResult ScanFileCore(string path, ScanMode mode, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var sw = Stopwatch.StartNew();
        var result = ScanResult.Clean(path);

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return result;

        if (_settings.IsExcluded(path) || !ScanPolicy.ShouldScanExtension(path, mode))
            return result;

        var clamTimeoutMs = mode switch
        {
            ScanMode.RealTime => 30_000,
            ScanMode.Quick => 20_000,
            _ => 120_000
        };
        var allowClamScanFallback = mode == ScanMode.SingleFile;
        var useYara = mode is ScanMode.Full or ScanMode.SingleFile;

        try
        {
            if (_clam.DaemonReady || (allowClamScanFallback && _clam.IsAvailable))
            {
                var clamThreats = _clam.Scan(path, clamTimeoutMs, allowClamScanFallback);
                if (clamThreats.Count > 0)
                {
                    result.Threats.AddRange(clamThreats);
                    return FinalizeResult(result, sw, mode);
                }
            }
            else if (!_clam.IsAvailable || !_clam.DaemonReady)
            {
                var hashThreat = _hash.Check(path);
                if (hashThreat != null && hashThreat.Severity >= ThreatSeverity.High)
                {
                    result.FileHash = HashChecker.ComputeSha256(path);
                    result.Threats.Add(hashThreat);
                    return FinalizeResult(result, sw, mode);
                }
            }

            if (useYara && _yara.IsAvailable)
            {
                result.Threats.AddRange(_yara.Scan(path));
                if (result.Threats.Count > 0)
                    return FinalizeResult(result, sw, mode);
            }

            if (mode == ScanMode.Full)
            {
                result.Entropy = EntropyAnalyzer.CalculateFileEntropy(path);
                var entropyThreat = EntropyAnalyzer.Analyze(path);
                if (entropyThreat != null)
                    result.Threats.Add(entropyThreat);
            }

            return FinalizeResult(result, sw, mode);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Logger.Error($"Scan failed [{path}]: {ex.Message}");
            return result;
        }
    }

    private ScanResult FinalizeResult(ScanResult result, Stopwatch sw, ScanMode mode)
    {
        result.Threats = DetectionFilter.FilterThreats(result.Threats, mode);
        result.IsThreat = result.Threats.Count > 0;
        result.ScanDurationMs = sw.ElapsedMilliseconds;
        if (result.IsThreat)
            ReportThreats(result);
        return result;
    }

    private void ReportThreats(ScanResult result)
    {
        foreach (var threat in result.Threats)
        {
            threat.FilePath = string.IsNullOrEmpty(threat.FilePath) ? result.FilePath : threat.FilePath;
            Logger.Threat($"{threat.ThreatName} in {result.FilePath} [{threat.Method}]");
            OnThreatDetected?.Invoke(threat);
        }
    }

    public async Task<List<ScanResult>> ScanDirectoryAsync(
        string directory, ScanMode mode, ScanProgress? progress = null, CancellationToken ct = default)
    {
        var results = new List<ScanResult>();
        if (!Directory.Exists(directory))
            return results;

        if (_settings.ShouldSkipDirectory(directory))
            return results;

        Func<string, bool> skipDir = _settings.ShouldSkipDirectory;

        // Quick scan: small trees — pre-list for parallel scan + progress bar
        if (mode == ScanMode.Quick)
        {
            var quickFiles = PathHelper.EnumerateFilesSafe(directory, skipDir)
                .Where(f => !_settings.IsExcluded(f) && ScanPolicy.ShouldScanExtension(f, mode))
                .ToList();

            if (progress != null)
                progress.TotalFiles = quickFiles.Count;

            if (quickFiles.Count > 1)
                return await ScanFilesParallelAsync(quickFiles, mode, progress, ct).ConfigureAwait(false);

            foreach (var file in quickFiles)
            {
                ct.ThrowIfCancellationRequested();
                await ScanOneFileAsync(file, mode, progress, results, ct).ConfigureAwait(false);
            }

            return results;
        }

        // Full / custom bulk — stream files; never materialize whole drive into RAM
        var scanned = 0;
        foreach (var file in PathHelper.EnumerateFilesSafe(directory, skipDir))
        {
            ct.ThrowIfCancellationRequested();

            if (_settings.IsExcluded(file) || !ScanPolicy.ShouldScanExtension(file, mode))
                continue;

            scanned++;
            if (progress != null && (scanned == 1 || scanned % 8 == 0))
            {
                progress.CurrentFile = file;
                progress.FilesScanned = scanned;
                ReportProgressThrottled(progress);
            }

            if (mode == ScanMode.Full && scanned % 64 == 0)
                await Task.Yield();

            var result = await ScanFileAsync(file, mode, ct).ConfigureAwait(false);
            if (result.IsThreat)
            {
                if (progress != null)
                    progress.ThreatsFound++;
                results.Add(result);
            }
        }

        return results;
    }

    private async Task ScanOneFileAsync(
        string file, ScanMode mode, ScanProgress? progress, List<ScanResult> results, CancellationToken ct)
    {
        if (progress != null)
        {
            progress.CurrentFile = file;
            progress.FilesScanned++;
            ReportProgressThrottled(progress);
        }

        var result = await ScanFileAsync(file, mode, ct).ConfigureAwait(false);
        if (result.IsThreat)
        {
            if (progress != null)
                progress.ThreatsFound++;
            results.Add(result);
        }
    }

    private async Task<List<ScanResult>> ScanFilesParallelAsync(
        List<string> files, ScanMode mode, ScanProgress? progress, CancellationToken ct)
    {
        var bag = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
        var scanned = 0;
        var threatCount = 0;

        var tasks = files.Select(async file =>
        {
            await _bulkParallelism.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                var n = Interlocked.Increment(ref scanned);
                if (progress != null)
                {
                    progress.CurrentFile = file;
                    progress.FilesScanned = n;
                    ReportProgressThrottled(progress);
                }

                var result = await ScanFileAsync(file, mode, ct).ConfigureAwait(false);
                if (result.IsThreat)
                {
                    Interlocked.Increment(ref threatCount);
                    bag.Add(result);
                }
            }
            finally
            {
                _bulkParallelism.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        if (progress != null)
            progress.ThreatsFound = threatCount;
        return bag.ToList();
    }

    private void ReportProgressThrottled(ScanProgress progress)
    {
        _progressCounter++;
        var now = DateTime.UtcNow;
        if (_progressCounter % 8 != 0 && (now - _lastProgressReport).TotalMilliseconds < 300)
            return;

        _lastProgressReport = now;
        OnProgress?.Invoke(progress);
    }

    public async Task<List<ScanResult>> RunScanAsync(ScanMode mode, CancellationToken ct = default)
    {
        await _scanLock.WaitAsync(ct).ConfigureAwait(false);
        Interlocked.Exchange(ref _isScanning, 1);
        EnterBulkScan();
        var progress = new ScanProgress { TotalFiles = 0, IsRunning = true };
        try
        {
            var token = ReplaceScanCts(ct).Token;
            _progressCounter = 0;
            Logger.Info($"{mode} scan started");
            OnProgress?.Invoke(progress);

            var roots = mode == ScanMode.Full ? PathHelper.GetFullScanPaths() : PathHelper.GetQuickScanPaths();
            var allResults = new List<ScanResult>();
            foreach (var root in roots)
            {
                token.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;
                allResults.AddRange(await ScanDirectoryAsync(root, mode, progress, token).ConfigureAwait(false));
            }

            RecordScanStats(progress.FilesScanned, allResults);
            Logger.Info($"{mode} scan done: {allResults.Count} threats");
            return allResults;
        }
        catch (OperationCanceledException)
        {
            progress.IsRunning = false;
            OnProgress?.Invoke(progress);
            throw;
        }
        finally
        {
            progress.IsRunning = false;
            OnProgress?.Invoke(progress);
            ExitBulkScan();
            Interlocked.Exchange(ref _isScanning, 0);
            _scanLock.Release();
        }
    }

    public async Task<List<ScanResult>?> TryRunScheduledScanAsync(ScanMode mode)
    {
        if (!await _scanLock.WaitAsync(0).ConfigureAwait(false))
        {
            Logger.Info("Scheduled scan skipped — another scan is running");
            return null;
        }

        Interlocked.Exchange(ref _isScanning, 1);
        EnterBulkScan();
        var progress = new ScanProgress { TotalFiles = 0, IsRunning = true };
        try
        {
            var token = ReplaceScanCts(CancellationToken.None).Token;
            OnProgress?.Invoke(progress);

            var allResults = new List<ScanResult>();
            foreach (var root in PathHelper.GetQuickScanPaths())
            {
                if (!Directory.Exists(root)) continue;
                allResults.AddRange(await ScanDirectoryAsync(root, mode, progress, token).ConfigureAwait(false));
            }

            RecordScanStats(progress.FilesScanned, allResults);
            return allResults;
        }
        finally
        {
            progress.IsRunning = false;
            OnProgress?.Invoke(progress);
            ExitBulkScan();
            Interlocked.Exchange(ref _isScanning, 0);
            _scanLock.Release();
        }
    }

    private void RecordScanStats(int filesScanned, List<ScanResult> results)
    {
        _settings.TotalFilesScanned += filesScanned;
        _settings.TotalThreatsFound += CountActionableThreats(results);
        _settings.LastScheduledScan = DateTime.Now;
        var settings = _settings;
        _ = Task.Run(() => SettingsService.Save(settings));
    }

    private static int CountActionableThreats(IEnumerable<ScanResult> results) =>
        results.Sum(r => r.Threats.Count(t => t.Severity >= ThreatSeverity.High));

    public IDisposable BeginBulkScanSession() => new BulkScanSession(this);

    private CancellationTokenSource ReplaceScanCts(CancellationToken ct)
    {
        lock (_ctsLock)
        {
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            _scanCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            return _scanCts;
        }
    }

    private void EnterBulkScan()
    {
        if (Interlocked.Increment(ref _bulkScanDepth) == 1)
            BulkScanStateChanged?.Invoke(true);
    }

    private void ExitBulkScan()
    {
        var depth = Interlocked.Decrement(ref _bulkScanDepth);
        if (depth <= 0)
        {
            Interlocked.Exchange(ref _bulkScanDepth, 0);
            BulkScanStateChanged?.Invoke(false);
        }
    }

    private sealed class BulkScanSession(ScannerEngine engine) : IDisposable
    {
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            engine.ExitBulkScan();
        }
    }

    public void CancelScan()
    {
        lock (_ctsLock)
        {
            _scanCts?.Cancel();
        }
    }

    public void Dispose()
    {
        lock (_ctsLock)
        {
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            _scanCts = null;
        }
        _scanLock.Dispose();
        _fileScanSemaphore.Dispose();
        _bulkParallelism.Dispose();
        _clam.Dispose();
        _yara.Dispose();
    }
}
