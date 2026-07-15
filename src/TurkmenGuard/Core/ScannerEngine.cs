using System.Diagnostics;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Multi-stage scan orchestrator: exclusions → ClamAV → YARA.
/// </summary>
public class ScannerEngine : IDisposable
{
    private readonly ClamAvEngine _clam = new();
    private readonly YaraScanner _yara = new();
    private readonly HashChecker _hash = new();
    private readonly AppSettings _settings;
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private readonly SemaphoreSlim _fileScanSemaphore = new(1, 1);
    // TCP clamd handles ~2 concurrent SCAN well; more causes queue/timeouts
    private readonly SemaphoreSlim _bulkParallelism = new(2, 2);
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

        var skipSemaphore = IsBulkScanActive && mode is ScanMode.Quick or ScanMode.Full;

        if (!skipSemaphore)
            await _fileScanSemaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return ScanFileCore(path, mode, ct);
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

        // Locked OS files (hiberfil.sys etc.) — never hand them to YARA/hash
        if (!ScanPolicy.CanOpenForScan(path))
            return result;

        try
        {
            var len = ScanPolicy.TryGetFileLength(path);
            var clamTimeoutMs = ResolveClamTimeoutMs(mode, len);

            // Multi‑MB / GB apps: structural scan first (fast), optional deep ClamAV on File Scan
            if (len > 0 && LargeFileScanner.NeedsLargeScan(len))
            {
                result.Threats.AddRange(ScanLargeFile(path, mode, ct));
                if (result.Threats.Count > 0)
                    return FinalizeResult(result, sw, mode);

                // Manual deep pass only when structural found nothing and file is bounded
                if (mode == ScanMode.SingleFile &&
                    len <= ScanPolicy.MaxSingleFileClamBytes &&
                    _clam.DaemonReady)
                {
                    var deep = _clam.Scan(path, timeoutMs: 60_000, allowClamScanFallback: false,
                        maxBytes: ScanPolicy.MaxSingleFileClamBytes);
                    result.Threats.AddRange(deep);
                }

                return FinalizeResult(result, sw, mode);
            }

            // Quick: ClamAV (speed) + YARA always (custom/test sigs ClamAV does not know)
            if (mode == ScanMode.Quick)
            {
                if (len > 0 && len <= ScanPolicy.MaxQuickClamFileBytes && _clam.DaemonReady)
                {
                    var clamThreats = _clam.Scan(path, clamTimeoutMs, allowClamScanFallback: false,
                        maxBytes: ScanPolicy.MaxQuickClamFileBytes);
                    if (clamThreats.Count > 0)
                        result.Threats.AddRange(clamThreats);
                }

                if (_yara.IsAvailable && len > 0 && len <= ScanPolicy.MaxYaraFileBytes)
                    result.Threats.AddRange(_yara.Scan(path));

                return FinalizeResult(result, sw, mode);
            }

            // Real-time: ClamAV + YARA (YARA catches custom/test signatures)
            if (mode == ScanMode.RealTime)
            {
                if (_clam.DaemonReady && len > 0 && len <= ScanPolicy.MaxQuickClamFileBytes)
                {
                    var clamThreats = _clam.Scan(path, clamTimeoutMs, allowClamScanFallback: false,
                        maxBytes: ScanPolicy.MaxQuickClamFileBytes);
                    if (clamThreats.Count > 0)
                        result.Threats.AddRange(clamThreats);
                }
                else if (!_clam.DaemonReady)
                {
                    var hashThreat = _hash.Check(path);
                    if (hashThreat != null && hashThreat.Severity >= ThreatSeverity.High)
                    {
                        result.FileHash = HashChecker.ComputeSha256(path);
                        result.Threats.Add(hashThreat);
                    }
                }

                if (_yara.IsAvailable && len > 0 && len <= ScanPolicy.MaxYaraFileBytes)
                    result.Threats.AddRange(_yara.Scan(path));

                return FinalizeResult(result, sw, mode);
            }

            // Full / SingleFile (≤ threshold) — ClamAV primary; YARA for scripts / timeout
            if (_clam.DaemonReady && len > 0 && len <= ScanPolicy.MaxFullClamFileBytes)
            {
                var clamThreats = _clam.Scan(path, clamTimeoutMs, allowClamScanFallback: false,
                    maxBytes: ScanPolicy.MaxFullClamFileBytes);
                if (clamThreats.Count > 0)
                {
                    result.Threats.AddRange(clamThreats);
                    return FinalizeResult(result, sw, mode);
                }
            }
            else if (!_clam.DaemonReady)
            {
                var hashThreat = _hash.Check(path);
                if (hashThreat != null && hashThreat.Severity >= ThreatSeverity.High)
                {
                    result.FileHash = HashChecker.ComputeSha256(path);
                    result.Threats.Add(hashThreat);
                    return FinalizeResult(result, sw, mode);
                }
            }

            if (_yara.IsAvailable && len > 0 && len <= ScanPolicy.MaxYaraFileBytes &&
                ShouldRunYaraLayer(path, mode, len))
            {
                result.Threats.AddRange(_yara.Scan(path));
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

    /// <summary>
    /// Large files: PE header/sections/overlay + edges → ClamAV/YARA buffers;
    /// ZIP/SFX inners extracted to scratch when present.
    /// </summary>
    private List<ThreatInfo> ScanLargeFile(string path, ScanMode mode, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();
        LargeFileScanner.CleanupScratch();

        var regions = LargeFileScanner.ExtractRegions(path, mode);
        var regionTimeout = mode == ScanMode.SingleFile ? 8_000 : 3_000;

        foreach (var region in regions)
        {
            ct.ThrowIfCancellationRequested();
            if (region.Data.Length == 0)
                continue;

            if (_clam.DaemonReady)
            {
                var clam = _clam.ScanBytes(region.Data, path, regionTimeout, region.Label);
                if (clam.Count > 0)
                {
                    threats.AddRange(clam);
                    if (mode != ScanMode.SingleFile)
                        return threats;
                }
            }

            if (_yara.IsAvailable)
            {
                var yara = _yara.ScanMemory(region.Data, path, region.Label);
                if (yara.Count > 0)
                {
                    threats.AddRange(yara);
                    if (mode != ScanMode.SingleFile)
                        return threats;
                }
            }
        }

        // ZIP / SFX with embedded executables (installers)
        var allowArchive = mode is ScanMode.SingleFile or ScanMode.Quick or ScanMode.Full;
        if (allowArchive)
        {
            var extracted = LargeFileScanner.ExtractArchiveExecutables(path, mode);
            try
            {
                foreach (var inner in extracted)
                {
                    ct.ThrowIfCancellationRequested();
                    if (_clam.DaemonReady)
                    {
                        var clam = _clam.Scan(inner, timeoutMs: regionTimeout, allowClamScanFallback: false,
                            maxBytes: ScanPolicy.LargeInnerEntryMaxBytes);
                        foreach (var t in clam)
                        {
                            t.FilePath = path;
                            t.Details = $"{t.Details} [archive-inner]";
                        }
                        threats.AddRange(clam);
                    }

                    if (_yara.IsAvailable)
                    {
                        var yara = _yara.Scan(inner);
                        foreach (var t in yara)
                        {
                            t.FilePath = path;
                            t.Details = $"{t.Details} [archive-inner]";
                        }
                        threats.AddRange(yara);
                    }

                    if (threats.Count > 0 && mode != ScanMode.SingleFile)
                        break;
                }
            }
            finally
            {
                foreach (var inner in extracted)
                {
                    try { File.Delete(inner); } catch { /* ignore */ }
                }
            }
        }

        if (regions.Count > 0)
            Logger.Info($"LargeFile scan [{Path.GetFileName(path)}]: {regions.Count} regions, {threats.Count} hits");

        return threats;
    }

    /// <summary>
    /// Adaptive ClamAV wall-clock: small files finish fast; never wait 20s on Full.
    /// </summary>
    private static int ResolveClamTimeoutMs(ScanMode mode, long length)
    {
        if (mode == ScanMode.SingleFile)
            return 12_000;
        if (mode == ScanMode.RealTime)
            return 3_500;
        if (mode == ScanMode.Quick)
            return length > 2L * 1024 * 1024 ? 3_000 : 2_000;

        // Full — prefer skip-and-continue over long stalls
        if (length <= 0)
            return 1_500;
        if (length <= 256 * 1024)
            return 1_200;
        if (length <= 2L * 1024 * 1024)
            return 2_000;
        return 3_000;
    }

    /// <summary>
    /// Full Scan: ClamAV covers known PE malware. YARA only for scripts / timeout / SingleFile.
    /// (YARA on every DLL under 2 MB made Full Scan unusably slow.)
    /// </summary>
    private bool ShouldRunYaraLayer(string path, ScanMode mode, long length)
    {
        if (mode == ScanMode.SingleFile)
            return true;

        // Real timeout on this file — YARA backup only for small payloads
        if (_clam.LastScanTimedOut)
            return length > 0 && length <= 512 * 1024;

        if (!_clam.DaemonReady)
            return length > 0 && length <= 1024 * 1024;

        var ext = Path.GetExtension(path);
        return ext.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".jse", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".vba", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".hta", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".wsf", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".htm", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".html", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".docm", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".xlsm", StringComparison.OrdinalIgnoreCase);
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

        // Quick scan: collect scannable files with live progress, then scan in bounded batches
        if (mode == ScanMode.Quick)
        {
            var quickFiles = new List<string>();
            foreach (var file in PathHelper.EnumerateFilesSafe(directory, skipDir))
            {
                ct.ThrowIfCancellationRequested();

                if (_settings.IsExcluded(file) || !ScanPolicy.ShouldScanExtension(file, mode))
                    continue;

                quickFiles.Add(file);
                if (progress != null && (quickFiles.Count == 1 || quickFiles.Count % 16 == 0))
                {
                    progress.TotalFiles = quickFiles.Count;
                    progress.FilesScanned = 0; // collecting phase
                    progress.CurrentFile = file;
                    ReportProgressThrottled(progress, force: quickFiles.Count == 1);
                    if (quickFiles.Count % 64 == 0)
                        await HopToThreadPoolAsync().ConfigureAwait(false);
                }
            }

            if (progress != null)
            {
                progress.TotalFiles = quickFiles.Count;
                ReportProgressThrottled(progress, force: true);
            }

            if (quickFiles.Count == 0)
                return results;

            // Parallel only when clamd handles scans; YARA is single-threaded internally
            if (quickFiles.Count > 1 && _clam.DaemonReady)
                return await ScanFilesParallelAsync(quickFiles, mode, progress, ct).ConfigureAwait(false);

            foreach (var file in quickFiles)
            {
                ct.ThrowIfCancellationRequested();
                await ScanOneFileAsync(file, mode, progress, results, ct).ConfigureAwait(false);
            }

            return results;
        }

        // Full / custom — sequential INSTREAM (2-way parallel flooded clamd → timeout streaks).
        var scanned = 0;
        foreach (var file in PathHelper.EnumerateFilesSafe(directory, skipDir))
        {
            ct.ThrowIfCancellationRequested();

            if (_settings.IsExcluded(file) || !ScanPolicy.ShouldScanExtension(file, mode))
                continue;

            scanned++;
            if (progress != null)
            {
                progress.CurrentFile = file;
                progress.FilesScanned = scanned;
                if (progress.TotalFiles < scanned)
                    progress.TotalFiles = scanned + 64;
                ReportProgressThrottled(progress, force: scanned == 1);
            }

            if (scanned % 64 == 0)
                await HopToThreadPoolAsync().ConfigureAwait(false);

            var result = await ScanFileAsync(file, mode, ct).ConfigureAwait(false);
            if (result.IsThreat)
            {
                if (progress != null)
                    progress.ThreatsFound++;
                results.Add(result);
            }
        }

        if (progress != null && scanned > 0)
            progress.TotalFiles = Math.Max(progress.TotalFiles, scanned);

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
        const int batchSize = 24;

        for (var offset = 0; offset < files.Count; offset += batchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch = files.GetRange(offset, Math.Min(batchSize, files.Count - offset));

            var tasks = batch.Select(async file =>
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

                    // Offload blocking TCP scan so the batch pipeline stays responsive
                    var result = await Task.Run(
                        async () => await ScanFileAsync(file, mode, ct).ConfigureAwait(false),
                        ct).ConfigureAwait(false);
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
        }

        if (progress != null)
            progress.ThreatsFound = threatCount;
        return bag.ToList();
    }

    private void ReportProgressThrottled(ScanProgress progress, bool force = false)
    {
        _progressCounter++;
        var now = DateTime.UtcNow;
        if (!force &&
            _progressCounter % 4 != 0 &&
            (now - _lastProgressReport).TotalMilliseconds < 150)
            return;

        _lastProgressReport = now;
        OnProgress?.Invoke(progress);
    }

    /// <summary>
    /// Runs Quick/Full scan on the thread pool so the WPF UI never freezes.
    /// </summary>
    public Task<List<ScanResult>> RunScanAsync(ScanMode mode, CancellationToken ct = default) =>
        Task.Run(() => RunScanCoreAsync(mode, ct));

    private async Task<List<ScanResult>> RunScanCoreAsync(ScanMode mode, CancellationToken ct)
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

            RecordManualScanStats(progress.FilesScanned, allResults);
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

    public Task<List<ScanResult>?> TryRunScheduledScanAsync(ScanMode mode) =>
        Task.Run(() => TryRunScheduledScanCoreAsync(mode));

    private async Task<List<ScanResult>?> TryRunScheduledScanCoreAsync(ScanMode mode)
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

    public Task<List<ScanResult>> ExecuteLockedScanAsync(
        Func<CancellationToken, Task<(List<ScanResult> Results, int FilesScanned)>> work,
        CancellationToken ct) =>
        Task.Run(() => ExecuteLockedScanCoreAsync(work, ct));

    private async Task<List<ScanResult>> ExecuteLockedScanCoreAsync(
        Func<CancellationToken, Task<(List<ScanResult> Results, int FilesScanned)>> work,
        CancellationToken ct)
    {
        await _scanLock.WaitAsync(ct).ConfigureAwait(false);
        Interlocked.Exchange(ref _isScanning, 1);
        EnterBulkScan();
        try
        {
            var token = ReplaceScanCts(ct).Token;
            var (results, filesScanned) = await work(token).ConfigureAwait(false);
            RecordManualScanStats(filesScanned, results);
            return results;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        finally
        {
            ExitBulkScan();
            Interlocked.Exchange(ref _isScanning, 0);
            _scanLock.Release();
        }
    }

    /// <summary>
    /// Yields to the thread pool. Unlike Task.Yield(), does not return to the WPF UI SynchronizationContext.
    /// </summary>
    private static Task HopToThreadPoolAsync()
    {
        if (SynchronizationContext.Current == null)
            return Task.CompletedTask;

        var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        ThreadPool.QueueUserWorkItem(_ => tcs.TrySetResult(null));
        return tcs.Task;
    }

    private void RecordManualScanStats(int filesScanned, List<ScanResult> results)
    {
        _settings.TotalFilesScanned += filesScanned;
        _settings.TotalThreatsFound += CountActionableThreats(results);
        _settings.LastManualScan = DateTime.Now;
        var settings = _settings;
        _ = Task.Run(() => SettingsService.Save(settings));
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

    private sealed class BulkScanSession : IDisposable
    {
        private readonly ScannerEngine _engine;
        private bool _disposed;

        public BulkScanSession(ScannerEngine engine)
        {
            _engine = engine;
            _engine.EnterBulkScan();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _engine.ExitBulkScan();
        }
    }

    public void CancelScan()
    {
        lock (_ctsLock)
        {
            _scanCts?.Cancel();
        }
        _clam.CancelActiveScan();
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
