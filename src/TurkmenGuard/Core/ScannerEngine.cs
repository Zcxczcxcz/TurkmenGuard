using System.Collections.Concurrent;
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
    // Quick/batch: match ClamAV TCP gate (3)
    private readonly SemaphoreSlim _bulkParallelism = new(3, 3);
    private readonly object _ctsLock = new();
    private CancellationTokenSource? _scanCts;
    private FullScanTimer? _fullScanTimer;
    private ConcurrentDictionary<string, byte>? _fullScanSeen;
    private ConcurrentBag<string>? _clamRetryQueue;
    private int _clamIncompleteCount;
    private bool _clamRetryPassActive;
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
        Task.Run(InitializeYaraAsync);
    }

    private void InitializeYaraAsync()
    {
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

    /// <summary>Blocks until background YARA init completes (tests / settings reload).</summary>
    public void WaitForYaraReady(int timeoutMs = 60_000)
    {
        var deadline = Environment.TickCount + timeoutMs;
        while (!_yara.IsAvailable && Environment.TickCount < deadline)
            Thread.Sleep(100);
    }

    public void ReloadClamAvDatabase()
    {
        _clam.Restart();
        if (_clam.IsAvailable)
            Logger.Info("ClamAV engine restarted after database reload");
    }

    public async Task<ScanResult> ScanFileAsync(string path, ScanMode mode = ScanMode.SingleFile, CancellationToken ct = default)
    {
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

        // Locked OS files — probe before YARA/hash; Full skips probe (ClamAV fails fast on locks)
        if (mode != ScanMode.Full && !ScanPolicy.CanOpenForScan(path))
            return result;

        try
        {
            var len = ScanPolicy.TryGetFileLength(path);
            var clamTimeoutMs = ResolveClamTimeoutMs(mode, len);
            var qualityMode = mode == ScanMode.Full;

            // Multi‑MB / GB apps: structural scan first (fast), optional deep ClamAV on File Scan
            if (len > 0 && LargeFileScanner.NeedsLargeScan(len))
            {
                result.Threats.AddRange(ScanLargeFile(path, mode, ct));
                if (result.Threats.Count > 0)
                    return FinalizeResult(result, sw, mode);

                if (mode == ScanMode.SingleFile &&
                    len <= ScanPolicy.MaxSingleFileClamBytes &&
                    _clam.DaemonReady)
                {
                    var deep = _clam.Scan(path, timeoutMs: 60_000, allowClamScanFallback: AllowClamScanFallback(mode),
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
                    var clamThreats = _clam.Scan(path, clamTimeoutMs, AllowClamScanFallback(mode),
                        maxBytes: ScanPolicy.MaxQuickClamFileBytes);
                    if (clamThreats.Count > 0)
                        result.Threats.AddRange(clamThreats);
                    else if (_clam.LastScanTimedOut)
                        MarkClamIncomplete(path, result);
                    else if (_clam.LastScanSkipped)
                    {
                        MarkClamIncomplete(path, result);
                        result.Threats.AddRange(ScanSkippedRegions(path, mode, ct));
                    }
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

            // Real-time: ClamAV + YARA (YARA catches custom/test signatures)
            if (mode == ScanMode.RealTime)
            {
                if (_clam.DaemonReady && len > 0 && len <= ScanPolicy.MaxQuickClamFileBytes)
                {
                    var clamThreats = _clam.Scan(path, clamTimeoutMs, AllowClamScanFallback(mode),
                        maxBytes: ScanPolicy.MaxQuickClamFileBytes);
                    if (clamThreats.Count > 0)
                        result.Threats.AddRange(clamThreats);
                    else if (_clam.LastScanTimedOut)
                        MarkClamIncomplete(path, result);
                    else if (_clam.LastScanSkipped)
                    {
                        MarkClamIncomplete(path, result);
                        result.Threats.AddRange(ScanSkippedRegions(path, mode, ct));
                    }
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

            // Full / SingleFile (≤ threshold) — ClamAV primary; YARA for scripts / PE timeout
            if (_clam.DaemonReady && len > 0 && len <= ScanPolicy.MaxFullClamFileBytes)
            {
                var clamThreats = _clam.Scan(path, clamTimeoutMs, AllowClamScanFallback(mode),
                    maxBytes: ScanPolicy.MaxFullClamFileBytes, qualityMode: qualityMode);
                if (clamThreats.Count > 0)
                {
                    result.Threats.AddRange(clamThreats);
                    return FinalizeResult(result, sw, mode);
                }

                if (_clam.LastScanTimedOut)
                {
                    MarkClamIncomplete(path, result);
                    if (_yara.IsAvailable && len <= ScanPolicy.MaxYaraFileBytes &&
                        ShouldRunYaraLayer(path, mode, len))
                        result.Threats.AddRange(_yara.Scan(path));
                    return FinalizeResult(result, sw, mode);
                }

                if (_clam.LastScanSkipped)
                {
                    MarkClamIncomplete(path, result);
                    result.Threats.AddRange(ScanSkippedRegions(path, mode, ct));
                    if (_yara.IsAvailable && len <= ScanPolicy.MaxYaraFileBytes &&
                        ShouldRunYaraLayer(path, mode, len))
                        result.Threats.AddRange(_yara.Scan(path));
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

        var rush = mode != ScanMode.Full && _clam.TimeoutStreak >= 8;
        var regions = LargeFileScanner.ExtractRegions(path, mode, rush);
        var qualityMode = mode == ScanMode.Full;
        var regionTimeout = mode == ScanMode.SingleFile ? 12_000
            : qualityMode ? 120_000
            : 8_000;
        var clamHadTimeout = false;

        foreach (var region in regions)
        {
            ct.ThrowIfCancellationRequested();
            if (region.Data.Length == 0)
                continue;

            if (_clam.DaemonReady)
            {
                var clam = _clam.ScanBytes(region.Data, path, regionTimeout, region.Label, qualityMode);
                if (clam.Count > 0)
                {
                    threats.AddRange(clam);
                    if (mode != ScanMode.SingleFile)
                        return threats;
                }
                else if (_clam.LastScanTimedOut)
                    clamHadTimeout = true;
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

        if (clamHadTimeout && mode == ScanMode.Full && !_clamRetryPassActive)
            EnqueueClamRetry(path);

        // ZIP / SFX — rush limits to 1 inner entry instead of skipping entirely
        var allowArchive = mode is ScanMode.SingleFile or ScanMode.Quick or ScanMode.Full;
        if (allowArchive)
        {
            var extracted = LargeFileScanner.ExtractArchiveExecutables(path, mode, rush);
            try
            {
                foreach (var inner in extracted)
                {
                    ct.ThrowIfCancellationRequested();
                    if (_clam.DaemonReady)
                    {
                        var clam = _clam.Scan(inner, timeoutMs: regionTimeout, AllowClamScanFallback(mode),
                            maxBytes: ScanPolicy.LargeInnerEntryMaxBytes, qualityMode: qualityMode);
                        foreach (var t in clam)
                        {
                            t.FilePath = path;
                            t.Details = $"{t.Details} [archive-inner]";
                        }
                        threats.AddRange(clam);
                        if (_clam.LastScanTimedOut)
                            clamHadTimeout = true;
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

    private void MarkClamIncomplete(string path, ScanResult result)
    {
        result.ClamAvIncomplete = true;
        Interlocked.Increment(ref _clamIncompleteCount);
        if (_clamRetryQueue != null)
            EnqueueClamRetry(path);
    }

    private void EnqueueClamRetry(string path)
    {
        if (_clamRetryQueue == null || string.IsNullOrWhiteSpace(path) || _clamRetryPassActive)
            return;
        try
        {
            var full = Path.GetFullPath(path);
            _clamRetryQueue.Add(full);
        }
        catch { /* ignore */ }
    }

    /// <summary>
    /// Retry pass: sequential ClamAV with long timeouts. Failed files stay in queue until verified or rounds exhausted.
    /// </summary>
    private async Task<List<ScanResult>> RunClamRetryPassAsync(ScanProgress progress, CancellationToken ct)
    {
        var results = new List<ScanResult>();
        if (_clamRetryQueue == null || _fullScanTimer == null)
            return results;

        var pending = _clamRetryQueue.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (pending.Count == 0)
            return results;

        progress.Phase = "retry";
        _clamRetryPassActive = true;
        Logger.Info($"Full scan ClamAV retry pass: {pending.Count} files (elapsed {_fullScanTimer.ElapsedLabel})");
        ReportProgressThrottled(progress, force: true);

        const int maxRounds = 8;
        const int retryTimeoutMs = 300_000;

        try
        {
            for (var round = 1; round <= maxRounds && pending.Count > 0; round++)
            {
                ct.ThrowIfCancellationRequested();
                var stillPending = new List<string>();

                if (round > 1)
                    Logger.Info($"ClamAV retry round {round}: {pending.Count} files remaining");

                foreach (var path in pending)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!File.Exists(path))
                        continue;

                    var sw = Stopwatch.StartNew();
                    var result = ScanResult.Clean(path);
                    var len = ScanPolicy.TryGetFileLength(path);

                    try
                    {
                        if (len > 0 && LargeFileScanner.NeedsLargeScan(len))
                        {
                            result.Threats.AddRange(ScanLargeFile(path, ScanMode.Full, ct));
                            if (_clam.LastScanTimedOut)
                            {
                                result.ClamAvIncomplete = true;
                                stillPending.Add(path);
                            }
                            else
                                Interlocked.Decrement(ref _clamIncompleteCount);
                        }
                        else if (_clam.DaemonReady && len > 0 && len <= ScanPolicy.MaxFullClamFileBytes)
                        {
                            var clam = _clam.Scan(path, timeoutMs: retryTimeoutMs, AllowClamScanFallback(ScanMode.Full),
                                maxBytes: ScanPolicy.MaxFullClamFileBytes, qualityMode: true);
                            result.Threats.AddRange(clam);
                            if (_clam.LastScanTimedOut)
                            {
                                result.ClamAvIncomplete = true;
                                stillPending.Add(path);
                            }
                            else
                                Interlocked.Decrement(ref _clamIncompleteCount);
                        }

                        if (!result.IsThreat && _yara.IsAvailable && len > 0 && len <= ScanPolicy.MaxYaraFileBytes)
                        {
                            var ext = Path.GetExtension(path);
                            if (ScanPolicy.IsPortableExecutableExtension(ext) || _clam.LastScanTimedOut)
                                result.Threats.AddRange(_yara.Scan(path));
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"ClamAV retry [{Path.GetFileName(path)}]: {ex.Message}");
                        stillPending.Add(path);
                    }

                    result = FinalizeResult(result, sw, ScanMode.Full);
                    if (result.IsThreat)
                    {
                        results.Add(result);
                        progress.ThreatsFound++;
                    }

                    progress.CurrentFile = path;
                    StampTimerOnProgress(progress);
                    ReportProgressThrottled(progress);
                    await HopToThreadPoolAsync().ConfigureAwait(false);
                }

                pending = stillPending.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

            if (pending.Count > 0)
                Logger.Warn($"ClamAV retry exhausted: {pending.Count} file(s) still incomplete after {maxRounds} rounds");
        }
        finally
        {
            _clamRetryPassActive = false;
        }

        progress.ClamAvIncompleteCount = Math.Max(0, Volatile.Read(ref _clamIncompleteCount));
        return results;
    }

    /// <summary>
    /// ClamAV wall-clock: Quick stays fast; Full Scan waits as long as needed for quality.
    /// </summary>
    private static int ResolveClamTimeoutMs(ScanMode mode, long length)
    {
        if (mode == ScanMode.SingleFile)
            return 12_000;
        if (mode == ScanMode.RealTime)
            return 3_500;
        if (mode == ScanMode.Quick)
            return length > 2L * 1024 * 1024 ? 3_000 : 2_000;

        // Full Scan — no artificial rush; scale by file size
        if (length <= 0)
            return 30_000;
        if (length <= 256 * 1024)
            return 30_000;
        if (length <= 2L * 1024 * 1024)
            return 60_000;
        if (length <= 8L * 1024 * 1024)
            return 120_000;
        return 180_000;
    }

    private bool AllowClamScanFallback(ScanMode mode) =>
        !_clam.DaemonReady || mode == ScanMode.SingleFile;

    /// <summary>
    /// Head/tail buffer scan when ClamAV skipped due to dynamic maxBytes shrink.
    /// </summary>
    private List<ThreatInfo> ScanSkippedRegions(string path, ScanMode mode, CancellationToken ct)
    {
        var threats = new List<ThreatInfo>();
        var regions = LargeFileScanner.ExtractEdgeRegions(path, mode, rush: mode != ScanMode.Full);
        var timeout = mode == ScanMode.Full ? 30_000 : 5_000;
        var qualityMode = mode == ScanMode.Full;

        foreach (var region in regions)
        {
            ct.ThrowIfCancellationRequested();
            if (region.Data.Length == 0)
                continue;

            if (_clam.DaemonReady)
            {
                var clam = _clam.ScanBytes(region.Data, path, timeout, region.Label, qualityMode);
                if (clam.Count > 0)
                    threats.AddRange(clam);
            }

            if (_yara.IsAvailable)
            {
                var yara = _yara.ScanMemory(region.Data, path, region.Label);
                if (yara.Count > 0)
                    threats.AddRange(yara);
            }
        }

        return threats;
    }

    /// <summary>
    /// Full Scan: ClamAV covers known PE malware. YARA for scripts / timeout / entropy / SingleFile.
    /// </summary>
    private bool ShouldRunYaraLayer(string path, ScanMode mode, long length)
    {
        if (mode == ScanMode.SingleFile)
            return true;

        // High-entropy PE triggers targeted YARA without scanning every DLL
        if (mode is ScanMode.Full or ScanMode.SingleFile && ScanPolicy.ShouldRunEntropy(path))
        {
            var entropy = EntropyAnalyzer.GetMaxSectionEntropy(path);
            if (entropy >= EntropyAnalyzer.SuspiciousThreshold)
                return length > 0 && length <= ScanPolicy.MaxYaraFileBytes;
        }

        // Real timeout — YARA backup for small payloads + PE up to 16 MB
        if (_clam.LastScanTimedOut || _clam.LastScanSkipped)
        {
            if (length > 0 && length <= 512 * 1024)
                return true;
            return length > 0 && length <= ScanPolicy.MaxYaraFileBytes &&
                   ScanPolicy.IsPortableExecutableExtension(Path.GetExtension(path));
        }

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
        string directory, ScanMode mode, ScanProgress? progress = null, CancellationToken ct = default,
        Func<string, bool>? extraSkipDirectory = null)
    {
        var results = new List<ScanResult>();
        if (!Directory.Exists(directory))
            return results;

        Func<string, bool> skipDir = d =>
            _settings.ShouldSkipDirectory(d, mode) ||
            (extraSkipDirectory?.Invoke(d) == true);

        if (skipDir(directory))
            return results;

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

        // Full / custom — adaptive 1–2 way pipeline (backs off when clamd is overloaded)
        if (mode == ScanMode.Full && _clam.DaemonReady)
            return await ScanDirectoryParallelStreamingAsync(directory, mode, progress, skipDir, ct)
                .ConfigureAwait(false);

        var scanned = 0;
        foreach (var file in PathHelper.EnumerateFilesSafe(directory, skipDir))
        {
            ct.ThrowIfCancellationRequested();

            if (!TryClaimFullScanFile(file))
                continue;
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

            if (scanned % 128 == 0)
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

    /// <summary>
    /// Full Scan: sequential clamd (one file at a time). Degree drops when TimeoutStreak rises.
    /// </summary>
    private async Task<List<ScanResult>> ScanDirectoryParallelStreamingAsync(
        string directory, ScanMode mode, ScanProgress? progress, Func<string, bool> skipDir, CancellationToken ct)
    {
        var bag = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();
        var scanned = 0;
        var threats = 0;
        var inFlight = new List<Task>(32);
        var degree = ResolveFullParallelism();
        using var gate = new SemaphoreSlim(degree, degree);

        foreach (var file in PathHelper.EnumerateFilesSafe(directory, skipDir))
        {
            ct.ThrowIfCancellationRequested();
            if (!TryClaimFullScanFile(file))
                continue;
            if (_settings.IsExcluded(file) || !ScanPolicy.ShouldScanExtension(file, mode))
                continue;

            await gate.WaitAsync(ct).ConfigureAwait(false);
            var path = file;
            var task = Task.Run(() =>
            {
                try
                {
                    ct.ThrowIfCancellationRequested();
                    var n = Interlocked.Increment(ref scanned);
                    if (progress != null)
                    {
                        progress.CurrentFile = path;
                        progress.FilesScanned = n;
                        if (progress.TotalFiles < n)
                            progress.TotalFiles = n + 64;
                        ReportProgressThrottled(progress);
                    }

                    var result = ScanFileCore(path, mode, ct);
                    if (result.ClamAvIncomplete)
                    {
                        if (progress != null)
                            progress.ClamAvIncompleteCount = Volatile.Read(ref _clamIncompleteCount);
                    }

                    if (result.IsThreat)
                    {
                        Interlocked.Increment(ref threats);
                        bag.Add(result);
                        if (progress != null)
                            progress.ThreatsFound = threats;
                    }
                }
                finally
                {
                    gate.Release();
                }
            }, ct);

            inFlight.Add(task);
            if (inFlight.Count >= 32)
            {
                var done = await Task.WhenAny(inFlight).ConfigureAwait(false);
                inFlight.Remove(done);
                await done.ConfigureAwait(false);
            }
        }

        await Task.WhenAll(inFlight).ConfigureAwait(false);
        if (progress != null)
        {
            progress.FilesScanned = scanned;
            progress.TotalFiles = Math.Max(progress.TotalFiles, scanned);
            progress.ThreatsFound = threats;
        }

        return bag.ToList();
    }

    private bool TryClaimFullScanFile(string file)
    {
        if (_fullScanSeen == null)
            return true;
        try
        {
            return _fullScanSeen.TryAdd(Path.GetFullPath(file), 0);
        }
        catch
        {
            return true;
        }
    }

    private int ResolveFullParallelism()
    {
        if (!_clam.DaemonReady)
            return 1;
        // Full Scan: one file at a time through clamd — fewer skips, retry queue stays small
        return 1;
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
        StampTimerOnProgress(progress);
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

            var allResults = new List<ScanResult>();

            if (mode == ScanMode.Full)
            {
                _fullScanTimer = new FullScanTimer();
                _fullScanSeen = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
                _clamRetryQueue = new ConcurrentBag<string>();
                Interlocked.Exchange(ref _clamIncompleteCount, 0);
                progress.Phase = "main";

                var priority = PathHelper.GetFullScanPriorityPaths();
                foreach (var folder in priority)
                {
                    token.ThrowIfCancellationRequested();
                    if (!Directory.Exists(folder)) continue;
                    allResults.AddRange(await ScanDirectoryAsync(folder, mode, progress, token)
                        .ConfigureAwait(false));
                }

                foreach (var drive in PathHelper.GetFullScanPaths())
                {
                    token.ThrowIfCancellationRequested();
                    if (!Directory.Exists(drive)) continue;

                    Func<string, bool> skipCovered = d =>
                        priority.Any(c => PathHelper.IsUnderPath(d, c));

                    allResults.AddRange(await ScanDirectoryAsync(drive, mode, progress, token, skipCovered)
                        .ConfigureAwait(false));
                }

                allResults.AddRange(await RunClamRetryPassAsync(progress, token).ConfigureAwait(false));

                progress.ClamAvIncompleteCount = Math.Max(0, Volatile.Read(ref _clamIncompleteCount));
                var incomplete = progress.ClamAvIncompleteCount;
                Logger.Info($"Full scan done: {allResults.Count} threats, {progress.FilesScanned} files, {incomplete} ClamAV incomplete, elapsed {_fullScanTimer.ElapsedLabel}");
            }
            else
            {
                foreach (var root in PathHelper.GetQuickScanPaths())
                {
                    token.ThrowIfCancellationRequested();
                    if (!Directory.Exists(root)) continue;
                    allResults.AddRange(await ScanDirectoryAsync(root, mode, progress, token)
                        .ConfigureAwait(false));
                }
            }

            RecordManualScanStats(progress.FilesScanned, allResults);
            if (mode != ScanMode.Full)
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
            _fullScanTimer = null;
            _fullScanSeen = null;
            _clamRetryQueue = null;
            ExitBulkScan();
            Interlocked.Exchange(ref _isScanning, 0);
            _scanLock.Release();
        }
    }

    private void StampTimerOnProgress(ScanProgress? progress)
    {
        if (progress == null || _fullScanTimer == null)
            return;
        progress.ElapsedSeconds = _fullScanTimer.ElapsedSeconds;
        progress.EstimatedRemainingSeconds = _fullScanTimer.EstimateRemainingSeconds(
            progress.FilesScanned, progress.TotalFiles);
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
