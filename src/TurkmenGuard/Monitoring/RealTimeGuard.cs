using System.Collections.Concurrent;
using TurkmenGuard.Core;
using TurkmenGuard.Quarantine;
using TurkmenGuard.Services;

namespace TurkmenGuard.Monitoring;

/// <summary>
/// Real-time file system protection via FileSystemWatcher.
/// Uses a single background queue so clamscan never runs in parallel storms.
/// </summary>
public class RealTimeGuard : IDisposable
{
    private readonly ScannerEngine _scanner;
    private readonly AppSettings _settings;
    private readonly QuarantineManager _quarantine; // reserved for future RT auto-quarantine
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentQueue<string> _scanQueue = new();
    private readonly Dictionary<string, DateTime> _debounce = new();
    private readonly TimeSpan _debounceInterval = TimeSpan.FromSeconds(2);
    private readonly object _debounceLock = new();
    private int _workerActive;
    private bool _enabled;
    private int _filesChecked;
    private int _threatsBlocked;
    private DateTime _lastActivityUtc = DateTime.MinValue;
    private System.Threading.Timer? _heartbeat;

    public event Action<string>? FileEvent;
    public event Action<ThreatInfo>? ThreatDetected;
    public event Action? ProtectionStateChanged;
    public event Action? StatsChanged;

    public bool IsEnabled => _enabled;
    public int WatchedFolders => _watchers.Count;
    public int FilesChecked => Volatile.Read(ref _filesChecked);
    public int ThreatsBlocked => Volatile.Read(ref _threatsBlocked);
    public int QueueLength => _scanQueue.Count;
    public DateTime LastActivityUtc => _lastActivityUtc;

    public RealTimeGuard(ScannerEngine scanner, AppSettings settings, QuarantineManager quarantine)
    {
        _scanner = scanner;
        _settings = settings;
        _quarantine = quarantine;
        _scanner.OnThreatDetected += OnScannerThreat;
    }

    public void Start()
    {
        if (_enabled) return;

        var folders = _settings.MonitoredFolders.Count > 0
            ? _settings.MonitoredFolders
            : PathHelper.GetDefaultMonitoredFolders();

        foreach (var folder in folders.Distinct())
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };
                watcher.Created += (_, e) => HandleEvent(e.FullPath);
                watcher.Renamed += (_, e) => HandleEvent(e.FullPath);
                _watchers.Add(watcher);
                Logger.Info($"Real-time monitoring: {folder}");
                FileEvent?.Invoke(LocalizationService.Format("RtWatching", folder));
            }
            catch (Exception ex)
            {
                Logger.Warn($"Cannot watch {folder}: {ex.Message}");
            }
        }

        _enabled = true;
        _settings.RealTimeEnabled = true;
        SettingsService.Save(_settings);
        _heartbeat = new System.Threading.Timer(_ => EmitHeartbeat(), null,
            TimeSpan.FromSeconds(12), TimeSpan.FromSeconds(12));
        ProtectionStateChanged?.Invoke();
        StatsChanged?.Invoke();
        Logger.Info("Real-time protection enabled");
    }

    public void Restart()
    {
        if (!_enabled) return;
        Stop();
        Start();
    }

    public void Stop()
    {
        if (!_enabled) return;

        _heartbeat?.Dispose();
        _heartbeat = null;

        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        while (_scanQueue.TryDequeue(out _)) { }

        lock (_debounceLock)
            _debounce.Clear();

        _enabled = false;
        _settings.RealTimeEnabled = false;
        SettingsService.Save(_settings);
        FileEvent?.Invoke(LocalizationService.Get("RtStopped"));
        ProtectionStateChanged?.Invoke();
        StatsChanged?.Invoke();
        Logger.Info("Real-time protection disabled");
    }

    public void Shutdown()
    {
        _heartbeat?.Dispose();
        _heartbeat = null;
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _enabled = false;
    }

    private void EmitHeartbeat()
    {
        if (!_enabled) return;
        FileEvent?.Invoke(LocalizationService.Format("RtHeartbeat", _watchers.Count, FilesChecked));
        StatsChanged?.Invoke();
    }

    private void HandleEvent(string path)
    {
        if (!_enabled || string.IsNullOrWhiteSpace(path) || Directory.Exists(path))
            return;

        if (_scanner.IsBulkScanActive)
            return;

        if (_settings.IsExcluded(path) || TrustedPaths.IsTrusted(path) ||
            !ScanPolicy.ShouldScanExtension(path))
            return;

        var now = DateTime.UtcNow;
        lock (_debounceLock)
        {
            if (_debounce.TryGetValue(path, out var last) && now - last < _debounceInterval)
                return;

            _debounce[path] = now;

            var stale = _debounce.Where(kv => now - kv.Value > TimeSpan.FromMinutes(5))
                .Select(kv => kv.Key)
                .ToList();
            foreach (var key in stale)
                _debounce.Remove(key);
        }

        if (_scanQueue.Count >= 32)
            _scanQueue.TryDequeue(out _);

        _scanQueue.Enqueue(path);
        FileEvent?.Invoke(LocalizationService.Format("RtQueued", Path.GetFileName(path)));
        EnsureWorker();
        StatsChanged?.Invoke();
    }

    private void EnsureWorker()
    {
        if (Interlocked.CompareExchange(ref _workerActive, 1, 0) != 0)
            return;

        Task.Run(ProcessQueueAsync);
    }

    private async Task ProcessQueueAsync()
    {
        try
        {
            while (_enabled && _scanQueue.TryDequeue(out var path))
            {
                if (_scanner.IsBulkScanActive)
                {
                    _scanQueue.Enqueue(path);
                    await Task.Delay(500);
                    continue;
                }

                try
                {
                    await Task.Delay(400);
                    if (!File.Exists(path)) continue;

                    _lastActivityUtc = DateTime.UtcNow;
                    Interlocked.Increment(ref _filesChecked);
                    var name = Path.GetFileName(path);
                    FileEvent?.Invoke(LocalizationService.Format("RtScanning", name));
                    StatsChanged?.Invoke();

                    var result = await _scanner.ScanFileAsync(path, ScanMode.RealTime).ConfigureAwait(false);
                    if (result.IsThreat)
                    {
                        Interlocked.Increment(ref _threatsBlocked);
                        FileEvent?.Invoke(LocalizationService.Format("RtThreat", name));
                    }
                    else
                    {
                        FileEvent?.Invoke(LocalizationService.Format("RtClean", name));
                    }

                    StatsChanged?.Invoke();
                }
                catch (Exception ex)
                {
                    Logger.Warn($"Real-time scan error [{path}]: {ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _workerActive, 0);
            if (_enabled && !_scanQueue.IsEmpty)
                EnsureWorker();
        }
    }

    private void OnScannerThreat(ThreatInfo threat)
    {
        if (_enabled)
            ThreatDetected?.Invoke(threat);
    }

    public void Dispose()
    {
        _scanner.OnThreatDetected -= OnScannerThreat;
        Shutdown();
    }
}
