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
    private readonly QuarantineManager _quarantine;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentQueue<string> _scanQueue = new();
    private readonly Dictionary<string, DateTime> _debounce = new();
    private readonly TimeSpan _debounceInterval = TimeSpan.FromSeconds(2);
    private readonly object _debounceLock = new();
    private int _workerActive;
    private bool _enabled;

    public event Action<string>? FileEvent;
    public event Action<ThreatInfo>? ThreatDetected;
    public event Action? ProtectionStateChanged;

    public bool IsEnabled => _enabled;

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
                FileEvent?.Invoke($"Monitoring: {folder}");
            }
            catch (Exception ex)
            {
                Logger.Warn($"Cannot watch {folder}: {ex.Message}");
            }
        }

        _enabled = true;
        _settings.RealTimeEnabled = true;
        SettingsService.Save(_settings);
        ProtectionStateChanged?.Invoke();
        Logger.Info("Real-time protection enabled");
    }

    public void Stop()
    {
        if (!_enabled) return;

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
        ProtectionStateChanged?.Invoke();
        Logger.Info("Real-time protection disabled");
    }

    public void Shutdown()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _enabled = false;
    }

    private void HandleEvent(string path)
    {
        if (!_enabled || string.IsNullOrWhiteSpace(path) || Directory.Exists(path))
            return;

        if (_scanner.IsBulkScanActive)
            return;

        if (_settings.IsExcluded(path) || !ScanPolicy.ShouldScanExtension(path))
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
        EnsureWorker();
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
                    await Task.Delay(500);
                    continue;
                }

                try
                {
                    await Task.Delay(400);
                    if (!File.Exists(path)) continue;

                    FileEvent?.Invoke(path);
                    await _scanner.ScanFileAsync(path, ScanMode.RealTime).ConfigureAwait(false);
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
