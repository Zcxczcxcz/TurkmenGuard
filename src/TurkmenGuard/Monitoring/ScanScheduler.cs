using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.Monitoring;

/// <summary>
/// Scheduled quick scans based on ScanSchedule setting.
/// </summary>
public class ScanScheduler : IDisposable
{
    private readonly AppSettings _settings;
    private readonly ScannerEngine _scanner;
    private System.Threading.Timer? _timer;
    private int _checkRunning;

    public event Action<int>? ScheduledScanComplete;

    public ScanScheduler(AppSettings settings, ScannerEngine scanner)
    {
        _settings = settings;
        _scanner = scanner;
    }

    public void Start()
    {
        if (_settings.ScanSchedule == "never")
            return;

        _timer = new System.Threading.Timer(_ => _ = CheckAndRunAsync(), null,
            TimeSpan.FromMinutes(5), TimeSpan.FromHours(6));
        Logger.Info($"Scan scheduler started ({_settings.ScanSchedule})");
    }

    private async Task CheckAndRunAsync()
    {
        if (Interlocked.CompareExchange(ref _checkRunning, 1, 0) != 0)
            return;

        try
        {
            if (_scanner.IsScanning || !IsDue())
                return;

            Logger.Info("Running scheduled quick scan");
            var results = await _scanner.TryRunScheduledScanAsync(ScanMode.Quick);
            if (results == null)
                return;

            _settings.LastScheduledScan = DateTime.Now;
            SettingsService.Save(_settings);
            ScheduledScanComplete?.Invoke(results.Count);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Scheduled scan failed: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _checkRunning, 0);
        }
    }

    private bool IsDue()
    {
        if (_settings.ScanSchedule == "never")
            return false;

        var last = _settings.LastScheduledScan;
        if (last == null)
            return true;

        return _settings.ScanSchedule switch
        {
            "daily" => DateTime.Now - last >= TimeSpan.FromDays(1),
            "weekly" => DateTime.Now - last >= TimeSpan.FromDays(7),
            "monthly" => DateTime.Now - last >= TimeSpan.FromDays(30),
            _ => false
        };
    }

    public void Restart()
    {
        Stop();
        Start();
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose() => Stop();
}
