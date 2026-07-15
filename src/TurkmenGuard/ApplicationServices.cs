using TurkmenGuard.Core;
using TurkmenGuard.Monitoring;
using TurkmenGuard.Quarantine;
using TurkmenGuard.Security;
using TurkmenGuard.Services;

namespace TurkmenGuard;

/// <summary>
/// Shared application services passed to views and view models.
/// </summary>
public class ApplicationServices
{
    public AppSettings Settings { get; }
    public ScannerEngine Scanner { get; }
    public QuarantineManager Quarantine { get; }
    public RealTimeGuard RealTimeGuard { get; }
    public SelfProtectionService SelfProtection { get; }
    public NotificationService Notifications { get; }
    public ProcessMonitor ProcessMonitor { get; }
    public ScanScheduler ScanScheduler { get; }
    public SignatureUpdateService SignatureUpdates { get; }

    public event Action? DashboardRefreshRequested;
    public event Action<string>? ActivityEvent;
    public event Action? ShowMainWindowRequested;
    public event Action? ExitRequested;

    private readonly Action _onShowMainWindow;
    private readonly Action _onExit;
    private readonly Action<ThreatInfo> _handleThreat;

    public ApplicationServices(
        AppSettings settings,
        ScannerEngine scanner,
        QuarantineManager quarantine,
        RealTimeGuard realTimeGuard,
        SelfProtectionService selfProtection,
        NotificationService notifications,
        ProcessMonitor processMonitor,
        ScanScheduler scanScheduler,
        SignatureUpdateService signatureUpdates)
    {
        Settings = settings;
        Scanner = scanner;
        Quarantine = quarantine;
        RealTimeGuard = realTimeGuard;
        SelfProtection = selfProtection;
        Notifications = notifications;
        ProcessMonitor = processMonitor;
        ScanScheduler = scanScheduler;
        SignatureUpdates = signatureUpdates;

        _onShowMainWindow = () => ShowMainWindowRequested?.Invoke();
        _onExit = () => ExitRequested?.Invoke();
        _handleThreat = HandleThreat;
    }

    public void Initialize()
    {
        ThemeManager.Apply(Settings.Theme);

        if (Settings.NotificationsEnabled)
            Notifications.Initialize();

        if (Settings.SelfProtectionEnabled)
        {
            SelfProtection.SetNotifier(Notifications);
            SelfProtection.Activate();
        }

        AutoStartService.SyncEnabled(Settings.AutoStart);

        WireNotificationHandlers();
        WireThreatHandlers();
        WireActivityEvents();

        if (Settings.RealTimeEnabled)
            SetRealTimeProtection(true);
        else if (Settings.ProcessMonitorEnabled)
            ProcessMonitor.Start();

        ScanScheduler.Start();
        SignatureUpdates.Start();

        RealTimeGuard.ProtectionStateChanged += () => DashboardRefreshRequested?.Invoke();
        Quarantine.QuarantineChanged += () => DashboardRefreshRequested?.Invoke();
        ScanScheduler.ScheduledScanComplete += count =>
        {
            if (Settings.NotificationsEnabled)
                Notifications.ShowInfo(
                    LocalizationService.AppTitle,
                    LocalizationService.Format("ScheduledScanDone", count));
            DashboardRefreshRequested?.Invoke();
        };
    }

    private void WireNotificationHandlers()
    {
        Notifications.ShowMainWindowRequested -= _onShowMainWindow;
        Notifications.ExitRequested -= _onExit;
        Notifications.ShowMainWindowRequested += _onShowMainWindow;
        Notifications.ExitRequested += _onExit;
    }

    private void UnwireNotificationHandlers()
    {
        Notifications.ShowMainWindowRequested -= _onShowMainWindow;
        Notifications.ExitRequested -= _onExit;
    }

    private void WireActivityEvents()
    {
        RealTimeGuard.FileEvent += path => ActivityEvent?.Invoke(path);
        ProcessMonitor.ProcessEvent += msg => ActivityEvent?.Invoke(msg);
    }

    private void WireThreatHandlers()
    {
        Scanner.OnThreatDetected -= _handleThreat;
        Scanner.OnThreatDetected += _handleThreat;

        ProcessMonitor.ThreatDetected -= OnProcessMonitorThreat;
        ProcessMonitor.ThreatDetected += OnProcessMonitorThreat;
    }

    private void OnProcessMonitorThreat(ThreatInfo threat) => HandleThreat(threat);

    private void HandleThreat(ThreatInfo threat)
    {
        if (Settings.NotificationsEnabled)
            Notifications.ShowThreat(threat);

        if (Settings.AutoQuarantine &&
            ThreatSeverityRules.ShouldAutoQuarantine(threat) &&
            !string.IsNullOrEmpty(threat.FilePath) &&
            File.Exists(threat.FilePath))
        {
            Quarantine.QuarantineFile(threat.FilePath, threat);
        }

        DashboardRefreshRequested?.Invoke();
    }

    public void ApplySettingsChanges()
    {
        ThemeManager.Apply(Settings.Theme);

        UnwireNotificationHandlers();

        if (Settings.NotificationsEnabled)
        {
            Notifications.Dispose();
            Notifications.Initialize();
            WireNotificationHandlers();
        }
        else
        {
            Notifications.Dispose();
        }

        if (Settings.RealTimeEnabled)
        {
            RealTimeGuard.Restart();
            Settings.ProcessMonitorEnabled = true;
            ProcessMonitor.Start();
        }
        else
        {
            RealTimeGuard.Stop();
            if (Settings.ProcessMonitorEnabled)
                ProcessMonitor.Start();
            else
                ProcessMonitor.Stop();
        }

        ScanScheduler.Restart();
        SignatureUpdates.Restart();
        DashboardRefreshRequested?.Invoke();
    }

    public void RequestDashboardRefresh() => DashboardRefreshRequested?.Invoke();

    /// <summary>
    /// Real-time protection = filesystem watcher + process monitor together
    /// so the Protection page always shows live activity when enabled.
    /// </summary>
    public void SetRealTimeProtection(bool enabled)
    {
        if (enabled)
        {
            RealTimeGuard.Start();
            Settings.ProcessMonitorEnabled = true;
            ProcessMonitor.Start();
        }
        else
        {
            RealTimeGuard.Stop();
            ProcessMonitor.Stop();
            Settings.ProcessMonitorEnabled = false;
        }

        Settings.RealTimeEnabled = enabled;
        SettingsService.Save(Settings);
        DashboardRefreshRequested?.Invoke();
    }

    public void Shutdown()
    {
        UnwireNotificationHandlers();
        Scanner.OnThreatDetected -= _handleThreat;
        ProcessMonitor.ThreatDetected -= OnProcessMonitorThreat;

        ProcessMonitor.Stop();
        ScanScheduler.Stop();
        SignatureUpdates.Dispose();
        RealTimeGuard.Shutdown();
        Scanner.Dispose();
        SelfProtection.Dispose();
        Notifications.Dispose();
    }
}
