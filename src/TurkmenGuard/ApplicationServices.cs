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
    public ThreatFeedService ThreatFeed { get; }
    public ThreatActionService ThreatActions { get; }

    public event Action? DashboardRefreshRequested;
    public event Action<string>? ActivityEvent;
    public event Action? ShowMainWindowRequested;
    public event Action? ExitRequested;
    public event Action? ThreatFeedChanged;

    private readonly Action _onShowMainWindow;
    private readonly Action _onExit;
    private readonly Action _onFeedChanged;

    public ApplicationServices(
        AppSettings settings,
        ScannerEngine scanner,
        QuarantineManager quarantine,
        RealTimeGuard realTimeGuard,
        SelfProtectionService selfProtection,
        NotificationService notifications,
        ProcessMonitor processMonitor,
        ScanScheduler scanScheduler,
        SignatureUpdateService signatureUpdates,
        ThreatFeedService threatFeed,
        ThreatActionService threatActions)
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
        ThreatFeed = threatFeed;
        ThreatActions = threatActions;

        _onShowMainWindow = () => ShowMainWindowRequested?.Invoke();
        _onExit = () => ExitRequested?.Invoke();
        _onFeedChanged = () => ThreatFeedChanged?.Invoke();
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

        ThreatFeed.FeedChanged += _onFeedChanged;

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
        Scanner.OnThreatDetected -= OnScannerThreat;
        Scanner.OnThreatDetected += OnScannerThreat;

        RealTimeGuard.ThreatDetected -= OnRealTimeThreat;
        RealTimeGuard.ThreatDetected += OnRealTimeThreat;

        ProcessMonitor.ThreatDetected -= OnProcessMonitorThreat;
        ProcessMonitor.ThreatDetected += OnProcessMonitorThreat;
    }

    private void OnScannerThreat(ThreatInfo threat)
    {
        // Real-time / process paths use dedicated handlers to avoid duplicate feed entries.
        if (!Scanner.IsBulkScanActive)
            return;
        HandleThreat(threat, ThreatSource.Scan);
    }

    private void OnRealTimeThreat(ThreatInfo threat) =>
        HandleThreat(threat, ThreatSource.RealTime);

    private void OnProcessMonitorThreat(ThreatInfo threat) =>
        HandleThreat(threat, ThreatSource.ProcessMonitor);

    public void HandleThreat(ThreatInfo threat, ThreatSource source)
    {
        if (string.IsNullOrWhiteSpace(threat.Source))
            threat.Source = source.ToString();

        var tier = ThreatRiskClassifier.Classify(threat);
        var entry = ThreatFeed.Add(threat, source);

        if (Settings.NotificationsEnabled)
            Notifications.ShowThreat(threat);

        var actions = new List<string>();

        var pid = threat.ProcessId ?? 0;
        var shouldKill = Settings.KillSuspiciousProcesses &&
                         pid > 0 &&
                         tier >= ThreatRiskTier.Dangerous &&
                         !TrustedPaths.IsSelfProtected(threat.FilePath);

        if (shouldKill && ThreatActions.TryKillProcess(pid))
            actions.Add(LocalizationService.Get("ActionKilled"));

        var fromProcess = source == ThreatSource.ProcessMonitor;
        var shouldQuarantine =
            (fromProcess && tier >= ThreatRiskTier.Dangerous) ||
            (Settings.AutoQuarantine && ThreatSeverityRules.ShouldAutoQuarantine(threat));

        if (shouldQuarantine &&
            !string.IsNullOrEmpty(threat.FilePath) &&
            File.Exists(threat.FilePath) &&
            !TrustedPaths.IsSelfProtected(threat.FilePath))
        {
            if (Quarantine.QuarantineFile(threat.FilePath, threat) != null)
                actions.Add(LocalizationService.Get("ActionQuarantined"));
        }

        if (actions.Count > 0)
            ThreatFeed.UpdateAction(entry.Id, string.Join("; ", actions));

        Settings.TotalThreatsFound++;
        SettingsService.Save(Settings);
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
        Scanner.OnThreatDetected -= OnScannerThreat;
        RealTimeGuard.ThreatDetected -= OnRealTimeThreat;
        ProcessMonitor.ThreatDetected -= OnProcessMonitorThreat;
        ThreatFeed.FeedChanged -= _onFeedChanged;

        ProcessMonitor.Stop();
        ScanScheduler.Stop();
        SignatureUpdates.Dispose();
        RealTimeGuard.Shutdown();
        Scanner.Dispose();
        SelfProtection.Dispose();
        Notifications.Dispose();
    }
}
