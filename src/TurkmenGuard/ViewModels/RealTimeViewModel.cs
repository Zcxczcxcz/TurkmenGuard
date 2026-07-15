using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class RealTimeViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;
    private bool _suppressToggle;
    private readonly DispatcherTimer _uiTimer;
    private const int MaxEvents = 80;

    [ObservableProperty] private bool _isEnabled;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _toggleLabel = "";
    [ObservableProperty] private string _eventsLabel = "";
    [ObservableProperty] private string _processMonitorLabel = "";
    [ObservableProperty] private string _liveStatusLabel = "";
    [ObservableProperty] private string _foldersStat = "";
    [ObservableProperty] private string _filesStat = "";
    [ObservableProperty] private string _processesStat = "";
    [ObservableProperty] private string _threatsStat = "";
    [ObservableProperty] private string _lastActivityText = "";
    [ObservableProperty] private bool _isPulseOn;

    public ObservableCollection<string> EventLog { get; } = [];

    public RealTimeViewModel(ApplicationServices services)
    {
        _services = services;
        IsEnabled = _services.RealTimeGuard.IsEnabled;
        RefreshLabels();
        RefreshStatus();
        RefreshStats();

        _services.RealTimeGuard.ProtectionStateChanged += () =>
            Dispatch(SyncFromGuard);
        _services.RealTimeGuard.StatsChanged += () =>
            Dispatch(RefreshStats);
        _services.ProcessMonitor.StatsChanged += () =>
            Dispatch(RefreshStats);
        _services.ActivityEvent += msg =>
            Dispatch(() => AddEvent(msg));
        LocalizationService.LanguageChanged += () =>
            Dispatch(() =>
            {
                RefreshLabels();
                RefreshStatus();
                RefreshStats();
            });

        _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _uiTimer.Tick += (_, _) =>
        {
            if (!IsEnabled) return;
            IsPulseOn = !IsPulseOn;
            RefreshLastActivity();
        };
        _uiTimer.Start();
    }

    private static void Dispatch(Action action)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher == null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.BeginInvoke(action);
    }

    private void RefreshLabels()
    {
        Title = LocalizationService.Get("NavRealTime");
        ToggleLabel = LocalizationService.Get("RealTime");
        EventsLabel = LocalizationService.Get("LiveActivity");
        ProcessMonitorLabel = _services.ProcessMonitor.IsRunning
            ? LocalizationService.Get("ProcessMonitorActive")
            : LocalizationService.Get("ProcessMonitorInactive");
    }

    private void AddEvent(string message)
    {
        EventLog.Insert(0, $"{DateTime.Now:HH:mm:ss}  {message}");
        while (EventLog.Count > MaxEvents)
            EventLog.RemoveAt(EventLog.Count - 1);
        RefreshLastActivity();
    }

    private void SyncFromGuard()
    {
        _suppressToggle = true;
        IsEnabled = _services.RealTimeGuard.IsEnabled;
        _suppressToggle = false;
        RefreshStatus();
        RefreshLabels();
        RefreshStats();
    }

    private void RefreshStatus()
    {
        StatusText = IsEnabled
            ? LocalizationService.Get("ProtectionEnabled")
            : LocalizationService.Get("ProtectionDisabled");
        LiveStatusLabel = IsEnabled
            ? LocalizationService.Get("ProtectionLive")
            : LocalizationService.Get("ProtectionIdle");
    }

    private void RefreshStats()
    {
        var rt = _services.RealTimeGuard;
        var pm = _services.ProcessMonitor;
        FoldersStat = LocalizationService.Format("RtStatFolders", rt.WatchedFolders);
        FilesStat = LocalizationService.Format("RtStatFiles", rt.FilesChecked);
        ProcessesStat = LocalizationService.Format("RtStatProcesses", pm.ProcessesSeen);
        ThreatsStat = LocalizationService.Format("RtStatThreats", rt.ThreatsBlocked + pm.ThreatsFound);
        ProcessMonitorLabel = pm.IsRunning
            ? LocalizationService.Get("ProcessMonitorActive")
            : LocalizationService.Get("ProcessMonitorInactive");
        RefreshLastActivity();
    }

    private void RefreshLastActivity()
    {
        var last = _services.RealTimeGuard.LastActivityUtc;
        var pmLast = _services.ProcessMonitor.LastActivityUtc;
        if (pmLast > last) last = pmLast;

        if (last == DateTime.MinValue)
        {
            LastActivityText = IsEnabled
                ? LocalizationService.Get("WaitingForActivity")
                : "";
            return;
        }

        var ago = DateTime.UtcNow - last;
        if (ago.TotalSeconds < 5)
            LastActivityText = LocalizationService.Get("ActivityJustNow");
        else if (ago.TotalMinutes < 1)
            LastActivityText = LocalizationService.Format("ActivitySecondsAgo", (int)ago.TotalSeconds);
        else
            LastActivityText = LocalizationService.Format("ActivityMinutesAgo", (int)ago.TotalMinutes);
    }

    partial void OnIsEnabledChanged(bool value)
    {
        if (_suppressToggle) return;

        _services.SetRealTimeProtection(value);
        RefreshStatus();
        RefreshStats();
    }
}
