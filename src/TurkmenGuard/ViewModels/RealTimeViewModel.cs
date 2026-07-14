using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using TurkmenGuard.Services;

namespace TurkmenGuard.ViewModels;

public partial class RealTimeViewModel : ViewModelBase
{
    private readonly ApplicationServices _services;
    private bool _suppressToggle;
    private const int MaxEvents = 50;

    [ObservableProperty] private bool _isEnabled;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _toggleLabel = "";
    [ObservableProperty] private string _eventsLabel = "";
    [ObservableProperty] private string _processMonitorLabel = "";

    public ObservableCollection<string> EventLog { get; } = [];

    public RealTimeViewModel(ApplicationServices services)
    {
        _services = services;
        IsEnabled = _services.RealTimeGuard.IsEnabled;
        RefreshLabels();
        RefreshStatus();

        _services.RealTimeGuard.ProtectionStateChanged += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(SyncFromGuard));
        _services.ActivityEvent += msg =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() => AddEvent(msg)));
        LocalizationService.LanguageChanged += () =>
            System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(RefreshLabels));
    }

    private void RefreshLabels()
    {
        Title = LocalizationService.Get("NavRealTime");
        ToggleLabel = LocalizationService.Get("RealTime");
        EventsLabel = LocalizationService.Get("RecentEvents");
        ProcessMonitorLabel = _services.ProcessMonitor.IsRunning
            ? LocalizationService.Get("ProcessMonitorActive")
            : LocalizationService.Get("ProcessMonitorInactive");
    }

    private void AddEvent(string message)
    {
        EventLog.Insert(0, $"{DateTime.Now:HH:mm:ss}  {message}");
        while (EventLog.Count > MaxEvents)
            EventLog.RemoveAt(EventLog.Count - 1);
    }

    private void SyncFromGuard()
    {
        _suppressToggle = true;
        IsEnabled = _services.RealTimeGuard.IsEnabled;
        _suppressToggle = false;
        RefreshStatus();
        RefreshLabels();
    }

    private void RefreshStatus()
    {
        StatusText = IsEnabled
            ? LocalizationService.Get("ProtectionEnabled")
            : LocalizationService.Get("ProtectionDisabled");
    }

    partial void OnIsEnabledChanged(bool value)
    {
        if (_suppressToggle) return;

        if (value)
            _services.RealTimeGuard.Start();
        else
            _services.RealTimeGuard.Stop();

        RefreshStatus();
    }
}
