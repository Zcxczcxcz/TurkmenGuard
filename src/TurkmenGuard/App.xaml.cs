using System.Windows;
using TurkmenGuard.Core;
using TurkmenGuard.Monitoring;
using TurkmenGuard.Quarantine;
using TurkmenGuard.Security;
using TurkmenGuard.Services;
using TurkmenGuard.Views;

namespace TurkmenGuard;

public partial class App : Application
{
    private ApplicationServices? _services;

    private void OnStartup(object sender, StartupEventArgs e)
    {
        PathHelper.EnsureDirectories();
        var settings = SettingsService.Load();

        if (settings.FirstRun)
        {
            var langWindow = new FirstRunLanguageWindow(settings);
            langWindow.ShowDialog();
        }

        LocalizationService.CurrentLanguage = settings.Language;
        Logger.Info($"TurkmenGuard v{PathHelper.GetVersion()} WPF starting...");

        var selfProtection = new SelfProtectionService(settings);
        if (!selfProtection.IsSingleInstance)
            return;

        var scanner = new ScannerEngine(settings);
        var quarantine = new QuarantineManager();
        var realTimeGuard = new RealTimeGuard(scanner, settings, quarantine);
        var notifications = new NotificationService();
        var processMonitor = new ProcessMonitor(scanner);
        var scanScheduler = new ScanScheduler(settings, scanner);
        var signatureUpdates = new SignatureUpdateService(settings, scanner);

        _services = new ApplicationServices(
            settings, scanner, quarantine, realTimeGuard, selfProtection,
            notifications, processMonitor, scanScheduler, signatureUpdates);

        _services.Initialize();

        var startInTray = e.Args.Any(a =>
            a.Equals(AutoStartService.TrayArgument, StringComparison.OrdinalIgnoreCase));

        var mainWindow = new MainWindow(_services);
        if (startInTray)
        {
            mainWindow.Hide();
            if (settings.NotificationsEnabled)
                notifications.ShowInfo(
                    LocalizationService.AppTitle,
                    LocalizationService.Get("TrayStartupNotice"));
        }
        else
        {
            mainWindow.Show();
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _services?.Shutdown();
        base.OnExit(e);
    }
}
