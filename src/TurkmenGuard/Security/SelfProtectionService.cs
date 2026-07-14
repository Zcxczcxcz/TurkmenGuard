using System.Diagnostics;

using System.IO;

using System.Windows;

using Microsoft.Win32;

using TurkmenGuard.Services;



namespace TurkmenGuard.Security;



/// <summary>

/// User-mode self-protection: single-instance mutex, protected-path monitoring,

/// integrity checks, and autostart registry watchdog.

/// </summary>

public class SelfProtectionService : IDisposable

{

    private readonly AppSettings _settings;

    private readonly Mutex? _mutex;

    private readonly bool _ownsMutex;

    private readonly List<FileSystemWatcher> _watchers = new();

    private readonly object _watchLock = new();



    private NotificationService? _notifications;

    private System.Threading.Timer? _integrityTimer;

    private System.Threading.Timer? _registryTimer;

    private bool _active;

    private bool _disposed;

    private string? _exePath;

    private Dictionary<string, long> _baselineSizes = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _lastTamperReport = DateTime.MinValue;

    private static readonly TimeSpan TamperReportInterval = TimeSpan.FromSeconds(30);



    public bool IsActive => _active;

    public bool IsSingleInstance => _ownsMutex;



    public SelfProtectionService(AppSettings settings)

    {

        _settings = settings;

        _mutex = new Mutex(true, "TurkmenGuard-SingleInstance-v4", out _ownsMutex);

        if (!_ownsMutex)
        {
            if (System.Windows.Application.Current != null)
            {
                System.Windows.MessageBox.Show(
                    LocalizationService.Get("AlreadyRunning"),
                    LocalizationService.AppTitle,
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                System.Windows.Application.Current.Shutdown();
            }
        }

    }



    public void SetNotifier(NotificationService notifications) =>

        _notifications = notifications;



    public void Activate()

    {

        _active = true;

        try

        {

            _exePath = Process.GetCurrentProcess().MainModule?.FileName;

        }

        catch

        {

            _exePath = null;

        }



        try

        {

            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.Normal;

        }

        catch

        {

            // Non-critical.

        }



        BuildIntegrityBaseline();

        StartPathWatchers();

        StartIntegrityMonitor();

        StartRegistryWatchdog();



        Logger.Info("Self-protection active (mutex + path watch + integrity + registry)");

    }



    public void Deactivate()

    {

        _active = false;

        StopWatchers();

        _integrityTimer?.Dispose();

        _integrityTimer = null;

        _registryTimer?.Dispose();

        _registryTimer = null;



        Logger.Info("Self-protection deactivated");

    }



    public bool CanClose(Window window)

    {

        if (!_active || !_settings.ConfirmOnExit)

            return true;



        var result = System.Windows.MessageBox.Show(

            LocalizationService.Get("ExitConfirm"),

            LocalizationService.AppTitle,

            MessageBoxButton.YesNo,

            MessageBoxImage.Question);

        return result == MessageBoxResult.Yes;

    }



    private void BuildIntegrityBaseline()

    {

        _baselineSizes.Clear();

        foreach (var path in GetProtectedFiles())

        {

            try

            {

                if (File.Exists(path))

                    _baselineSizes[path] = new FileInfo(path).Length;

            }

            catch

            {

                // Skip inaccessible files.

            }

        }

    }



    private IEnumerable<string> GetProtectedFiles()

    {

        if (!string.IsNullOrEmpty(_exePath))

            yield return _exePath;



        var clamScan = PathHelper.ClamScanExe;

        if (File.Exists(clamScan))

            yield return clamScan;



        var settings = PathHelper.SettingsPath;

        if (File.Exists(settings))

            yield return settings;

    }



    private IEnumerable<string> GetProtectedDirectories()

    {

        yield return PathHelper.RulesDir;

        yield return PathHelper.QuarantineDir;

    }



    private void StartPathWatchers()

    {

        StopWatchers();

        lock (_watchLock)

        {

            foreach (var dir in GetProtectedDirectories())

            {

                if (!Directory.Exists(dir))

                    continue;



                try

                {

                    var watcher = new FileSystemWatcher(dir)

                    {

                        IncludeSubdirectories = true,

                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName

                    };



                    watcher.Deleted += OnProtectedPathChanged;

                    watcher.Renamed += OnProtectedPathRenamed;

                    watcher.Created += OnProtectedPathChanged;

                    watcher.Error += (_, e) =>

                        Logger.Warn($"Self-protection watcher error: {e.GetException().Message}");



                    watcher.EnableRaisingEvents = true;

                    _watchers.Add(watcher);

                }

                catch (Exception ex)

                {

                    Logger.Warn($"Self-protection watcher [{dir}]: {ex.Message}");

                }

            }

        }

    }



    private void OnProtectedPathChanged(object sender, FileSystemEventArgs e) =>

        ReportTamper("change", e.FullPath);



    private void OnProtectedPathRenamed(object sender, RenamedEventArgs e) =>

        ReportTamper("rename", $"{e.OldFullPath} -> {e.FullPath}");



    private void ReportTamper(string action, string path)

    {

        if (!_active)

            return;



        var now = DateTime.UtcNow;

        if (now - _lastTamperReport < TamperReportInterval)

            return;



        _lastTamperReport = now;

        Logger.Warn($"Self-protection: {action} on protected path: {path}");

        _notifications?.ShowInfo(

            LocalizationService.Get("TamperDetected"),

            LocalizationService.Format("TamperDetectedDetail", Path.GetFileName(path)));

    }



    private void StartIntegrityMonitor()

    {

        _integrityTimer?.Dispose();

        _integrityTimer = new System.Threading.Timer(_ => CheckIntegrity(), null,

            TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(5));

    }



    private void CheckIntegrity()

    {

        if (!_active)

            return;



        foreach (var entry in _baselineSizes)

        {

            try

            {

                if (!File.Exists(entry.Key))

                {

                    Logger.Warn($"Self-protection: missing protected file: {entry.Key}");

                    _notifications?.ShowInfo(

                        LocalizationService.Get("TamperDetected"),

                        LocalizationService.Format("TamperMissingFile", Path.GetFileName(entry.Key)));

                    continue;

                }



                var size = new FileInfo(entry.Key).Length;

                if (size != entry.Value)

                {

                    Logger.Warn($"Self-protection: size change {entry.Key}: {entry.Value} -> {size}");

                    _notifications?.ShowInfo(

                        LocalizationService.Get("TamperDetected"),

                        LocalizationService.Format("TamperModifiedFile", Path.GetFileName(entry.Key)));

                }

            }

            catch (Exception ex)

            {

                Logger.Warn($"Integrity check failed [{entry.Key}]: {ex.Message}");

            }

        }



        try

        {

            var ruleCount = Directory.Exists(PathHelper.RulesDir)

                ? Directory.GetFiles(PathHelper.RulesDir, "*.yar").Length

                : 0;

            if (ruleCount < 10)

            {

                Logger.Warn($"Self-protection: YARA rules count low ({ruleCount})");

                _notifications?.ShowInfo(

                    LocalizationService.Get("TamperDetected"),

                    LocalizationService.Get("TamperRulesMissing"));

            }

        }

        catch

        {

            // Ignore.

        }

    }



    private void StartRegistryWatchdog()

    {

        _registryTimer?.Dispose();

        _registryTimer = new System.Threading.Timer(_ => CheckRegistry(), null,

            TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(2));

    }



    private void CheckRegistry()

    {

        if (!_active || !_settings.AutoStart)

            return;



        if (!AutoStartService.IsRegistryCorrect())

        {

            Logger.Warn("Self-protection: autostart registry tampered, restoring");

            AutoStartService.SetEnabled(true);

            _notifications?.ShowInfo(

                LocalizationService.Get("TamperDetected"),

                LocalizationService.Get("TamperAutostartRestored"));

        }

    }



    private void StopWatchers()

    {

        lock (_watchLock)

        {

            foreach (var watcher in _watchers)

            {

                try

                {

                    watcher.EnableRaisingEvents = false;

                    watcher.Dispose();

                }

                catch

                {

                    // Ignore.

                }

            }

            _watchers.Clear();

        }

    }



    public void Dispose()

    {

        if (_disposed) return;

        _disposed = true;



        Deactivate();



        try

        {

            if (_ownsMutex)

                _mutex?.ReleaseMutex();

        }

        catch (System.ApplicationException)

        {

            // Mutex not owned by this thread.

        }

        _mutex?.Dispose();

    }

}


