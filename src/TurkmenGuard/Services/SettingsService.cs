using System.Text.Json;
using TurkmenGuard.Core;

namespace TurkmenGuard.Services;

public static class SettingsService
{
    private static readonly object Lock = new();
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        PathHelper.EnsureDirectories();

        AppSettings settings;
        if (!File.Exists(PathHelper.SettingsPath))
        {
            settings = CreateDefaults();
            Save(settings);
            return settings;
        }

        try
        {
            lock (Lock)
            {
                var json = File.ReadAllText(PathHelper.SettingsPath);
                settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? CreateDefaults();
            }
        }
        catch
        {
            settings = CreateDefaults();
        }

        EnsureDefaultExclusions(settings);
        return settings;
    }

    public static void Save(AppSettings settings)
    {
        try
        {
            lock (Lock)
            {
                PathHelper.EnsureDirectories();
                var json = JsonSerializer.Serialize(settings, JsonOptions);
                File.WriteAllText(PathHelper.SettingsPath, json);
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"Failed to save settings: {ex.Message}");
        }
    }

    public static AppSettings CreateDefaults()
    {
        var settings = new AppSettings
        {
            FirstRun = true,
            RealTimeEnabled = false,
            AutoQuarantine = false,
            AutoStart = false,
            SelfProtectionEnabled = true,
            ProcessMonitorEnabled = false,
            ScanSchedule = "never",
            TotalFilesScanned = 0,
            TotalThreatsFound = 0,
            SignatureUpdatesEnabled = true,
            CheckUpdatesOnStartup = false,
            LastScheduledScan = null,
            LastSignatureUpdate = null,
            LastSignatureVersion = null
        };
        settings.Exclusions.Extensions = ScanPolicy.GetDefaultExcludedExtensions().ToList();
        EnsureDefaultExclusions(settings);
        return settings;
    }

    public static void ResetCounters(AppSettings settings)
    {
        settings.TotalFilesScanned = 0;
        settings.TotalThreatsFound = 0;
        Save(settings);
    }

    private static void EnsureDefaultExclusions(AppSettings settings)
    {
        var folders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var folder in folders)
        {
            if (string.IsNullOrWhiteSpace(folder))
                continue;

            var normalized = folder.TrimEnd('\\');
            if (!settings.Exclusions.Folders.Any(f =>
                    string.Equals(f.TrimEnd('\\'), normalized, StringComparison.OrdinalIgnoreCase)))
            {
                settings.Exclusions.Folders.Add(normalized);
            }
        }
    }
}
