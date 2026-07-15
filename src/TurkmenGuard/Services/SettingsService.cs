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

        // v4.7+: no longer hide Windows / Program Files from Full Scan
        if (StripLegacyOsWhitelists(settings))
            Save(settings);

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
        // Only skip inert media by default — user may add folder exclusions manually
        settings.Exclusions.Extensions = ScanPolicy.GetDefaultExcludedExtensions().ToList();
        return settings;
    }

    public static void ResetCounters(AppSettings settings)
    {
        settings.TotalFilesScanned = 0;
        settings.TotalThreatsFound = 0;
        Save(settings);
    }

    /// <summary>
    /// Older builds auto-added Windows + Program Files as exclusions.
    /// Remove those exact defaults so Full Scan covers the whole system.
    /// Manual user exclusions for other paths are kept.
    /// </summary>
    private static bool StripLegacyOsWhitelists(AppSettings settings)
    {
        var legacy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 })
        {
            if (!string.IsNullOrWhiteSpace(folder))
                legacy.Add(folder.TrimEnd('\\'));
        }

        var before = settings.Exclusions.Folders.Count;
        settings.Exclusions.Folders = settings.Exclusions.Folders
            .Where(f => !string.IsNullOrWhiteSpace(f) && !legacy.Contains(f.TrimEnd('\\')))
            .ToList();

        if (settings.Exclusions.Folders.Count != before)
        {
            Logger.Info("Removed legacy OS folder exclusions (Windows/Program Files) — Full Scan covers system");
            return true;
        }

        return false;
    }
}
