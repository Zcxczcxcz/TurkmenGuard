namespace TurkmenGuard.Services;

public class ExclusionSettings
{
    public List<string> Folders { get; set; } = [];
    public List<string> Extensions { get; set; } = [];
}

public class AppSettings
{
    public string Language { get; set; } = "tk";
    public bool FirstRun { get; set; } = true;
    public bool RealTimeEnabled { get; set; }
    public bool AutoQuarantine { get; set; } = false;
    public bool AutoStart { get; set; }
    public bool SelfProtectionEnabled { get; set; } = true;
    public bool ConfirmOnExit { get; set; } = false;
    public string Theme { get; set; } = "corporate";
    public string ScanSchedule { get; set; } = "never";
    public DateTime? LastScheduledScan { get; set; }
    public bool NotificationsEnabled { get; set; } = true;
    public bool ProcessMonitorEnabled { get; set; } = false;
    public ExclusionSettings Exclusions { get; set; } = new();
    public List<string> MonitoredFolders { get; set; } = [];
    public int TotalFilesScanned { get; set; }
    public int TotalThreatsFound { get; set; }

    public bool SignatureUpdatesEnabled { get; set; } = true;
    public string SignatureUpdateSchedule { get; set; } = "weekly";
    public string SignatureUpdateEndpoint { get; set; } = SignatureUpdateService.DefaultEndpoint;
    public bool CheckUpdatesOnStartup { get; set; } = false;
    public DateTime? LastSignatureUpdate { get; set; }
    public string? LastSignatureVersion { get; set; }

    private static readonly string[] SkipPathFragments =
    [
        "\\node_modules\\",
        "\\.git\\",
        "\\.nuget\\",
        "\\packages\\",
        "\\AppData\\Local\\Programs\\",
        "\\AppData\\Local\\Microsoft\\",
        "\\AppData\\Local\\Temp\\",
        "\\Temp\\",
        "\\Cache\\",
        "\\Cached\\",
        "\\GPUCache\\",
        "\\Code Cache\\",
        "\\Windows\\WinSxS\\",
        "\\Windows\\Installer\\",
        "\\$Recycle.Bin\\",
        "\\System Volume Information\\"
    ];

    private static readonly string[] SkipDirectoryNames =
    [
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
        "Config.Msi"
    ];

    public bool ShouldSkipDirectory(string directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
            return true;

        try
        {
            var name = Path.GetFileName(directoryPath.TrimEnd('\\', '/'));
            if (SkipDirectoryNames.Any(n => name.Equals(n, StringComparison.OrdinalIgnoreCase)))
                return true;

            var full = Path.GetFullPath(directoryPath).TrimEnd('\\') + "\\";

            foreach (var folder in Exclusions.Folders)
            {
                if (string.IsNullOrWhiteSpace(folder))
                    continue;

                var excluded = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
                if (full.StartsWith(excluded, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            foreach (var fragment in SkipPathFragments)
            {
                if (full.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    public bool IsExcluded(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        try
        {
            var full = Path.GetFullPath(filePath);
            var ext = Path.GetExtension(full);

            if (!string.IsNullOrEmpty(ext) &&
                Exclusions.Extensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                return true;

            foreach (var fragment in SkipPathFragments)
            {
                if (full.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return Exclusions.Folders.Any(folder =>
                !string.IsNullOrWhiteSpace(folder) &&
                full.StartsWith(Path.GetFullPath(folder).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }
}
