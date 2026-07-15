namespace TurkmenGuard.Services;

using TurkmenGuard.Core;

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
    public DateTime? LastManualScan { get; set; }
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

    /// <summary>
    /// Technical skips only (speed / OS locks) — NOT a software whitelist.
    /// Malware in Program Files, AppData, browsers, IDEs is still scanned.
    /// </summary>
    private static readonly string[] SkipPathFragments =
    [
        "\\$Recycle.Bin\\",
        "\\System Volume Information\\",
        // Hard-link forests — weeks of scan, almost no unique detections
        "\\Windows\\WinSxS\\",
        "\\Windows\\Installer\\",
        "\\Windows\\assembly\\",
        "\\Windows\\Servicing\\",
        "\\Windows\\SoftwareDistribution\\",
        "\\Windows\\Logs\\",
        "\\Windows\\Prefetch\\",
        // Dev trees — huge file counts
        "\\node_modules\\",
        "\\.git\\",
        "\\__pycache__\\",
        "\\.nuget\\",
        // Engine caches (binary blobs, not user programs)
        "\\GPUCache\\",
        "\\Code Cache\\",
        "\\ShaderCache\\",
    ];

    private static readonly string[] SkipDirectoryNames =
    [
        "$Recycle.Bin",
        "System Volume Information",
        "Recovery",
        "Config.Msi",
        "WinSxS",
        "node_modules",
        ".git",
        "__pycache__",
    ];

    private static readonly string[] FullScanSkipFragments =
    [
        "\\Windows\\Fonts\\",
        "\\Windows\\Speech\\",
        "\\Windows\\Help\\",
        "\\Windows\\Panther\\",
        "\\Windows\\CbsTemp\\",
        "\\Windows\\Temp\\",
        "\\Windows\\System32\\DriverStore\\",
        "\\Windows\\System32\\catroot2\\",
        "\\Windows\\System32\\wbem\\Repository\\",
        "\\Windows\\System32\\config\\",
        "\\Windows\\SystemResources\\",
        "\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
        "\\AppData\\Local\\Packages\\",
        "\\AppData\\Local\\D3DSCache\\",
        "\\AppData\\Local\\NVIDIA\\",
        "\\AppData\\Local\\AMD\\",
        "\\Package Cache\\",
        "\\Microsoft\\Edge\\User Data\\Default\\Cache\\",
        "\\Google\\Chrome\\User Data\\Default\\Cache\\",
        "\\Steam\\steamapps\\shadercache\\",
        "\\.vs\\",
        "\\TurkmenGuard.Tests\\bin\\",
    ];

    public bool ShouldSkipDirectory(string directoryPath, ScanMode mode = ScanMode.Full)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
            return true;

        try
        {
            if (TrustedPaths.IsTrusted(directoryPath))
                return true;

            if (TrustedPaths.IsEngineOrLabArtifact(directoryPath))
                return true;

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

            if (mode == ScanMode.Full)
            {
                foreach (var fragment in FullScanSkipFragments)
                {
                    if (full.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        return true;
                }
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
            if (TrustedPaths.IsTrusted(filePath))
                return true;

            if (TrustedPaths.IsEngineOrLabArtifact(filePath))
                return true;

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
