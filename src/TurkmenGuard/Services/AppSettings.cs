namespace TurkmenGuard.Services;

using TurkmenGuard.Core;

public class ExclusionSettings
{
    [Obsolete("User exclusions removed — all paths are scanned.")]
    public List<string> Folders { get; set; } = [];
    [Obsolete("User exclusions removed — all paths are scanned.")]
    public List<string> Extensions { get; set; } = [];
}

public class AppSettings
{
    public string Language { get; set; } = "tk";
    public bool FirstRun { get; set; } = true;
    public bool RealTimeEnabled { get; set; }
    public bool AutoQuarantine { get; set; } = false;
    /// <summary>Terminate Dangerous/Malware processes detected by ProcessMonitor.</summary>
    public bool KillSuspiciousProcesses { get; set; } = true;
    public bool AutoStart { get; set; }
    public bool SelfProtectionEnabled { get; set; } = true;
    public bool ConfirmOnExit { get; set; } = false;
    public string Theme { get; set; } = "corporate";
    public string ScanSchedule { get; set; } = "never";
    public DateTime? LastScheduledScan { get; set; }
    public DateTime? LastManualScan { get; set; }
    public bool NotificationsEnabled { get; set; } = true;
    public bool ProcessMonitorEnabled { get; set; } = false;
    [Obsolete("Legacy — ignored; all folders are scanned.")]
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

    /// <summary>No directory skips — enumerate everything; access errors handled per-file.</summary>
    public bool ShouldSkipDirectory(string directoryPath, ScanMode mode = ScanMode.Full) => false;

    /// <summary>No file-path exclusions — every file is scanned unless OS-locked at open time.</summary>
    public bool IsExcluded(string filePath) => false;
}
