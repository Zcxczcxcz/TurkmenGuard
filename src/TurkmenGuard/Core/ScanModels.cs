namespace TurkmenGuard.Core;

public enum DetectionMethod
{
    None,
    ClamAV,
    YARA,
    Hash,
    Entropy,
    Process
}

public enum ScanMode
{
    Quick,
    Full,
    SingleFile,
    RealTime
}

/// <summary>
/// Severity is ordered intentionally: Test is lowest so EICAR / test markers
/// never outrank a real Critical ransomware detection when results are sorted.
/// <c>Info</c> covers low-confidence indicators (e.g. packer markers) that should
/// inform but not alarm the user and must never trigger auto-quarantine.
/// </summary>
public enum ThreatSeverity
{
    Test = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

/// <summary>
/// True if the severity warrants treating the finding as a threat
/// (quarantine, alarm). Info-level findings are advisory only.
/// </summary>
public static class ThreatSeverityRules
{
    /// <summary>Shown in scan results and logs (excludes advisory Info).</summary>
    public static bool ShouldReport(ThreatSeverity s) => s != ThreatSeverity.Info;

    public static bool IsActionable(ThreatSeverity s) => s >= ThreatSeverity.Low;

    /// <summary>Only Malware/Dangerous tiers trigger auto-quarantine.</summary>
    public static bool ShouldAutoQuarantine(ThreatInfo threat) =>
        threat.Severity >= ThreatSeverity.High &&
        ThreatRiskClassifier.Classify(threat) >= ThreatRiskTier.Dangerous;
}

public class ThreatInfo
{
    public string FilePath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public DetectionMethod Method { get; set; }
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
    public string Details { get; set; } = "";
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    /// <summary>When detected from ProcessMonitor — used for kill-before-quarantine.</summary>
    public int? ProcessId { get; set; }
    /// <summary>Human-readable origin: Scan, RealTime, ProcessMonitor, Scheduled.</summary>
    public string Source { get; set; } = "";
}

public class ScanResult
{
    public string FilePath { get; set; } = "";
    public bool IsThreat { get; set; }
    /// <summary>ClamAV did not finish (timeout/io) — file may have been partially checked via YARA/LargeFile.</summary>
    public bool ClamAvIncomplete { get; set; }
    public List<ThreatInfo> Threats { get; set; } = [];
    public double? Entropy { get; set; }
    public string? FileHash { get; set; }
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    public long ScanDurationMs { get; set; }

    public static ScanResult Clean(string path) => new() { FilePath = path, IsThreat = false };
}

public class ScanProgress
{
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public string CurrentFile { get; set; } = "";
    public int TotalFiles { get; set; }
    public bool IsRunning { get; set; }
    /// <summary>Files where ClamAV timed out or failed.</summary>
    public int ClamAvIncompleteCount { get; set; }
    /// <summary>Full Scan: seconds since start (display).</summary>
    public int ElapsedSeconds { get; set; }
    /// <summary>Soft ETA seconds remaining (0 = unknown). Not a hard limit.</summary>
    public int EstimatedRemainingSeconds { get; set; }
    /// <summary>Backward-compatible minutes estimate.</summary>
    public int EstimatedMinutesRemaining =>
        EstimatedRemainingSeconds <= 0 ? 0 : Math.Max(1, (EstimatedRemainingSeconds + 59) / 60);
    public string Phase { get; set; } = "";
}
