using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// User-facing risk groups for scan results (triage, not internal severity enum).
/// </summary>
public enum ThreatRiskTier
{
    /// <summary>Clear malware families (Trojan/Worm/Virus/Ransom/…). Act first.</summary>
    Malware = 4,
    /// <summary>High-confidence threats; quarantine recommended.</summary>
    Dangerous = 3,
    /// <summary>Suspicious / heuristic — review before quarantine.</summary>
    Suspicious = 2,
    /// <summary>Low probability, lab/test, noise — inform only.</summary>
    Low = 1
}

/// <summary>
/// Maps detections into triage groups for the scan results UI.
/// </summary>
public static class ThreatRiskClassifier
{
    public static ThreatRiskTier Classify(ThreatInfo threat)
    {
        if (threat.Severity == ThreatSeverity.Test)
            return ThreatRiskTier.Low;

        if (TrustedPaths.IsEngineOrLabArtifact(threat.FilePath))
            return ThreatRiskTier.Low;

        var name = threat.ThreatName ?? "";

        if (threat.Method == DetectionMethod.ClamAV || threat.Method == DetectionMethod.Hash)
        {
            if (IsMalwareFamilyName(name))
                return ThreatRiskTier.Malware;
            return ThreatRiskTier.Dangerous;
        }

        if (threat.Severity == ThreatSeverity.Critical || IsMalwareFamilyName(name))
            return ThreatRiskTier.Malware;

        if (threat.Severity == ThreatSeverity.High)
            return ThreatRiskTier.Dangerous;

        if (threat.Severity == ThreatSeverity.Medium ||
            DetectionFilter.IsHeuristicYaraRule(name))
            return ThreatRiskTier.Suspicious;

        return ThreatRiskTier.Low;
    }

    public static bool IsMalwareFamilyName(string threatName)
    {
        if (string.IsNullOrWhiteSpace(threatName))
            return false;

        return threatName.IndexOf("Trojan", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Worm", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Virus", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Ransom", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Backdoor", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Rootkit", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Spyware", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Coinminer", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("Stealer", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("RAT_", StringComparison.OrdinalIgnoreCase) >= 0 ||
               threatName.IndexOf("WebShell_", StringComparison.OrdinalIgnoreCase) >= 0;
    }
}
