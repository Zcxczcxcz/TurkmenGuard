namespace TurkmenGuard.Core;

/// <summary>
/// Reduces false positives in automated scans (PUA/PUP/heuristics, entropy, noisy YARA).
/// Quick/RealTime rely on ClamAV; YARA heuristics are restricted on Full scans.
/// </summary>
public static class DetectionFilter
{
    private static readonly string[] NoisePrefixes =
    [
        "PUA.", "PUP.", "PUA-", "PUP-",
        "Heuristics.", "Heuristic.",
        "Win.Tool.", "Win.Trojan.PUA", "Win.PUA", "Win.PUP",
        "Generic.", "Html.Phishing", "Html.Trojan",
        "SecuriteInfo.com.PUA", "SecuriteInfo.com.PUP",
        "Susware.", "Grayware.", "Riskware."
    ];

    private static readonly string[] NoiseSubstrings =
    [
        ".PUA.", ".PUP.", ".Adware.", ".Dialer.", ".Downloader.",
        "Unwanted", "Bundled", "InstallCore", "InstallMonetizer"
    ];

    /// <summary>Broad YARA rules that match legitimate admin/dev scripts.</summary>
    private static readonly string[] HeuristicYaraMarkers =
    [
        "LOLBin_", "PS_Downloader", "Macro_", "Persist_", "WMI_",
        "Batch_", "Lateral_", "Suspicious_", "Downloader_"
    ];

    public static bool IsNoiseSignature(string threatName)
    {
        if (string.IsNullOrWhiteSpace(threatName))
            return true;

        foreach (var prefix in NoisePrefixes)
        {
            if (threatName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var part in NoiseSubstrings)
        {
            if (threatName.IndexOf(part, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        return false;
    }

    public static bool IsHeuristicYaraRule(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
            return false;

        foreach (var marker in HeuristicYaraMarkers)
        {
            if (ruleName.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        return false;
    }

    public static bool IncludeInResults(ThreatInfo threat, ScanMode mode)
    {
        if (threat.Severity == ThreatSeverity.Test)
            return true;

        if (IsNoiseSignature(threat.ThreatName))
            return false;

        if (threat.Method == DetectionMethod.Entropy)
            return false;

        if (threat.Method == DetectionMethod.YARA && IsHeuristicYaraRule(threat.ThreatName))
        {
            if (mode == ScanMode.SingleFile)
                return threat.Severity >= ThreatSeverity.Medium;
            // Full scan: heuristic YARA only at Critical (CredTheft/AMSI/WebShell stay Critical)
            return threat.Severity >= ThreatSeverity.Critical;
        }

        if (mode == ScanMode.SingleFile)
            return threat.Severity >= ThreatSeverity.Medium &&
                   ThreatSeverityRules.ShouldReport(threat.Severity);

        // Quick / Full / RealTime — ClamAV + strong YARA only
        return threat.Severity >= ThreatSeverity.High;
    }

    public static List<ThreatInfo> FilterThreats(IEnumerable<ThreatInfo> threats, ScanMode mode) =>
        threats.Where(t => IncludeInResults(t, mode)).ToList();
}
