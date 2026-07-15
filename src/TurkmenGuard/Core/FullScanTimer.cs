namespace TurkmenGuard.Core;

/// <summary>
/// Full Scan wall-clock (display only — no hard stop). Soft ETA from scan rate.
/// </summary>
public sealed class FullScanTimer
{
    private readonly DateTime _startedUtc = DateTime.UtcNow;

    public int ElapsedSeconds => Math.Max(0, (int)(DateTime.UtcNow - _startedUtc).TotalSeconds);

    /// <summary>Elapsed since Full Scan started (HH:MM:SS when ≥1 h, else MM:SS).</summary>
    public string ElapsedLabel => FormatDuration(ElapsedSeconds);

    /// <summary>Format seconds as MM:SS or H:MM:SS when over an hour.</summary>
    public static string FormatDuration(int totalSeconds)
    {
        totalSeconds = Math.Max(0, totalSeconds);
        if (totalSeconds >= 3600)
            return $"{totalSeconds / 3600}:{(totalSeconds % 3600) / 60:D2}:{totalSeconds % 60:D2}";
        return $"{totalSeconds / 60:D2}:{totalSeconds % 60:D2}";
    }

    /// <summary>
    /// Soft countdown to finish (files/sec). Returns 0 when rate is unknown.
    /// Not a deadline — scan continues past zero.
    /// </summary>
    public int EstimateRemainingSeconds(int filesScanned, int totalFiles)
    {
        if (filesScanned < 32 || totalFiles <= filesScanned)
            return 0;

        var elapsed = Math.Max(1, ElapsedSeconds);
        var rate = (double)filesScanned / elapsed;
        if (rate < 0.05)
            return 0;

        var remainingFiles = totalFiles - filesScanned;
        var seconds = remainingFiles / rate;
        return Math.Max(1, (int)Math.Ceiling(seconds));
    }

    /// <summary>Backward-compatible minutes estimate (rounded up).</summary>
    public int EstimateRemainingMinutes(int filesScanned, int totalFiles)
    {
        var seconds = EstimateRemainingSeconds(filesScanned, totalFiles);
        return seconds <= 0 ? 0 : Math.Max(1, (seconds + 59) / 60);
    }
}
