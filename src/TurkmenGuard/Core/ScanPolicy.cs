namespace TurkmenGuard.Core;

/// <summary>
/// Scan policy — extension-based filtering only. No path-based whitelists
/// (viruses can hide in "trusted" paths like System32), but unknown extensions
/// are skipped by default to avoid wasting effort on inert data files.
/// </summary>
public static class ScanPolicy
{
    /// <summary>
    /// Extensions we actively scan: executables, scripts, archives, Office
    /// docs that can carry macros. This is a closed allow-list.
    /// </summary>
    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Executables / native code
        ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv",
        // Scripts
        ".bat", ".cmd", ".ps1", ".vbs", ".vba", ".js", ".jse", ".wsf", ".wsh", ".hta",
        // Installers / packages
        ".msi", ".msp", ".msu",
        // Java / mobile
        ".jar", ".apk",
        // Office (macro-capable)
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        // Documents that can carry exploits
        ".pdf",
        // Archives
        ".zip", ".rar", ".7z", ".iso", ".img",
        // System shortcuts / registry
        ".lnk", ".reg", ".inf",
    };

    /// <summary>
    /// Extensions for which entropy heuristics run. Deliberately restricted to
    /// native binaries — minified scripts and bundles legitimately have high
    /// entropy, which would cause false positives.
    /// </summary>
    private static readonly HashSet<string> EntropyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys"
    };

    /// <summary>
    /// Extensions we always skip: media, plain text, caches. Even if an attacker
    /// hides code in a .jpg, real-time and YARA scanning of the underlying bytes
    /// is not productive at this layer; the OS loader won't execute a .jpg.
    /// </summary>
    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Images
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff", ".heic",
        // Audio / video
        ".mp3", ".m4a", ".aac", ".flac", ".wav", ".ogg",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
        // Plain text / markup
        ".txt", ".md", ".json", ".xml", ".csv", ".html", ".htm", ".css", ".yaml", ".yml",
        // Temp / cache / system
        ".log", ".tmp", ".bak", ".old", ".cache", ".idx", ".db-wal", ".db-shm",
        ".part", ".crdownload", ".partial",
        // Fonts
        ".ttf", ".otf", ".woff", ".woff2",
    };

    /// <summary>Below this size the entropy signal is too noisy to trust.</summary>
    public const int MinEntropyFileSize = 8192;

    /// <summary>Cap for non-PE entropy sampling (script-like files).</summary>
    public const int MaxEntropySampleBytes = 262144; // 256 KB

    /// <summary>Skipped in Quick/RealTime — archives and passive libs are slow and noisy.</summary>
    private static readonly HashSet<string> QuickRealTimeSkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".iso", ".img",
        ".dll", ".pdf",
        ".doc", ".xls", ".ppt",
    };

    /// <summary>
    /// Decides whether a file should be scanned based on extension. Unknown
    /// extensions are skipped (closed allow-list model) so we never waste a
    /// full hash+YARA pass on inert data.
    /// </summary>
    public static bool ShouldScanExtension(string filePath, ScanMode mode = ScanMode.Full)
    {
        var ext = Path.GetExtension(filePath);
        if (string.IsNullOrEmpty(ext))
        {
            if (mode is ScanMode.Quick or ScanMode.RealTime)
                return false;
            return true;
        }

        if (SkipExtensions.Contains(ext))
            return false;
        if (!ScannableExtensions.Contains(ext))
            return false;

        if (mode is ScanMode.Quick or ScanMode.RealTime && QuickRealTimeSkipExtensions.Contains(ext))
            return false;

        return true;
    }

    public static bool ShouldRunEntropy(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        try
        {
            var info = new FileInfo(filePath);
            if (info.Length < MinEntropyFileSize)
                return false;
        }
        catch
        {
            return false;
        }

        var ext = Path.GetExtension(filePath);
        return EntropyExtensions.Contains(ext);
    }

    public static IEnumerable<string> GetDefaultExcludedExtensions() =>
        [".log", ".tmp", ".bak", ".old", ".cache", ".jpg", ".png", ".mp3", ".mp4"];
}
