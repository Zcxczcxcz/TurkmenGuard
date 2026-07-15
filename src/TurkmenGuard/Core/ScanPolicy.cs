namespace TurkmenGuard.Core;

/// <summary>
/// Extension / size policy for what enters the scan pipeline.
/// Quick = focused allow-list (speed). Full = broader coverage with size caps.
/// </summary>
public static class ScanPolicy
{
    private static readonly HashSet<string> SkipFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "hiberfil.sys",
        "pagefile.sys",
        "swapfile.sys",
        "dumpstack.log.tmp",
        "dumpstack.log",
        "LOCK",
        "LOG",
        "CURRENT",
        "LOG.old",
    };

    public const long MaxYaraFileBytes = 16L * 1024 * 1024;
    public const long MaxHashFileBytes = 64L * 1024 * 1024;
    public const long MaxQuickClamFileBytes = 8L * 1024 * 1024;
    /// <summary>Full Scan: keep ClamAV work small so INSTREAM stays under ~1–3s/file.</summary>
    public const long MaxFullClamFileBytes = 8L * 1024 * 1024;
    public const long MaxFullArchiveBytes = 2L * 1024 * 1024;
    public const long MaxFullUnknownFileBytes = 256L * 1024;
    public const long MaxTestPayloadBytes = 4096; // EICAR / small .txt samples

    /// <summary>Above this → LargeFileScanner (PE slices / overlay / edges), not full INSTREAM.</summary>
    public const long LargeFileThresholdBytes = MaxFullClamFileBytes;
    /// <summary>Manual File Scan may still stream this much through ClamAV.</summary>
    public const long MaxSingleFileClamBytes = 256L * 1024 * 1024;
    public const long LargeEdgeChunkBytes = 4L * 1024 * 1024;
    public const long LargeSectionSampleBytes = 256L * 1024;
    public const long LargeOverlayMaxFullBytes = 8L * 1024 * 1024;
    public const long LargeOverlayMaxDeepBytes = 16L * 1024 * 1024;
    public const long LargeInnerEntryMaxBytes = 8L * 1024 * 1024;
    public const int LargeInnerEntryMaxCount = 12;

    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv",
        ".bat", ".cmd", ".ps1", ".vbs", ".vba", ".js", ".jse", ".wsf", ".wsh", ".hta",
        ".msi", ".msp", ".msu",
        ".jar", ".apk",
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".pdf",
        ".zip", ".rar", ".7z", ".iso", ".img",
        ".lnk", ".reg", ".inf",
    };

    private static readonly HashSet<string> EntropyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys"
    };

    /// <summary>Media / caches — never scan (except tiny text payloads handled separately).</summary>
    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff", ".heic",
        ".mp3", ".m4a", ".aac", ".flac", ".wav", ".ogg",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
        ".md", ".json", ".xml", ".csv", ".css", ".yaml", ".yml",
        ".log", ".tmp", ".bak", ".old", ".cache", ".idx", ".db-wal", ".db-shm",
        ".part", ".crdownload", ".partial",
        ".ttf", ".otf", ".woff", ".woff2",
    };

    private static readonly HashSet<string> QuickRealTimeSkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".iso", ".img",
        ".dll", ".pdf",
        ".doc", ".xls", ".ppt",
    };

    public const int MinEntropyFileSize = 8192;
    public const int MaxEntropySampleBytes = 262144;

    public static bool ShouldScanExtension(string filePath, ScanMode mode = ScanMode.Full)
    {
        var name = Path.GetFileName(filePath);
        if (!string.IsNullOrEmpty(name) && SkipFileNames.Contains(name))
            return false;

        if (!string.IsNullOrEmpty(name) &&
            name.StartsWith("MANIFEST-", StringComparison.OrdinalIgnoreCase))
            return false;

        // User picked this file — always enter the pipeline (LargeFileScanner handles size)
        if (mode == ScanMode.SingleFile)
            return true;

        var ext = Path.GetExtension(filePath);

        // Tiny text/html — EICAR and lab samples often use .txt
        if (ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".html", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".htm", StringComparison.OrdinalIgnoreCase))
        {
            var len = TryGetFileLength(filePath);
            return len > 0 && len <= MaxTestPayloadBytes;
        }

        if (string.IsNullOrEmpty(ext))
        {
            // Full only: small extensionless files (not multi‑GB pagefile-style blobs)
            if (mode is ScanMode.Full or ScanMode.SingleFile)
            {
                var len = TryGetFileLength(filePath);
                return len > 0 && len <= MaxFullUnknownFileBytes;
            }
            return false;
        }

        if (SkipExtensions.Contains(ext))
            return false;

        if (ScannableExtensions.Contains(ext))
        {
            if ((mode is ScanMode.Quick or ScanMode.RealTime) &&
                QuickRealTimeSkipExtensions.Contains(ext))
                return false;

            // Archives/ISO unpack slowly in ClamAV — size-cap on Full, skip huge disk images
            if (mode == ScanMode.Full && IsHeavyArchive(ext))
            {
                if (ext.Equals(".iso", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".img", StringComparison.OrdinalIgnoreCase))
                    return false;

                var len = TryGetFileLength(filePath);
                return len > 0 && len <= MaxFullArchiveBytes;
            }

            return true;
        }

        // Full/SingleFile: unknown extensions — tiny only (speed); SingleFile keeps 2 MB
        if (mode is ScanMode.Full or ScanMode.SingleFile)
        {
            var len = TryGetFileLength(filePath);
            var cap = mode == ScanMode.SingleFile ? 2L * 1024 * 1024 : MaxFullUnknownFileBytes;
            return len > 0 && len <= cap;
        }

        return false;
    }

    private static bool IsHeavyArchive(string ext) =>
        ext.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".rar", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".7z", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".iso", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".img", StringComparison.OrdinalIgnoreCase);

    public static bool CanOpenForScan(string filePath)
    {
        try
        {
            using var stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static long TryGetFileLength(string filePath)
    {
        try { return new FileInfo(filePath).Length; }
        catch { return -1; }
    }

    public static bool ShouldRunEntropy(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        try
        {
            if (new FileInfo(filePath).Length < MinEntropyFileSize)
                return false;
        }
        catch
        {
            return false;
        }

        return EntropyExtensions.Contains(Path.GetExtension(filePath));
    }

    public static IEnumerable<string> GetDefaultExcludedExtensions() =>
        [".log", ".tmp", ".bak", ".old", ".cache", ".jpg", ".png", ".mp3", ".mp4"];
}
