namespace TurkmenGuard.Core;

/// <summary>
/// Scan-all policy: every file enters the pipeline unless OS-locked (pagefile/hiberfil).
/// Large files use LargeFileScanner slices; nothing is skipped by extension whitelist.
/// </summary>
public static class ScanPolicy
{
    /// <summary>Windows kernel files that cannot be opened for read — only true hard skips.</summary>
    private static readonly HashSet<string> OsLockedFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "hiberfil.sys",
        "pagefile.sys",
        "swapfile.sys",
    };

    public const long MaxYaraFileBytes = 32L * 1024 * 1024;
    public const long MaxHashFileBytes = 128L * 1024 * 1024;
    public const long MaxQuickClamFileBytes = 16L * 1024 * 1024;
    public const long MaxFullClamFileBytes = 16L * 1024 * 1024;
    public const long MaxFullArchiveBytes = 64L * 1024 * 1024;
    public const long MaxFullUnknownFileBytes = 4L * 1024 * 1024;
    public const long MaxTestPayloadBytes = 4096;

    public const long LargeFileThresholdBytes = MaxFullClamFileBytes;
    public const long MaxSingleFileClamBytes = 512L * 1024 * 1024;
    public const long LargeEdgeChunkBytes = 4L * 1024 * 1024;
    public const long LargeEdgeChunkBytesFull = 2L * 1024 * 1024;
    public const long LargeSectionSampleBytes = 512L * 1024;
    public const long LargeOverlayMaxFullBytes = 8L * 1024 * 1024;
    public const long LargeOverlayMaxDeepBytes = 32L * 1024 * 1024;
    public const long LargeInnerEntryMaxBytes = 16L * 1024 * 1024;
    public const int LargeInnerEntryMaxCount = 24;
    public const long LargeMidSampleBytes = 128L * 1024;

    private static readonly HashSet<string> EntropyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys"
    };

    public const int MinEntropyFileSize = 8192;
    public const int MaxEntropySampleBytes = 262144;

    /// <summary>Scan every file except OS-locked kernel blobs.</summary>
    public static bool ShouldScanExtension(string filePath, ScanMode mode = ScanMode.Full)
    {
        var name = Path.GetFileName(filePath);
        if (!string.IsNullOrEmpty(name) && OsLockedFileNames.Contains(name))
            return false;

        return true;
    }

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

    public static bool IsPortableExecutableExtension(string ext) =>
        ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".com", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".ocx", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".cpl", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".drv", StringComparison.OrdinalIgnoreCase) ||
        ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);

    // Legacy compatibility: settings loader expects this method.
    public static IEnumerable<string> GetDefaultExcludedExtensions() => [];
}
