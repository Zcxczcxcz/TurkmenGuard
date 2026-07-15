using System.IO.Compression;
using System.Text;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Structural scan for multi‑MB / multi‑GB files without reading the whole blob.
/// Targets PE headers, section samples, overlay (common dropper append), and file edges.
/// </summary>
public static class LargeFileScanner
{
    private static readonly HashSet<string> InterestingArchiveExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar",
    };

    public readonly struct Region
    {
        public readonly string Label;
        public readonly byte[] Data;

        public Region(string label, byte[] data)
        {
            Label = label;
            Data = data;
        }
    }

    public static bool NeedsLargeScan(long length) =>
        length > ScanPolicy.LargeFileThresholdBytes;

    /// <summary>Extract small regions that usually host malware in large apps/installers.</summary>
    public static List<Region> ExtractRegions(string filePath, ScanMode mode)
    {
        var regions = new List<Region>(12);
        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            var length = fs.Length;
            if (length <= 0)
                return regions;

            if (TryReadPeRegions(fs, length, mode, regions))
                return regions;

            // Non-PE: head + tail (worms/appended payloads often sit at edges)
            AddEdgeRegions(fs, length, regions);
        }
        catch (Exception ex)
        {
            Logger.Warn($"LargeFile extract [{Path.GetFileName(filePath)}]: {ex.Message}");
        }

        return regions;
    }

    /// <summary>
    /// Pull executable-like entries from ZIP / ZIP-in-overlay into scratch files.
    /// Caller must delete returned paths.
    /// </summary>
    public static List<string> ExtractArchiveExecutables(string filePath, ScanMode mode)
    {
        var paths = new List<string>();
        var maxEntries = mode == ScanMode.SingleFile
            ? ScanPolicy.LargeInnerEntryMaxCount
            : mode == ScanMode.RealTime ? 4 : 8;

        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            long zipOffset = 0;
            if (IsPe(fs, out var overlayStart) && overlayStart > 0 && overlayStart < fs.Length)
            {
                fs.Position = overlayStart;
                if (IsZipLocalHeader(fs))
                    zipOffset = overlayStart;
                else
                    zipOffset = -1;
            }
            else
            {
                fs.Position = 0;
                if (!IsZipLocalHeader(fs) && !PathLooksLikeZip(filePath))
                    return paths;
                zipOffset = 0;
            }

            if (zipOffset < 0)
                return paths;

            fs.Position = zipOffset;
            using var zip = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);
            var scratch = EnsureScratchDir();
            var count = 0;

            foreach (var entry in zip.Entries)
            {
                if (count >= maxEntries)
                    break;
                if (entry.Length <= 0 || entry.Length > ScanPolicy.LargeInnerEntryMaxBytes)
                    continue;

                var name = entry.FullName.Replace('/', '\\');
                var ext = Path.GetExtension(name);
                if (!InterestingArchiveExt.Contains(ext))
                    continue;

                var dest = Path.Combine(scratch,
                    $"{Guid.NewGuid():N}_{SanitizeFileName(Path.GetFileName(name))}");
                try
                {
                    using (var src = entry.Open())
                    using (var dst = File.Create(dest))
                    {
                        src.CopyTo(dst);
                    }

                    paths.Add(dest);
                    count++;
                }
                catch
                {
                    TryDelete(dest);
                }
            }
        }
        catch (InvalidDataException)
        {
            // Not a zip / truncated SFX — ignore
        }
        catch (Exception ex)
        {
            Logger.Warn($"LargeFile archive [{Path.GetFileName(filePath)}]: {ex.Message}");
        }

        return paths;
    }

    public static void CleanupScratch()
    {
        try
        {
            var dir = Path.Combine(PathHelper.AppDataDir, "scratch");
            if (!Directory.Exists(dir))
                return;

            foreach (var f in Directory.EnumerateFiles(dir))
            {
                try
                {
                    var age = DateTime.UtcNow - File.GetCreationTimeUtc(f);
                    if (age.TotalHours > 2)
                        File.Delete(f);
                }
                catch { /* ignore */ }
            }
        }
        catch { /* ignore */ }
    }

    private static bool TryReadPeRegions(FileStream fs, long length, ScanMode mode, List<Region> regions)
    {
        if (!IsPe(fs, out var overlayStart))
            return false;

        fs.Position = 0;
        var headerLen = (int)Math.Min(4096, length);
        regions.Add(new Region("pe-header", ReadAt(fs, 0, headerLen)));

        // Optional: sample each section (raw data head)
        try
        {
            fs.Position = 0x3C;
            var eLfanewBuf = new byte[4];
            if (fs.Read(eLfanewBuf, 0, 4) != 4)
                return true;

            var eLfanew = BitConverter.ToInt32(eLfanewBuf, 0);
            if (eLfanew <= 0 || eLfanew > length - 0x18)
                return true;

            fs.Position = eLfanew + 4; // skip PE\0\0
            var coff = new byte[20];
            if (fs.Read(coff, 0, 20) != 20)
                return true;

            var numSections = BitConverter.ToUInt16(coff, 2);
            var optHeaderSize = BitConverter.ToUInt16(coff, 16);
            if (numSections == 0 || numSections > 96)
                return true;

            var sectionTable = eLfanew + 24 + optHeaderSize;
            var sample = (int)ScanPolicy.LargeSectionSampleBytes;
            var maxSections = mode == ScanMode.SingleFile ? 8 : 4;

            for (var i = 0; i < numSections && i < maxSections; i++)
            {
                fs.Position = sectionTable + i * 40;
                var sec = new byte[40];
                if (fs.Read(sec, 0, 40) != 40)
                    break;

                var name = Encoding.ASCII.GetString(sec, 0, 8).TrimEnd('\0');
                var rawSize = BitConverter.ToUInt32(sec, 16);
                var rawPtr = BitConverter.ToUInt32(sec, 20);
                if (rawSize == 0 || rawPtr == 0 || rawPtr >= length)
                    continue;

                var take = (int)Math.Min(sample, Math.Min(rawSize, (uint)(length - rawPtr)));
                if (take < 64)
                    continue;

                regions.Add(new Region($"section-{SanitizeLabel(name)}", ReadAt(fs, rawPtr, take)));
            }
        }
        catch
        {
            // Header-only is still useful
        }

        var overlayMax = mode == ScanMode.SingleFile
            ? ScanPolicy.LargeOverlayMaxDeepBytes
            : ScanPolicy.LargeOverlayMaxFullBytes;

        if (overlayStart > 0 && overlayStart < length)
        {
            var overlayLen = length - overlayStart;
            if (overlayLen <= overlayMax)
            {
                regions.Add(new Region("overlay", ReadAt(fs, overlayStart, (int)overlayLen)));
            }
            else
            {
                // Head + tail of overlay (appended archives / droppers)
                var edge = (int)Math.Min(ScanPolicy.LargeEdgeChunkBytes, overlayLen / 2);
                regions.Add(new Region("overlay-head", ReadAt(fs, overlayStart, edge)));
                regions.Add(new Region("overlay-tail",
                    ReadAt(fs, length - edge, edge)));
            }
        }
        else if (length > ScanPolicy.LargeFileThresholdBytes)
        {
            // PE without overlay still gets edges (packed installers)
            AddEdgeRegions(fs, length, regions);
        }

        return true;
    }

    private static void AddEdgeRegions(FileStream fs, long length, List<Region> regions)
    {
        var chunk = (int)Math.Min(ScanPolicy.LargeEdgeChunkBytes, length);
        regions.Add(new Region("head", ReadAt(fs, 0, chunk)));
        if (length > chunk)
            regions.Add(new Region("tail", ReadAt(fs, length - chunk, chunk)));
    }

    private static bool IsPe(FileStream fs, out long overlayStart)
    {
        overlayStart = 0;
        if (fs.Length < 0x40)
            return false;

        fs.Position = 0;
        if (fs.ReadByte() != 'M' || fs.ReadByte() != 'Z')
            return false;

        fs.Position = 0x3C;
        var buf = new byte[4];
        if (fs.Read(buf, 0, 4) != 4)
            return false;

        var eLfanew = BitConverter.ToInt32(buf, 0);
        if (eLfanew < 0x40 || eLfanew > fs.Length - 4)
            return false;

        fs.Position = eLfanew;
        if (fs.Read(buf, 0, 4) != 4)
            return false;
        if (buf[0] != 'P' || buf[1] != 'E' || buf[2] != 0 || buf[3] != 0)
            return false;

        // COFF + optional header → section table → max end of raw sections
        fs.Position = eLfanew + 4;
        var coff = new byte[20];
        if (fs.Read(coff, 0, 20) != 20)
            return true;

        var numSections = BitConverter.ToUInt16(coff, 2);
        var optHeaderSize = BitConverter.ToUInt16(coff, 16);
        var sectionTable = eLfanew + 24 + optHeaderSize;
        long maxEnd = sectionTable + numSections * 40L;

        for (var i = 0; i < numSections && i < 96; i++)
        {
            fs.Position = sectionTable + i * 40;
            var sec = new byte[40];
            if (fs.Read(sec, 0, 40) != 40)
                break;

            var rawSize = BitConverter.ToUInt32(sec, 16);
            var rawPtr = BitConverter.ToUInt32(sec, 20);
            if (rawPtr == 0)
                continue;

            var end = (long)rawPtr + rawSize;
            if (end > maxEnd)
                maxEnd = end;
        }

        if (maxEnd > 0 && maxEnd < fs.Length)
            overlayStart = maxEnd;

        return true;
    }

    private static bool IsZipLocalHeader(Stream s)
    {
        var b = new byte[4];
        var pos = s.Position;
        var n = s.Read(b, 0, 4);
        s.Position = pos;
        return n == 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4;
    }

    private static bool PathLooksLikeZip(string path)
    {
        var ext = Path.GetExtension(path);
        return ext.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".jar", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".apk", StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] ReadAt(FileStream fs, long offset, int count)
    {
        var data = new byte[count];
        fs.Position = offset;
        var read = 0;
        while (read < count)
        {
            var n = fs.Read(data, read, count - read);
            if (n <= 0)
                break;
            read += n;
        }

        if (read == count)
            return data;

        if (read <= 0)
            return Array.Empty<byte>();

        var trimmed = new byte[read];
        Buffer.BlockCopy(data, 0, trimmed, 0, read);
        return trimmed;
    }

    private static string EnsureScratchDir()
    {
        var dir = Path.Combine(PathHelper.AppDataDir, "scratch");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string SanitizeFileName(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Length > 64 ? name.Substring(0, 64) : name;
    }

    private static string SanitizeLabel(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');
        return sb.Length == 0 ? "sec" : sb.ToString();
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* ignore */ }
    }
}
