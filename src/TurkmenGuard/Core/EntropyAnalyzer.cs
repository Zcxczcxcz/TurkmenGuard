using System.IO;

namespace TurkmenGuard.Core;

/// <summary>
/// Shannon entropy analysis.
///
/// Design goal (v4.0): minimize false positives on legitimate compressed /
/// packed binaries (UPX, Inno Setup, NSIS, Electron, .NET single-file, Go/Rust)
/// while still catching genuinely crypto-obfuscated payloads.
///
/// Approach:
///  - Threshold raised to <see cref="SuspiciousThreshold"/> (7.95), i.e. the
///    file/section must be ~99.4% of perfectly random.
///  - For PE files, entropy is measured per section (the maximum section wins)
///    rather than over the first 64 KB. This catches a packed .text/.rsrc while
///    ignoring the low-entropy PE headers, and does not fire on ordinary
///    UPX-packed freeware whose overall layout remains well below the threshold.
///  - For non-PE files entropy is not run at all by default (see ScanPolicy).
/// </summary>
public static class EntropyAnalyzer
{
    /// <summary>
    /// Per-section entropy threshold. Max-8.0 (perfectly random); 7.95 leaves a
    /// narrow band that real packers/crypters exceed but ordinary compressed
    /// binaries do not.
    /// </summary>
    public const double SuspiciousThreshold = 7.95;

    private static readonly byte[] PeHeader = [0x4D, 0x5A];

    public static double CalculateEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return 0;

        Span<int> frequencies = stackalloc int[256];
        foreach (var b in data)
            frequencies[b]++;

        double entropy = 0;
        var len = data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (frequencies[i] == 0)
                continue;
            var p = (double)frequencies[i] / len;
            entropy -= p * Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// Reads up to <paramref name="maxBytes"/> from the start of the file and
    /// computes entropy over the exact bytes read (uses ReadExactly to avoid
    /// mis-measurement on short reads).
    /// </summary>
    public static double CalculateFileEntropy(string filePath, int maxBytes = ScanPolicy.MaxEntropySampleBytes)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            var length = (int)Math.Min(fs.Length, maxBytes);
            if (length == 0)
                return 0;
            var buffer = new byte[length];
            ReadExactly(fs, buffer);
            return CalculateEntropy(buffer);
        }
        catch
        {
            return 0;
        }
    }

    public static bool IsPeFile(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            if (fs.Length < 2)
                return false;
            var header = new byte[2];
            ReadExactly(fs, header);
            return header[0] == PeHeader[0] && header[1] == PeHeader[1];
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Runs the entropy heuristic against <paramref name="filePath"/>. Returns a
    /// <see cref="ThreatInfo"/> only when the file's maximum PE-section entropy
    /// (or, for non-PE binaries that still pass the extension gate, the leading
    /// sample) exceeds <see cref="SuspiciousThreshold"/>.
    /// </summary>
    public static ThreatInfo? Analyze(string filePath)
    {
        if (!ScanPolicy.ShouldRunEntropy(filePath))
            return null;

        var entropy = GetMaxSectionEntropy(filePath);
        if (entropy < SuspiciousThreshold)
            return null;

        var isPe = IsPeFile(filePath);
        return new ThreatInfo
        {
            FilePath = filePath,
            ThreatName = isPe ? "Suspicious.HighEntropy.PE" : "Suspicious.HighEntropy",
            Method = DetectionMethod.Entropy,
            Severity = isPe ? ThreatSeverity.Medium : ThreatSeverity.Low,
            Details = $"Shannon entropy: {entropy:F2} (threshold: {SuspiciousThreshold})"
        };
    }

    /// <summary>
    /// For PE files: parses the section table and returns the highest per-section
    /// entropy. For non-PE files that reach this path (rare, via the extension
    /// gate): falls back to entropy over the leading sample. Returns 0 on any
    /// parse/IO failure so the caller never raises a false positive from an
    /// unreadable file.
    /// </summary>
    public static double GetMaxSectionEntropy(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            using var br = new BinaryReader(fs);
            if (fs.Length < 0x40)
                return 0;

            // DOS header: e_lfanew at 0x3C
            fs.Position = 0x3C;
            int peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset + 4 > fs.Length)
                return LeadingSampleEntropy(fs);

            // PE signature "PE\0\0"
            fs.Position = peOffset;
            uint peSig = br.ReadUInt32();
            if (peSig != 0x00004550) // "PE\0\0"
                return LeadingSampleEntropy(fs);

            // COFF header
            ushort numSections = br.ReadUInt16();
            ushort optHeaderSize = br.ReadUInt16();
            if (numSections == 0 || numSections > 96)
                return LeadingSampleEntropy(fs);

            // Section table starts right after the optional header
            long sectionTableOffset = peOffset + 4 + 20 + optHeaderSize;
            if (sectionTableOffset + numSections * 40L > fs.Length)
                return LeadingSampleEntropy(fs);

            double max = 0;
            for (int i = 0; i < numSections; i++)
            {
                fs.Position = sectionTableOffset + i * 40L;
                var nameBuf = new byte[8];
                ReadExactly(fs, nameBuf); // Name (8 bytes)

                // VirtualSize (4), VirtualAddress (4) — skip
                uint sizeOfRawData = br.ReadUInt32();
                uint pointerToRawData = br.ReadUInt32();

                if (sizeOfRawData == 0 || pointerToRawData == 0)
                    continue;
                if (sizeOfRawData > 64 * 1024 * 1024) // sanity cap: 64 MB / section
                    sizeOfRawData = 64 * 1024 * 1024;
                if (pointerToRawData + sizeOfRawData > fs.Length)
                    continue;

                var saved = fs.Position;
                var entropy = SectionEntropy(fs, pointerToRawData, sizeOfRawData);
                fs.Position = saved;
                if (entropy > max)
                    max = entropy;
            }

            return max;
        }
        catch
        {
            return 0;
        }
    }

    private static double SectionEntropy(FileStream fs, uint offset, uint size)
    {
        // Cap per-section sample at 1 MB: enough to converge on the true
        // distribution, cheap to read.
        const int cap = 1 * 1024 * 1024;
        int len = (int)Math.Min(size, cap);
        var buffer = new byte[len];
        fs.Position = offset;
        ReadExactly(fs, buffer);
        return CalculateEntropy(buffer);
    }

    private static double LeadingSampleEntropy(FileStream fs)
    {
        const int sample = 256 * 1024; // 256 KB
        var len = (int)Math.Min(fs.Length, sample);
        var buffer = new byte[len];
        fs.Position = 0;
        ReadExactly(fs, buffer);
        return CalculateEntropy(buffer);
    }

    private static readonly double InvLog2 = 1.0 / Math.Log(2);

    private static double Log2(double value) => Math.Log(value) * InvLog2;

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        int totalRead = 0;
        int bytesToRead = buffer.Length;
        while (totalRead < bytesToRead)
        {
            int read = stream.Read(buffer, totalRead, bytesToRead - totalRead);
            if (read == 0)
                throw new EndOfStreamException();
            totalRead += read;
        }
    }
}
