using System.Security.Cryptography;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Hash checking against embedded ClamAV SQLite database (MD5 + SHA256).
/// </summary>
public class HashChecker
{
    private readonly HashDatabase _database = new();
    private readonly Dictionary<string, (string Name, ThreatSeverity Severity)> _fallback =
        new(StringComparer.OrdinalIgnoreCase);

    public bool IsLoaded => _database.IsOpen || _fallback.Count > 0;
    public int SignatureCount => _database.IsOpen ? _database.Count : _fallback.Count;
    public string DatabaseVersion => _database.IsOpen ? _database.Version : "json-fallback";
    public string DatabaseSource => _database.IsOpen ? _database.Source : "fallback";

    public void LoadFromEmbedded()
    {
        _fallback.Clear();
        _database.Close();
        EnsureLocalDatabase();

        // Prefer embedded production DB (ClamAV) shipped with the app.
        var embedded = PathHelper.EmbeddedHashDatabasePath;
        if (File.Exists(embedded) && _database.Open(embedded))
            return;

        var appDataDb = PathHelper.HashDatabasePath;
        if (File.Exists(appDataDb) && _database.Open(appDataDb))
            return;

        var jsonPath = Path.Combine(PathHelper.DataDir, "hash-signatures.json");
        if (File.Exists(jsonPath) && HashDatabase.CreateFromJson(jsonPath, appDataDb) && _database.Open(appDataDb))
            return;

        LoadDefaultSignatures();
        Logger.Warn("Using built-in fallback hash signatures (no DB found).");
    }

    public void Reload()
    {
        _database.Close();
        LoadFromEmbedded();
    }

    public void CloseDatabase() => _database.Close();

    public void LoadSignatures(IEnumerable<(string Sha256, string Name, ThreatSeverity Severity)> signatures)
    {
        _database.Close();
        _fallback.Clear();
        foreach (var (sha256, name, severity) in signatures)
            _fallback[sha256.ToLowerInvariant()] = (name, severity);
    }

    private static void EnsureLocalDatabase()
    {
        var target = PathHelper.HashDatabasePath;
        if (File.Exists(target))
            return;

        var embedded = PathHelper.EmbeddedHashDatabasePath;
        if (File.Exists(embedded))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(embedded, target);
        }
    }

    private void LoadDefaultSignatures()
    {
        LoadSignatures([
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File", ThreatSeverity.Test),
        ]);
    }

    public static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    public static string ComputeMd5(string filePath)
    {
        using var md5 = MD5.Create();
        using var stream = File.OpenRead(filePath);
        return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    public ThreatInfo? Check(string filePath, string? knownSha256 = null, string? knownMd5 = null)
    {
        try
        {
            if (!File.Exists(filePath))
                return null;

            long fileSize = ScanPolicy.TryGetFileLength(filePath);
            if (fileSize < 0 || fileSize > ScanPolicy.MaxHashFileBytes)
                return null;

            if (!ScanPolicy.CanOpenForScan(filePath))
                return null;

            if (_database.IsOpen)
            {
                var sha256 = knownSha256 ?? ComputeSha256(filePath);
                var hit = _database.Lookup(sha256, "sha256", fileSize);
                if (hit != null)
                    return BuildThreat(filePath, sha256, hit.Value.Name, hit.Value.Severity, "SHA-256");

                var md5 = knownMd5 ?? ComputeMd5(filePath);
                hit = _database.Lookup(md5, "md5", fileSize);
                if (hit != null)
                    return BuildThreat(filePath, md5, hit.Value.Name, hit.Value.Severity, "MD5");
            }

            var hash = knownSha256 ?? ComputeSha256(filePath);
            if (_fallback.TryGetValue(hash, out var sig))
                return BuildThreat(filePath, hash, sig.Name, sig.Severity, "SHA-256");
        }
        catch (IOException)
        {
            // Locked by another process (Steam/Chrome caches) — expected, not an error.
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception ex)
        {
            Logger.Warn($"Hash check failed [{Path.GetFileName(filePath)}]: {ex.Message}");
        }

        return null;
    }

    private static ThreatInfo BuildThreat(string path, string hash, string name, ThreatSeverity severity, string algo) =>
        new()
        {
            FilePath = path,
            ThreatName = name,
            Method = DetectionMethod.Hash,
            Severity = severity,
            Details = $"ClamAV/{algo}: {hash}"
        };
}
