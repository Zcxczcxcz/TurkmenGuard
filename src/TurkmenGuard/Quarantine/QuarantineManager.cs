using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.Quarantine;

public class QuarantineEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string OriginalPath { get; set; } = "";
    public string QuarantinedFileName { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string DetectionMethod { get; set; } = "";
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
    public long OriginalSize { get; set; }
}

/// <summary>
/// Encrypted quarantine storage for detected threats.
/// </summary>
public class QuarantineManager
{
    private readonly object _lock = new();
    private readonly string _quarantineDir;
    private readonly string _indexPath;
    private readonly List<QuarantineEntry> _entries = [];
    private readonly byte[] _key;

    public event Action? QuarantineChanged;

    public IReadOnlyList<QuarantineEntry> Entries
    {
        get { lock (_lock) return _entries.ToList(); }
    }

    public QuarantineManager()
    {
        _quarantineDir = PathHelper.QuarantineDir;
        _indexPath = Path.Combine(_quarantineDir, "index.json");
        _key = LoadOrCreateKey();
        Directory.CreateDirectory(_quarantineDir);
        LoadIndex();
    }

    private static byte[] LoadOrCreateKey()
    {
        const string entropyLabel = "TurkmenGuard-Quarantine-v4";
        var entropy = Encoding.UTF8.GetBytes(entropyLabel);
        var keyPath = Path.Combine(PathHelper.QuarantineDir, ".key");

        try
        {
            Directory.CreateDirectory(PathHelper.QuarantineDir);
            if (File.Exists(keyPath))
            {
                var protectedKey = File.ReadAllBytes(keyPath);
                return ProtectedData.Unprotect(protectedKey, entropy, DataProtectionScope.CurrentUser);
            }

            var key = new byte[32];
            RandomNumberGenerator.Create().GetBytes(key);
            var protectedBytes = ProtectedData.Protect(key, entropy, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(keyPath, protectedBytes);
            return key;
        }
        catch
        {
            var salt = Encoding.UTF8.GetBytes("TurkmenGuard-Quarantine-Salt-2026");
            var machineId = Environment.MachineName + Environment.UserName;
            using var sha = SHA256.Create();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(machineId + Convert.ToBase64String(salt)));
        }
    }

    public QuarantineEntry? QuarantineFile(string filePath, ThreatInfo threat)
    {
        QuarantineEntry? created = null;
        lock (_lock)
        {
            try
            {
                if (!File.Exists(filePath))
                    return null;

                var entry = new QuarantineEntry
                {
                    OriginalPath = filePath,
                    ThreatName = threat.ThreatName,
                    DetectionMethod = threat.Method.ToString(),
                    OriginalSize = new FileInfo(filePath).Length,
                    QuarantinedFileName = $"{Guid.NewGuid():N}.qtn"
                };

                var destPath = Path.Combine(_quarantineDir, entry.QuarantinedFileName);
                EncryptFile(filePath, destPath);

                try
                {
                    File.Delete(filePath);
                }
                catch
                {
                    try { File.Delete(destPath); } catch { /* ignore */ }
                    throw;
                }

                _entries.Add(entry);
                SaveIndex();
                created = entry;
                Logger.Info($"Quarantined: {filePath} -> {entry.ThreatName}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Quarantine failed [{filePath}]: {ex.Message}");
                return null;
            }
        }

        if (created != null)
            QuarantineChanged?.Invoke();

        return created;
    }

    public bool Restore(string entryId)
    {
        var changed = false;
        lock (_lock)
        {
            var entry = _entries.FirstOrDefault(e => e.Id == entryId);
            if (entry == null) return false;

            try
            {
                var src = Path.Combine(_quarantineDir, entry.QuarantinedFileName);
                if (!File.Exists(src)) return false;

                if (File.Exists(entry.OriginalPath))
                    return false;

                var destDir = Path.GetDirectoryName(entry.OriginalPath);
                if (!string.IsNullOrEmpty(destDir))
                    Directory.CreateDirectory(destDir);

                DecryptFile(src, entry.OriginalPath);
                File.Delete(src);
                _entries.Remove(entry);
                SaveIndex();
                changed = true;
                Logger.Info($"Restored: {entry.OriginalPath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Restore failed [{entryId}]: {ex.Message}");
                return false;
            }
        }

        if (changed)
            QuarantineChanged?.Invoke();

        return changed;
    }

    public bool DeletePermanently(string entryId)
    {
        var changed = false;
        lock (_lock)
        {
            var entry = _entries.FirstOrDefault(e => e.Id == entryId);
            if (entry == null) return false;

            try
            {
                var src = Path.Combine(_quarantineDir, entry.QuarantinedFileName);
                if (File.Exists(src))
                    File.Delete(src);

                _entries.Remove(entry);
                SaveIndex();
                changed = true;
                Logger.Info($"Deleted from quarantine: {entry.OriginalPath}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Delete failed [{entryId}]: {ex.Message}");
                return false;
            }
        }

        if (changed)
            QuarantineChanged?.Invoke();

        return changed;
    }

    private void EncryptFile(string source, string dest)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV();

        using var input = File.OpenRead(source);
        using var output = File.Create(dest);
        output.Write(aes.IV, 0, aes.IV.Length);

        using var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
        input.CopyTo(crypto);
    }

    private void DecryptFile(string source, string dest)
    {
        using var input = File.OpenRead(source);
        var iv = new byte[16];
        int bytesRead = input.Read(iv, 0, 16);
        if (bytesRead < 16)
            throw new EndOfStreamException();

        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = iv;

        using var output = File.Create(dest);
        using var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
        crypto.CopyTo(output);
    }

    private void LoadIndex()
    {
        try
        {
            if (!File.Exists(_indexPath)) return;
            var json = File.ReadAllText(_indexPath);
            var entries = JsonSerializer.Deserialize<List<QuarantineEntry>>(json);
            if (entries != null)
                _entries.AddRange(entries);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Failed to load quarantine index: {ex.Message}");
        }
    }

    private void SaveIndex()
    {
        try
        {
            var json = JsonSerializer.Serialize(_entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_indexPath, json);
        }
        catch (Exception ex)
        {
            Logger.Error($"Failed to save quarantine index: {ex.Message}");
        }
    }
}
