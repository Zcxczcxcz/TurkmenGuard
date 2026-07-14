using System.Data.SQLite;
using System.Security.Cryptography;
using System.Text.Json;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// SQLite hash signature store (ClamAV .hdb/.hsb imported).
/// Supports MD5, SHA1, SHA256 with optional file-size matching.
/// </summary>
public sealed class HashDatabase : IDisposable
{
    private SQLiteConnection? _connection;
    private readonly object _lock = new();

    public bool IsOpen => _connection != null;
    public int Count { get; private set; }
    public string? DatabasePath { get; private set; }
    public string Version { get; private set; } = "embedded";
    public string Source { get; private set; } = "local";

    public bool Open(string dbPath)
    {
        lock (_lock)
        {
            CloseInternal();
            if (!File.Exists(dbPath))
                return false;

            try
            {
                var builder = new SQLiteConnectionStringBuilder
                {
                    DataSource = dbPath,
                    Version = 3,
                    ReadOnly = true,
                    Pooling = false
                };

                _connection = new SQLiteConnection(builder.ConnectionString);
                _connection.Open();
                DatabasePath = dbPath;
                Count = QueryCount();
                Version = ReadMeta("version") ?? "embedded";
                Source = ReadMeta("source") ?? "local";
                Logger.Info($"Hash DB opened: {Count:N0} signatures [{Source} v{Version}]");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Warn($"Hash DB open failed: {ex.Message}");
                CloseInternal();
                return false;
            }
        }
    }

    /// <summary>
    /// Looks up a hash. When <paramref name="fileSize"/> is known, skips size-specific
    /// signatures that don't match (reduces ClamAV false positives).
    /// </summary>
    public (string Name, ThreatSeverity Severity)? Lookup(string hashHex, string algo, long fileSize = -1)
    {
        if (string.IsNullOrWhiteSpace(hashHex))
            return null;

        lock (_lock)
        {
            var conn = _connection;
            if (conn == null)
                return null;

            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT name, severity, file_size FROM signatures
                    WHERE hash = @h AND algo = @a
                    LIMIT 5;
                    """;
                cmd.Parameters.AddWithValue("@h", hashHex.ToLowerInvariant());
                cmd.Parameters.AddWithValue("@a", algo.ToLowerInvariant());

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var name = reader.GetString(0);
                    var severity = (ThreatSeverity)reader.GetInt32(1);
                    var sigSize = reader.GetInt64(2);

                    if (sigSize >= 0 && fileSize >= 0 && sigSize != fileSize)
                        continue;

                    return (name, severity);
                }
            }
            catch (Exception ex)
            {
                Logger.Warn($"Hash DB lookup failed: {ex.Message}");
            }

            return null;
        }
    }

    public static bool CreateFromJson(string jsonPath, string outputDbPath)
    {
        try
        {
            if (!File.Exists(jsonPath))
                return false;

            var entries = JsonSerializer.Deserialize<List<HashEntry>>(File.ReadAllText(jsonPath));
            if (entries == null || entries.Count == 0)
                return false;

            if (File.Exists(outputDbPath))
                File.Delete(outputDbPath);

            Directory.CreateDirectory(Path.GetDirectoryName(outputDbPath)!);

            using var conn = new SQLiteConnection($"Data Source={outputDbPath};Version=3;");
            conn.Open();
            CreateSchema(conn);

            using var tx = conn.BeginTransaction();
            using var insert = conn.CreateCommand();
            insert.CommandText = """
                INSERT OR IGNORE INTO signatures (hash, algo, name, file_size, severity, source)
                VALUES (@h, @a, @n, -1, @s, 'json');
                """;
            var pH = insert.CreateParameter(); pH.ParameterName = "@h"; insert.Parameters.Add(pH);
            var pA = insert.CreateParameter(); pA.ParameterName = "@a"; insert.Parameters.Add(pA);
            var pN = insert.CreateParameter(); pN.ParameterName = "@n"; insert.Parameters.Add(pN);
            var pS = insert.CreateParameter(); pS.ParameterName = "@s"; insert.Parameters.Add(pS);

            foreach (var e in entries)
            {
                if (string.IsNullOrWhiteSpace(e.Sha256))
                    continue;

                var severity = Enum.TryParse<ThreatSeverity>(e.Severity, ignoreCase: true, out var s)
                    ? s
                    : ThreatSeverity.High;

                pH.Value = e.Sha256.ToLowerInvariant();
                pA.Value = "sha256";
                pN.Value = e.Name ?? "Unknown";
                pS.Value = (int)severity;
                insert.ExecuteNonQuery();
            }

            tx.Commit();

            using (var meta = conn.CreateCommand())
            {
                meta.CommandText = "INSERT INTO meta (key, value) VALUES ('version', @v), ('source', 'json');";
                meta.Parameters.AddWithValue("@v", DateTime.UtcNow.ToString("yyyy.MM.dd"));
                meta.ExecuteNonQuery();
            }

            conn.Close();
            Logger.Info($"Hash DB created from JSON: {entries.Count} entries");
            return true;
        }
        catch (Exception ex)
        {
            Logger.Error($"Hash DB build failed: {ex.Message}");
            return false;
        }
    }

    private static void CreateSchema(SQLiteConnection conn)
    {
        conn.ExecuteNonQuery("""
            CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT NOT NULL,
                algo TEXT NOT NULL,
                name TEXT NOT NULL,
                file_size INTEGER NOT NULL DEFAULT -1,
                severity INTEGER NOT NULL DEFAULT 4,
                source TEXT NOT NULL DEFAULT 'local',
                PRIMARY KEY (hash, algo)
            );
            CREATE INDEX IF NOT EXISTS idx_sig_hash ON signatures(hash);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            """);
    }

    public void Close()
    {
        lock (_lock)
            CloseInternal();
    }

    private void CloseInternal()
    {
        try { _connection?.Close(); } catch { }
        try { _connection?.Dispose(); } catch { }
        _connection = null;
        Count = 0;
    }

    private int QueryCount()
    {
        if (_connection == null)
            return 0;

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM signatures;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private string? ReadMeta(string key)
    {
        if (_connection == null)
            return null;

        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key = @k LIMIT 1;";
        cmd.Parameters.AddWithValue("@k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void Dispose() => Close();

    private sealed class HashEntry
    {
        public string Sha256 { get; set; } = "";
        public string Name { get; set; } = "";
        public string Severity { get; set; } = "High";
    }
}

internal static class SqliteExtensions
{
    public static void ExecuteNonQuery(this SQLiteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
