using System.Text;

namespace TurkmenGuard.Services;

public static class Logger
{
    private static readonly object Lock = new();
    private static StreamWriter? _writer;
    private static string? _writerDate;
    private static bool _dirsEnsured;
    private const long MaxLogSizeBytes = 10 * 1024 * 1024;
    private const int RetentionDays = 14;

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);
    public static void Threat(string message) => Write("THREAT", message);

    public static string ReadRecentLogs(int maxLines = 200)
    {
        lock (Lock)
        {
            try
            {
                FlushWriter();
                var logFile = GetTodayLogPath();
                if (!File.Exists(logFile))
                    return "";

                var lines = File.ReadAllLines(logFile);
                return string.Join(Environment.NewLine, lines.Skip(Math.Max(0, lines.Length - maxLines)));
            }
            catch
            {
                return "";
            }
        }
    }

    public static string GetTodayLogPath() =>
        Path.Combine(PathHelper.LogsDir, $"turkmenguard_{DateTime.Now:yyyy-MM-dd}.log");

    private static void EnsureReady()
    {
        if (_dirsEnsured)
            return;

        PathHelper.EnsureDirectories();
        _dirsEnsured = true;
        PurgeOldLogs();
    }

    private static void PurgeOldLogs()
    {
        try
        {
            if (!Directory.Exists(PathHelper.LogsDir))
                return;

            var cutoff = DateTime.Now.AddDays(-RetentionDays);
            foreach (var file in Directory.GetFiles(PathHelper.LogsDir, "turkmenguard_*.log"))
            {
                try
                {
                    if (File.GetLastWriteTime(file) < cutoff)
                        File.Delete(file);
                }
                catch { /* ignore */ }
            }
        }
        catch { /* ignore */ }
    }

    private static StreamWriter GetWriter()
    {
        var today = DateTime.Now.ToString("yyyy-MM-dd");
        var path = GetTodayLogPath();

        if (_writer != null && _writerDate == today && File.Exists(path))
        {
            var size = new FileInfo(path).Length;
            if (size <= MaxLogSizeBytes)
                return _writer;

            FlushWriter();
            var rotated = path.Replace(".log", $"_{DateTime.Now:HHmmss}.log");
            try { File.Move(path, rotated); } catch { /* ignore */ }
        }

        FlushWriter();
        _writer = new StreamWriter(path, append: true, Encoding.UTF8) { AutoFlush = true };
        _writerDate = today;
        return _writer;
    }

    private static void FlushWriter()
    {
        try
        {
            _writer?.Flush();
            _writer?.Dispose();
        }
        catch { /* ignore */ }
        finally
        {
            _writer = null;
            _writerDate = null;
        }
    }

    private static void Write(string level, string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
        lock (Lock)
        {
            try
            {
                EnsureReady();
                GetWriter().WriteLine(line);
            }
            catch { /* ignore */ }
        }
    }
}
