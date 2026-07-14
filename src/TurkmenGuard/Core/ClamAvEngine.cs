using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Full ClamAV integration via bundled clamd + clamdscan (libclamav).
/// Loads main.cvd + daily.cvd + bytecode.cvd — all signature types (.ndb, .ldb, .hdb, .hsb).
/// Falls back to clamscan.exe only for explicit single-file scans when the daemon is down.
/// </summary>
public sealed class ClamAvEngine : IDisposable
{
    private static readonly Regex FoundLine = new(
        @"^(.+?):\s+(.+?)\s+FOUND\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly object _daemonLock = new();
    private Process? _clamdProcess;
    private System.Threading.Timer? _healthTimer;
    private volatile bool _daemonReady;
    private bool _disposed;

    public bool IsAvailable { get; private set; }
    public bool DaemonReady => _daemonReady;
    public string? LastError { get; private set; }
    public string Version { get; private set; } = "";
    public int DatabaseCount { get; private set; }

    public bool Initialize()
    {
        lock (_daemonLock)
        {
            try
            {
                if (!File.Exists(PathHelper.ClamScanExe))
                {
                    LastError = "clamscan.exe not found";
                    return false;
                }

                if (!Directory.Exists(PathHelper.ClamDatabaseDir))
                {
                    LastError = "ClamAV database directory missing";
                    return false;
                }

                DatabaseCount = Directory.GetFiles(PathHelper.ClamDatabaseDir, "*.cvd").Length
                              + Directory.GetFiles(PathHelper.ClamDatabaseDir, "*.cld").Length;
                if (DatabaseCount == 0)
                {
                    LastError = "No .cvd/.cld databases in ClamAV database folder";
                    return false;
                }

                EnsureConfigFiles();
                Version = DetectVersion() ?? "1.5.x";

                if (TryStartDaemon())
                {
                    IsAvailable = true;
                    StartHealthMonitor();
                    Logger.Info($"ClamAV daemon ready (v{Version}, {DatabaseCount} DB files)");
                    return true;
                }

                IsAvailable = true;
                Logger.Warn($"ClamAV daemon unavailable ({LastError}); YARA/hash mode for bulk scans");
                return true;
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Logger.Error($"ClamAV init failed: {ex.Message}");
                return false;
            }
        }
    }

    public List<ThreatInfo> Scan(string filePath, int timeoutMs = 120_000, bool allowClamScanFallback = false)
    {
        var threats = new List<ThreatInfo>();
        if (!IsAvailable || !File.Exists(filePath))
            return threats;

        try
        {
            string? output;
            if (_daemonReady)
            {
                output = RunProcess(PathHelper.ClamdScanExe, BuildClamdScanArgs(filePath), PathHelper.ClamAvDir, timeoutMs);
            }
            else if (allowClamScanFallback)
            {
                output = RunProcess(PathHelper.ClamScanExe, BuildClamScanArgs(filePath), PathHelper.ClamAvDir, timeoutMs);
            }
            else
            {
                return threats;
            }

            if (string.IsNullOrWhiteSpace(output))
                return threats;

            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var m = FoundLine.Match(line.Trim());
                if (!m.Success)
                    continue;

                var threatName = m.Groups[2].Value.Trim();
                threats.Add(new ThreatInfo
                {
                    FilePath = filePath,
                    ThreatName = threatName,
                    Method = DetectionMethod.ClamAV,
                    Severity = MapSeverity(threatName),
                    Details = $"ClamAV: {threatName}"
                });
            }
        }
        catch (Exception ex)
        {
            Logger.Warn($"ClamAV scan [{filePath}]: {ex.Message}");
        }

        return threats;
    }

    private static ThreatSeverity MapSeverity(string name)
    {
        if (name.IndexOf("Eicar", StringComparison.OrdinalIgnoreCase) >= 0 ||
            name.IndexOf("Test", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.Test;

        if (DetectionFilter.IsNoiseSignature(name))
            return ThreatSeverity.Info;

        if (name.StartsWith("PUA.", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("PUP.", StringComparison.OrdinalIgnoreCase))
            return ThreatSeverity.Info;

        if (name.IndexOf("Ransom", StringComparison.OrdinalIgnoreCase) >= 0 ||
            name.IndexOf("Trojan", StringComparison.OrdinalIgnoreCase) >= 0 ||
            name.IndexOf("Malware", StringComparison.OrdinalIgnoreCase) >= 0 ||
            name.IndexOf("Exploit", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.High;

        return ThreatSeverity.High;
    }

    private void StartHealthMonitor()
    {
        _healthTimer?.Dispose();
        _healthTimer = new System.Threading.Timer(_ => HealthCheck(), null,
            TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
    }

    private void HealthCheck()
    {
        if (_disposed || !_daemonReady)
            return;

        lock (_daemonLock)
        {
            if (_disposed || !_daemonReady)
                return;

            if (IsDaemonListening())
                return;

            Logger.Warn("ClamAV daemon health check failed, restarting...");
            _daemonReady = false;
            if (!TryStartDaemon())
                Logger.Warn($"ClamAV daemon restart failed: {LastError}");
        }
    }

    private bool TryStartDaemon()
    {
        if (!File.Exists(PathHelper.ClamdExe))
            return false;

        try
        {
            StopDaemonInternal();

            var psi = new ProcessStartInfo
            {
                FileName = PathHelper.ClamdExe,
                Arguments = $"--config-file=\"{PathHelper.ClamdConf}\"",
                WorkingDirectory = PathHelper.ClamAvDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            _clamdProcess = Process.Start(psi);
            if (_clamdProcess == null)
                return false;

            for (var i = 0; i < 40; i++)
            {
                Thread.Sleep(500);
                if (_clamdProcess.HasExited)
                {
                    LastError = "clamd exited during startup";
                    return false;
                }

                if (IsDaemonListening())
                {
                    _daemonReady = true;
                    return true;
                }
            }

            LastError = "clamd startup timeout";
            StopDaemonInternal();
            return false;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            return false;
        }
    }

    private bool IsDaemonListening()
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var result = client.BeginConnect("127.0.0.1", 3310, null, null);
            var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(300));
            if (!success)
                return false;

            client.EndConnect(result);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            try { client?.Close(); } catch { /* ignore */ }
        }
    }

    private void StopDaemonInternal()
    {
        _daemonReady = false;
        try
        {
            if (_clamdProcess != null && !_clamdProcess.HasExited)
            {
                _clamdProcess.Kill();
                _clamdProcess.WaitForExit(5000);
            }
        }
        catch { }
        finally
        {
            _clamdProcess?.Dispose();
            _clamdProcess = null;
        }
    }

    private static string BuildClamScanArgs(string filePath) =>
        $"--config-file=\"{PathHelper.ClamScanConf}\" --no-summary --stdout \"{filePath}\"";

    private static string BuildClamdScanArgs(string filePath) =>
        $"--config-file=\"{PathHelper.ClamdScanConf}\" --no-summary --stdout \"{filePath}\"";

    private static string? RunProcess(string exe, string args, string workDir, int timeoutMs = 120_000)
    {
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            WorkingDirectory = workDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                stdout.AppendLine(e.Data);
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                stderr.AppendLine(e.Data);
        };

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        try { proc.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { /* ignore */ }

        if (!proc.WaitForExit(timeoutMs))
        {
            try
            {
                proc.Kill();
                proc.WaitForExit(5000);
            }
            catch { /* ignore */ }

            Logger.Warn($"ClamAV scan timed out after {timeoutMs}ms");
            return null;
        }

        proc.WaitForExit(2000);

        if (proc.ExitCode == 2 && stdout.Length == 0)
            Logger.Warn($"ClamAV error: {stderr.ToString().Trim()}");

        return stdout.ToString();
    }

    private static void EnsureConfigFiles()
    {
        Directory.CreateDirectory(PathHelper.ClamAvDir);
        Directory.CreateDirectory(PathHelper.ClamDatabaseDir);
        Directory.CreateDirectory(PathHelper.ClamLogDir);

        var db = PathHelper.ClamDatabaseDir.Replace("\\", "/");
        var logDir = PathHelper.ClamLogDir.Replace("\\", "/");

        WriteIfMissing(PathHelper.ClamdConf, $"""
            DatabaseDirectory {db}
            LogFile {logDir}/clamd.log
            PidFile {logDir}/clamd.pid
            TCPSocket 3310
            TCPAddr 127.0.0.1
            Foreground no
            """);

        WriteIfMissing(PathHelper.ClamdScanConf, """
            TCPSocket 3310
            TCPAddr 127.0.0.1
            """);

        WriteIfMissing(PathHelper.ClamScanConf, $"""
            DatabaseDirectory {db}
            """);

        WriteIfMissing(PathHelper.FreshClamConf, $"""
            DatabaseDirectory {db}
            UpdateLogFile {logDir}/freshclam.log
            DNSDatabaseInfo current.cvd.clamav.net
            DatabaseMirror database.clamav.net
            MaxAttempts 3
            CompressLocalDatabase yes
            """);
    }

    private static void WriteIfMissing(string path, string content)
    {
        if (!File.Exists(path))
            File.WriteAllText(path, content, Encoding.UTF8);
    }

    private string? DetectVersion()
    {
        try
        {
            var output = RunProcess(PathHelper.ClamScanExe, "--version", PathHelper.ClamAvDir, 30_000);
            if (string.IsNullOrWhiteSpace(output))
                return null;
            var line = output.Split('\n')[0].Trim();
            var idx = line.IndexOf('/');
            return idx > 0 ? line.Substring(idx + 1).Trim() : line;
        }
        catch
        {
            return null;
        }
    }

    public void Restart()
    {
        lock (_daemonLock)
        {
            _healthTimer?.Dispose();
            _healthTimer = null;
            StopDaemonInternal();
            IsAvailable = false;
            _daemonReady = false;
            Initialize();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        lock (_daemonLock)
        {
            _healthTimer?.Dispose();
            _healthTimer = null;
            StopDaemonInternal();
            IsAvailable = false;
        }
    }
}
