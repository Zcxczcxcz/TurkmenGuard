using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using TurkmenGuard.Services;

namespace TurkmenGuard.Core;

/// <summary>
/// Full ClamAV integration via bundled clamd (TCP SCAN) + optional clamscan fallback.
/// Per-file clamdscan.exe is avoided — spawning it for every file made Quick Scan crawl.
/// </summary>
public sealed class ClamAvEngine : IDisposable
{
    private static readonly Regex FoundLine = new(
        @"^(.+?):\s+(.+?)\s+FOUND\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly object _daemonLock = new();
    private readonly object _scanProcessLock = new();
    // One INSTREAM at a time keeps clamd responsive; Quick still pipelines via short timeouts
    private readonly SemaphoreSlim _tcpGate = new(1, 1);
    private Process? _clamdProcess;
    private Process? _activeScanProcess;
    private System.Threading.Timer? _healthTimer;
    private volatile bool _daemonReady;
    private bool _disposed;
    private int _timeoutStreak;

    public bool IsAvailable { get; private set; }
    public bool DaemonReady => _daemonReady;
    public bool LastScanTimedOut { get; private set; }
    /// <summary>Consecutive INSTREAM failures (connect/IO/empty). Reset on success.</summary>
    public int TimeoutStreak => Volatile.Read(ref _timeoutStreak);
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

    public List<ThreatInfo> Scan(string filePath, int timeoutMs = 120_000, bool allowClamScanFallback = false, long maxBytes = 0)
    {
        var threats = new List<ThreatInfo>();
        LastScanTimedOut = false;
        if (!IsAvailable || !File.Exists(filePath))
            return threats;

        if (maxBytes <= 0)
            maxBytes = ScanPolicy.MaxFullClamFileBytes;

        // Under load, shrink work so clamd recovers instead of timing out every file
        var streak = TimeoutStreak;
        if (streak >= 8)
            maxBytes = Math.Min(maxBytes, 2L * 1024 * 1024);
        if (streak >= 20)
            maxBytes = Math.Min(maxBytes, 512L * 1024);
        if (streak >= 8)
            timeoutMs = Math.Min(timeoutMs, 1_500);

        try
        {
            string? output = null;
            if (_daemonReady)
            {
                // INSTREAM streams bytes to clamd — nSCAN hangs on Windows path checks.
                var outcome = ScanViaInstreamFile(filePath, timeoutMs, maxBytes);
                output = outcome.Output;
                LastScanTimedOut = outcome.TimedOut;
            }
            else if (allowClamScanFallback)
            {
                output = RunProcess(PathHelper.ClamScanExe, BuildClamScanArgs(filePath), PathHelper.ClamAvDir, timeoutMs);
            }

            ParseFoundLines(output, filePath, threats, detailPrefix: "ClamAV");
        }
        catch (Exception ex)
        {
            Logger.Warn($"ClamAV scan [{Path.GetFileName(filePath)}]: {ex.Message}");
        }

        return threats;
    }

    /// <summary>
    /// Scan an in-memory slice (large-file PE/overlay/edges) via zINSTREAM.
    /// Threats are attributed to <paramref name="originalPath"/>.
    /// </summary>
    public List<ThreatInfo> ScanBytes(byte[] data, string originalPath, int timeoutMs = 5_000, string? regionLabel = null)
    {
        var threats = new List<ThreatInfo>();
        LastScanTimedOut = false;
        if (!IsAvailable || !_daemonReady || data == null || data.Length == 0)
            return threats;

        if (data.Length > ScanPolicy.MaxFullClamFileBytes)
            return threats;

        var streak = TimeoutStreak;
        if (streak >= 8)
            timeoutMs = Math.Min(timeoutMs, 1_500);

        try
        {
            var outcome = ScanViaInstreamBytes(data, timeoutMs);
            LastScanTimedOut = outcome.TimedOut;
            var prefix = string.IsNullOrEmpty(regionLabel)
                ? "ClamAV/large"
                : $"ClamAV/large:{regionLabel}";
            ParseFoundLines(outcome.Output, originalPath, threats, prefix);
        }
        catch (Exception ex)
        {
            Logger.Warn($"ClamAV ScanBytes [{Path.GetFileName(originalPath)}]: {ex.Message}");
        }

        return threats;
    }

    private void ParseFoundLines(string? output, string filePath, List<ThreatInfo> threats, string detailPrefix)
    {
        if (string.IsNullOrWhiteSpace(output))
            return;

        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.IndexOf("ERROR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.EndsWith(" OK", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("stream: OK", StringComparison.OrdinalIgnoreCase))
                continue;

            var m = FoundLine.Match(trimmed);
            if (!m.Success)
                continue;

            var threatName = m.Groups[2].Value.Trim();
            threats.Add(new ThreatInfo
            {
                FilePath = filePath,
                ThreatName = threatName,
                Method = DetectionMethod.ClamAV,
                Severity = MapSeverity(threatName),
                Details = $"{detailPrefix}: {threatName}"
            });
        }
    }

    private readonly struct InstreamResult
    {
        public readonly string? Output;
        public readonly bool TimedOut;
        public InstreamResult(string? output, bool timedOut)
        {
            Output = output;
            TimedOut = timedOut;
        }
    }

    private InstreamResult ScanViaInstreamFile(string filePath, int timeoutMs, long maxBytes)
    {
        long length;
        try { length = new FileInfo(filePath).Length; }
        catch { return new InstreamResult(null, timedOut: false); }

        if (length <= 0 || length > maxBytes)
            return new InstreamResult("stream: OK", timedOut: false);

        return WithInstreamSession(timeoutMs, net =>
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[128 * 1024];
            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
            {
                var sizeBe = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(read));
                net.Write(sizeBe, 0, 4);
                net.Write(buffer, 0, read);
            }
        });
    }

    private InstreamResult ScanViaInstreamBytes(byte[] data, int timeoutMs) =>
        WithInstreamSession(timeoutMs, net =>
        {
            var offset = 0;
            while (offset < data.Length)
            {
                var chunk = Math.Min(128 * 1024, data.Length - offset);
                var sizeBe = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(chunk));
                net.Write(sizeBe, 0, 4);
                net.Write(data, offset, chunk);
                offset += chunk;
            }
        });

    /// <summary>zINSTREAM session: caller writes data chunks; we send EOF and read the reply.</summary>
    private InstreamResult WithInstreamSession(int timeoutMs, Action<NetworkStream> writeBody)
    {
        var gateWait = Math.Min(Math.Max(timeoutMs, 500), 1_200);
        if (!_tcpGate.Wait(gateWait))
        {
            NoteTimeout();
            return new InstreamResult(null, timedOut: true);
        }

        try
        {
            using var client = new TcpClient { NoDelay = true };
            var ar = client.BeginConnect("127.0.0.1", 3310, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(800))
            {
                try { client.Close(); } catch { /* ignore */ }
                NoteTimeout();
                return new InstreamResult(null, timedOut: true);
            }

            try { client.EndConnect(ar); }
            catch
            {
                NoteTimeout();
                return new InstreamResult(null, timedOut: true);
            }

            client.ReceiveTimeout = timeoutMs;
            client.SendTimeout = Math.Min(timeoutMs, 2_500);

            using var net = client.GetStream();
            var cmd = Encoding.ASCII.GetBytes("zINSTREAM");
            net.Write(cmd, 0, cmd.Length);
            net.WriteByte(0);

            writeBody(net);

            net.Write(BitConverter.GetBytes(0), 0, 4);
            net.Flush();

            using var reader = new StreamReader(net, Encoding.ASCII, false, 4096, leaveOpen: true);
            var line = reader.ReadLine();
            if (string.IsNullOrEmpty(line))
            {
                NoteTimeout();
                return new InstreamResult(null, timedOut: true);
            }

            Interlocked.Exchange(ref _timeoutStreak, 0);
            return new InstreamResult(line, timedOut: false);
        }
        catch (IOException)
        {
            NoteTimeout();
            return new InstreamResult(null, timedOut: true);
        }
        catch (SocketException)
        {
            NoteTimeout();
            return new InstreamResult(null, timedOut: true);
        }
        finally
        {
            _tcpGate.Release();
        }
    }

    private void NoteTimeout()
    {
        var streak = Interlocked.Increment(ref _timeoutStreak);
        if (streak == 1 || streak % 25 == 0)
            Logger.Warn($"ClamAV INSTREAM slow/timeout (streak={streak}) — file skipped for ClamAV, scan continues");

        if (streak == 12)
            Logger.Warn("ClamAV INSTREAM overloaded — shrinking file size/timeout until it recovers");
    }

    public void CancelActiveScan()
    {
        lock (_scanProcessLock)
        {
            try
            {
                var proc = _activeScanProcess;
                if (proc == null || proc.HasExited)
                    return;
                proc.Kill();
                proc.WaitForExit(2000);
            }
            catch (Exception ex)
            {
                Logger.Warn($"ClamAV cancel: {ex.Message}");
            }
            finally
            {
                _activeScanProcess = null;
            }
        }
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

            // CVD load can take 20–60s on first start; wait up to ~90s for TCP 3310.
            for (var i = 0; i < 180; i++)
            {
                Thread.Sleep(500);

                if (IsDaemonListening())
                {
                    _daemonReady = true;
                    Logger.Info($"ClamAV daemon listening after ~{(i + 1) * 0.5:0.0}s");
                    return true;
                }

                if (_clamdProcess.HasExited && i >= 6)
                {
                    LastError = "clamd exited during startup";
                    return false;
                }
            }

            LastError = "clamd startup timeout (databases still loading?)";
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

    private string? RunProcess(string exe, string args, string workDir, int timeoutMs = 120_000)
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
        lock (_scanProcessLock)
            _activeScanProcess = proc;

        try
        {
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
        finally
        {
            lock (_scanProcessLock)
            {
                if (ReferenceEquals(_activeScanProcess, proc))
                    _activeScanProcess = null;
            }
        }
    }

    // ClamAV rejects UTF-8 BOM configs ("Unknown option DatabaseDirectory").
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private static void EnsureConfigFiles()
    {
        Directory.CreateDirectory(PathHelper.ClamAvDir);
        Directory.CreateDirectory(PathHelper.ClamDatabaseDir);
        Directory.CreateDirectory(PathHelper.ClamLogDir);

        var db = PathHelper.ClamDatabaseDir.Replace("\\", "/");
        var logDir = PathHelper.ClamLogDir.Replace("\\", "/");

        // Always rewrite clamd.conf — Foreground yes + no BOM (required for daemon).
        WriteConfig(PathHelper.ClamdConf, $"""
            DatabaseDirectory {db}
            LogFile {logDir}/clamd.log
            PidFile {logDir}/clamd.pid
            TCPSocket 3310
            TCPAddr 127.0.0.1
            Foreground yes
            MaxThreads 3
            MaxQueue 64
            MaxFileSize 10M
            MaxScanSize 20M
            StreamMaxLength 10M
            ReadTimeout 20
            CommandReadTimeout 8
            ConcurrentDatabaseReload no
            """);

        WriteConfigIfMissing(PathHelper.ClamdScanConf, """
            TCPSocket 3310
            TCPAddr 127.0.0.1
            """);

        WriteConfigIfMissing(PathHelper.ClamScanConf, $"""
            DatabaseDirectory {db}
            """);

        WriteConfigIfMissing(PathHelper.FreshClamConf, $"""
            DatabaseDirectory {db}
            UpdateLogFile {logDir}/freshclam.log
            DNSDatabaseInfo current.cvd.clamav.net
            DatabaseMirror database.clamav.net
            MaxAttempts 3
            CompressLocalDatabase yes
            """);
    }

    private static void WriteConfigIfMissing(string path, string content)
    {
        if (!File.Exists(path) || HasUtf8Bom(path))
            WriteConfig(path, content);
    }

    private static void WriteConfig(string path, string content)
    {
        // Trim indent from raw string literals; ClamAV is picky about leading spaces.
        var lines = content.Replace("\r\n", "\n").Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0);
        File.WriteAllText(path, string.Join("\n", lines) + "\n", Utf8NoBom);
    }

    private static bool HasUtf8Bom(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            return fs.Length >= 3 && fs.ReadByte() == 0xEF && fs.ReadByte() == 0xBB && fs.ReadByte() == 0xBF;
        }
        catch
        {
            return false;
        }
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

        try { _tcpGate.Dispose(); } catch { /* ignore */ }
    }
}
