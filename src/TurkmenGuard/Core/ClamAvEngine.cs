using System.Diagnostics;
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
    // One zINSTREAM per TCP connection. Up to 3 concurrent when clamd is healthy.
    private readonly SemaphoreSlim _tcpGate = new(3, 3);
    private Process? _clamdProcess;
    private Process? _activeScanProcess;
    private System.Threading.Timer? _healthTimer;
    private volatile bool _daemonReady;
    private bool _disposed;
    private int _timeoutStreak;

    public bool IsAvailable { get; private set; }
    public bool DaemonReady => _daemonReady;
    public bool LastScanTimedOut { get; private set; }
    /// <summary>File exceeded maxBytes cap — not scanned (not clean).</summary>
    public bool LastScanSkipped { get; private set; }
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

    public List<ThreatInfo> Scan(string filePath, int timeoutMs = 120_000, bool allowClamScanFallback = false, long maxBytes = 0, bool qualityMode = false)
    {
        var threats = new List<ThreatInfo>();
        LastScanTimedOut = false;
        LastScanSkipped = false;
        if (!IsAvailable || !File.Exists(filePath))
            return threats;

        if (maxBytes <= 0)
            maxBytes = ScanPolicy.MaxFullClamFileBytes;

        // Quick/RealTime: shrink under load so clamd recovers. Full Scan qualityMode waits as long as needed.
        if (!qualityMode)
        {
            var streak = TimeoutStreak;
            if (streak >= 8)
                maxBytes = Math.Min(maxBytes, 2L * 1024 * 1024);
            if (streak >= 20)
                maxBytes = Math.Min(maxBytes, 512L * 1024);
            if (streak >= 8)
                timeoutMs = Math.Min(timeoutMs, 1_500);
        }

        try
        {
            string? output = null;
            if (_daemonReady)
            {
                // INSTREAM streams bytes to clamd — nSCAN hangs on Windows path checks.
                var outcome = ScanViaInstreamFile(filePath, timeoutMs, maxBytes, qualityMode);
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
    public List<ThreatInfo> ScanBytes(byte[] data, string originalPath, int timeoutMs = 5_000, string? regionLabel = null, bool qualityMode = false)
    {
        var threats = new List<ThreatInfo>();
        LastScanTimedOut = false;
        if (!IsAvailable || !_daemonReady || data == null || data.Length == 0)
            return threats;

        if (data.Length > ScanPolicy.MaxFullClamFileBytes)
            return threats;

        if (!qualityMode)
        {
            var streak = TimeoutStreak;
            if (streak >= 8)
                timeoutMs = Math.Min(timeoutMs, 1_500);
        }

        try
        {
            var outcome = ScanViaInstreamBytes(data, timeoutMs, qualityMode);
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
            // IDSESSION replies look like "1: stream: OK" / "1: stream: Trojan.X FOUND"
            var trimmed = StripIdSessionPrefix(line.Trim());
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

    /// <summary>Strip leading "N: " from clamd IDSESSION replies.</summary>
    private static string StripIdSessionPrefix(string line)
    {
        var i = 0;
        while (i < line.Length && char.IsDigit(line[i]))
            i++;
        if (i == 0 || i >= line.Length || line[i] != ':')
            return line;
        i++;
        while (i < line.Length && line[i] == ' ')
            i++;
        return i < line.Length ? line.Substring(i) : line;
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

    private InstreamResult ScanViaInstreamFile(string filePath, int timeoutMs, long maxBytes, bool qualityMode)
    {
        long length;
        try { length = new FileInfo(filePath).Length; }
        catch { return new InstreamResult(null, timedOut: false); }

        if (length <= 0)
            return new InstreamResult(null, timedOut: false);

        if (length > maxBytes)
        {
            LastScanSkipped = true;
            return new InstreamResult(null, timedOut: false);
        }

        timeoutMs = ScaleTimeoutForBytes(timeoutMs, length, qualityMode);
        return WithInstream(timeoutMs, net =>
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 256 * 1024, FileOptions.SequentialScan);
            var buffer = new byte[256 * 1024];
            int read;
            while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                WriteInstreamChunk(net, buffer, read);
        }, qualityMode);
    }

    private InstreamResult ScanViaInstreamBytes(byte[] data, int timeoutMs, bool qualityMode)
    {
        timeoutMs = ScaleTimeoutForBytes(timeoutMs, data.Length, qualityMode);
        return WithInstream(timeoutMs, net =>
        {
            var offset = 0;
            while (offset < data.Length)
            {
                var chunk = Math.Min(256 * 1024, data.Length - offset);
                WriteInstreamChunk(net, data, offset, chunk);
                offset += chunk;
            }
        }, qualityMode);
    }

    /// <summary>
    /// One TCP connection → one zINSTREAM → read reply → close.
    /// Socket pooling / IDSESSION caused timeouts under Full Scan load; localhost connect is cheap.
    /// </summary>
    private InstreamResult WithInstream(int timeoutMs, Action<NetworkStream> writeBody, bool qualityMode)
    {
        var gateWait = qualityMode
            ? Math.Min(Math.Max(timeoutMs * 4, 60_000), 600_000)
            : Math.Min(Math.Max(timeoutMs * 2, 3_000), 12_000);
        if (!_tcpGate.Wait(gateWait))
            return new InstreamResult(null, timedOut: true);

        TcpClient? client = null;
        try
        {
            client = ConnectLocal(timeoutMs, qualityMode);
            if (client == null)
            {
                NoteTimeout("connect", qualityMode);
                return new InstreamResult(null, timedOut: true);
            }

            // Send can block if clamd is busy draining — keep send budget ≥ scan budget
            client.SendTimeout = qualityMode ? Math.Max(timeoutMs * 2, 60_000) : Math.Max(timeoutMs, 10_000);
            client.ReceiveTimeout = timeoutMs;

            var net = client.GetStream();
            WriteZCommand(net, "zINSTREAM");
            writeBody(net);
            WriteChunkLength(net, 0);
            net.Flush();

            var line = ReadClamdLine(net);
            if (string.IsNullOrEmpty(line))
            {
                NoteTimeout("read", qualityMode);
                return new InstreamResult(null, timedOut: true);
            }

            var body = StripIdSessionPrefix(line.Trim());
            if (body.IndexOf("ERROR", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                NoteTimeout("error", qualityMode);
                return new InstreamResult(line, timedOut: true);
            }

            Interlocked.Exchange(ref _timeoutStreak, 0);
            return new InstreamResult(line, timedOut: false);
        }
        catch (IOException)
        {
            NoteTimeout("io", qualityMode);
            return new InstreamResult(null, timedOut: true);
        }
        catch (SocketException)
        {
            NoteTimeout("socket", qualityMode);
            return new InstreamResult(null, timedOut: true);
        }
        finally
        {
            if (client != null)
                DiscardSocket(client);
            _tcpGate.Release();
        }
    }

    /// <summary>ClamAV needs seconds on multi‑MB PE slices; Full quality allows minutes on large payloads.</summary>
    private static int ScaleTimeoutForBytes(int requestedMs, long byteCount, bool qualityMode)
    {
        if (byteCount <= 512 * 1024)
            return requestedMs;

        var maxCap = qualityMode ? 300_000 : 20_000;
        // ~2 ms per KB above 512 KB
        var scaled = 5_000 + (int)((byteCount - 512 * 1024) / 512);
        return Math.Max(requestedMs, Math.Min(scaled, maxCap));
    }

    private static void WriteInstreamChunk(NetworkStream net, byte[] buffer, int length) =>
        WriteInstreamChunk(net, buffer, 0, length);

    private static void WriteInstreamChunk(NetworkStream net, byte[] buffer, int offset, int length)
    {
        WriteChunkLength(net, length);
        net.Write(buffer, offset, length);
    }

    /// <summary>4-byte big-endian unsigned chunk length (ClamAV INSTREAM wire format).</summary>
    private static void WriteChunkLength(NetworkStream net, int length)
    {
        var n = (uint)length;
        net.WriteByte((byte)(n >> 24));
        net.WriteByte((byte)(n >> 16));
        net.WriteByte((byte)(n >> 8));
        net.WriteByte((byte)n);
    }

    private static TcpClient? ConnectLocal(int connectTimeoutMs, bool qualityMode)
    {
        try
        {
            var client = new TcpClient
            {
                NoDelay = true,
                LingerState = new LingerOption(true, 0),
                ReceiveBufferSize = 256 * 1024,
                SendBufferSize = 256 * 1024
            };
            var ar = client.BeginConnect("127.0.0.1", 3310, null, null);
            var wait = qualityMode
                ? Math.Min(Math.Max(connectTimeoutMs, 15_000), 60_000)
                : Math.Min(Math.Max(connectTimeoutMs, 800), 3_000);
            if (!ar.AsyncWaitHandle.WaitOne(wait))
            {
                try { client.Close(); } catch { /* ignore */ }
                client.Dispose();
                return null;
            }

            client.EndConnect(ar);
            return client;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Read one clamd reply ending at LF or NUL (z-protocol).</summary>
    private static string? ReadClamdLine(NetworkStream net)
    {
        var buffer = new byte[1024];
        var len = 0;
        while (len < buffer.Length)
        {
            int b;
            try { b = net.ReadByte(); }
            catch { return null; }

            if (b < 0)
                return len > 0 ? Encoding.ASCII.GetString(buffer, 0, len) : null;
            if (b == 0 || b == '\n')
                break;
            if (b == '\r')
                continue;
            buffer[len++] = (byte)b;
        }

        return len > 0 ? Encoding.ASCII.GetString(buffer, 0, len) : null;
    }

    private static void WriteZCommand(NetworkStream net, string command)
    {
        var cmd = Encoding.ASCII.GetBytes(command);
        net.Write(cmd, 0, cmd.Length);
        net.WriteByte(0);
    }

    private static void DiscardSocket(TcpClient client)
    {
        try { client.Close(); } catch { /* ignore */ }
        try { client.Dispose(); } catch { /* ignore */ }
    }

    private void NoteTimeout(string reason = "timeout", bool qualityMode = false)
    {
        var streak = Interlocked.Increment(ref _timeoutStreak);
        // Less spam: first hit, then every 25
        if (streak == 1 || streak % 25 == 0)
        {
            var suffix = qualityMode
                ? " — queued for ClamAV retry"
                : " — file skipped for ClamAV, scan continues";
            Logger.Warn($"ClamAV INSTREAM slow/{reason} (streak={streak}){suffix}");
        }

        if (!qualityMode && streak == 12)
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
            MaxThreads 4
            MaxQueue 200
            MaxFileSize 256M
            MaxScanSize 512M
            StreamMaxLength 256M
            ReadTimeout 300
            CommandReadTimeout 120
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
