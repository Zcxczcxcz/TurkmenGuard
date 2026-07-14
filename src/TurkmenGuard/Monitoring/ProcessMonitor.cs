using System.Management;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

namespace TurkmenGuard.Monitoring;

/// <summary>
/// Monitors new processes and scans suspicious executables.
/// </summary>
public class ProcessMonitor : IDisposable
{
    private readonly ScannerEngine _scanner;
    private readonly HashSet<int> _knownPids = [];
    private readonly HashSet<string> _blacklist = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd_inject_test.exe",
        "malware_test.exe",
        "keylogger_test.exe",
        "rat_client.exe"
    };
    private System.Threading.Timer? _timer;
    private int _running;
    private int _checking;

    public event Action<string>? ProcessEvent;
    public event Action<ThreatInfo>? ThreatDetected;

    public bool IsRunning => Volatile.Read(ref _running) == 1;

    public ProcessMonitor(ScannerEngine scanner)
    {
        _scanner = scanner;
    }

    public void Start()
    {
        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
            return;

        System.Diagnostics.Process[]? snapshot = null;
        try
        {
            snapshot = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in snapshot)
            {
                try { _knownPids.Add(proc.Id); }
                catch { /* ignore */ }
            }
        }
        finally
        {
            DisposeProcesses(snapshot);
        }

        _timer = new System.Threading.Timer(_ => CheckProcesses(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        Logger.Info("Process monitor started");
    }

    public void Stop()
    {
        if (Interlocked.CompareExchange(ref _running, 0, 1) != 1)
            return;

        _timer?.Dispose();
        _timer = null;
        Logger.Info("Process monitor stopped");
    }

    private void CheckProcesses()
    {
        if (Volatile.Read(ref _running) == 0)
            return;

        if (Interlocked.CompareExchange(ref _checking, 1, 0) != 0)
            return;

        System.Diagnostics.Process[]? processes = null;
        try
        {
            processes = System.Diagnostics.Process.GetProcesses();
            var alivePids = new HashSet<int>();

            foreach (var proc in processes)
            {
                try
                {
                    alivePids.Add(proc.Id);
                    if (_knownPids.Contains(proc.Id))
                        continue;

                    _knownPids.Add(proc.Id);
                    var name = proc.ProcessName;
                    var path = GetProcessPath(proc.Id);

                    if (_blacklist.Contains(name + ".exe"))
                    {
                        var threat = new ThreatInfo
                        {
                            FilePath = path ?? name,
                            ThreatName = $"Blacklisted.Process.{name}",
                            Method = DetectionMethod.Process,
                            Severity = ThreatSeverity.High,
                            Details = $"Blacklisted process: {name}"
                        };
                        Logger.Threat(threat.Details);
                        ThreatDetected?.Invoke(threat);
                        ProcessEvent?.Invoke($"Blacklisted: {name} (PID {proc.Id})");
                        continue;
                    }

                    if (!string.IsNullOrEmpty(path) && File.Exists(path) &&
                        path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !_scanner.IsBulkScanActive)
                    {
                        _ = Task.Run(async () =>
                        {
                            var result = await _scanner.ScanFileAsync(path, ScanMode.RealTime);
                            if (!result.IsThreat) return;

                            foreach (var threat in result.Threats)
                            {
                                ProcessEvent?.Invoke($"Threat in process: {name} - {threat.ThreatName}");
                                ThreatDetected?.Invoke(threat);
                            }
                        });
                    }
                }
                catch
                {
                    // Access denied for system processes.
                }
            }

            _knownPids.RemoveWhere(pid => !alivePids.Contains(pid));
        }
        catch (Exception ex)
        {
            Logger.Warn($"Process monitor error: {ex.Message}");
        }
        finally
        {
            DisposeProcesses(processes);
            Interlocked.Exchange(ref _checking, 0);
        }
    }

    private static void DisposeProcesses(System.Diagnostics.Process[]? processes)
    {
        if (processes == null)
            return;

        foreach (var proc in processes)
        {
            try { proc.Dispose(); }
            catch { /* ignore */ }
        }
    }

    private static string? GetProcessPath(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
            using var collection = searcher.Get();
            foreach (ManagementObject obj in collection)
            {
                try
                {
                    return obj["ExecutablePath"]?.ToString();
                }
                finally
                {
                    obj.Dispose();
                }
            }
        }
        catch
        {
            System.Diagnostics.Process? proc = null;
            try
            {
                proc = System.Diagnostics.Process.GetProcessById(pid);
                return proc.MainModule?.FileName;
            }
            catch { /* ignore */ }
            finally
            {
                proc?.Dispose();
            }
        }

        return null;
    }

    public void Dispose() => Stop();
}
