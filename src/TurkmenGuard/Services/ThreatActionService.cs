using System.Diagnostics;

namespace TurkmenGuard.Services;

/// <summary>
/// Terminates suspicious processes and records actions.
/// </summary>
public class ThreatActionService
{
    public bool TryKillProcess(int processId, bool includeChildren = true)
    {
        if (processId <= 0)
            return false;

        var killed = false;
        try
        {
            if (includeChildren)
            {
                foreach (var child in GetChildProcessIds(processId))
                    killed |= KillSingleProcess(child);
            }

            killed |= KillSingleProcess(processId);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Kill process {processId} failed: {ex.Message}");
        }

        return killed;
    }

    private static bool KillSingleProcess(int pid)
    {
        if (pid <= 0)
            return false;

        try
        {
            using var proc = Process.GetProcessById(pid);
            if (proc.HasExited)
                return false;

            var name = proc.ProcessName;
            proc.Kill();
            Logger.Info($"Terminated process: {name} (PID {pid})");
            return true;
        }
        catch (Exception ex)
        {
            Logger.Warn($"Cannot kill PID {pid}: {ex.Message}");
            return false;
        }
    }

    private static IEnumerable<int> GetChildProcessIds(int parentId)
    {
        var children = new List<int>();
        Process[]? processes = null;
        try
        {
            processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                try
                {
                    if (proc.Id != parentId && TryGetParentId(proc, out var ppid) && ppid == parentId)
                        children.Add(proc.Id);
                }
                catch { /* access denied */ }
            }
        }
        finally
        {
            if (processes != null)
            {
                foreach (var p in processes)
                {
                    try { p.Dispose(); } catch { /* ignore */ }
                }
            }
        }

        return children;
    }

    private static bool TryGetParentId(Process proc, out int parentId)
    {
        parentId = 0;
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {proc.Id}");
            using var results = searcher.Get();
            foreach (System.Management.ManagementObject obj in results)
            {
                try
                {
                    parentId = Convert.ToInt32(obj["ParentProcessId"]);
                    return true;
                }
                finally { obj.Dispose(); }
            }
        }
        catch { /* ignore */ }

        return false;
    }
}
