using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using libyaraNET;
using TurkmenGuard.Services;
using YaraScanResult = libyaraNET.ScanResult;

namespace TurkmenGuard.Core;

/// <summary>
/// YARA scanner wrapper for libyara.NET (.NET Framework 4.8 / Windows 7+).
/// </summary>
public sealed class YaraScanner : IDisposable
{
    private readonly object _scanLock = new();
    private readonly YaraContext _context = new();

    private Rules? _rules;
    private bool _initialized;
    private bool _disposed;
    private int _filesLoaded;

    public bool IsAvailable => _initialized && _rules != null;
    public string? LastError { get; private set; }
    public int RulesLoaded => _filesLoaded;
    public int CompiledRuleCount { get; private set; }

    public bool Initialize(string rulesDirectory)
    {
        try
        {
            DisposeRules();

            if (!Directory.Exists(rulesDirectory))
            {
                LastError = $"Rules directory not found: {rulesDirectory}";
                return false;
            }

            var yarFiles = Directory.GetFiles(rulesDirectory, "*.yar", SearchOption.TopDirectoryOnly)
                .Where(f => Path.GetFileName(f).IndexOf(".disabled", StringComparison.OrdinalIgnoreCase) < 0)
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (yarFiles.Length == 0)
            {
                LastError = "No .yar rule files found";
                return false;
            }

            var compiler = new Compiler();
            var filesLoaded = 0;

            foreach (var file in yarFiles)
            {
                try
                {
                    compiler.AddRuleFile(file);
                    filesLoaded++;
                    Logger.Info("Loaded YARA rule file: " + Path.GetFileName(file));
                }
                catch (Exception ex)
                {
                    Logger.Warn("Rule load failed [" + Path.GetFileName(file) + "]: " + ex.Message);
                }
            }

            if (filesLoaded == 0)
            {
                LastError = "No YARA rules compiled";
                return false;
            }

            _rules = compiler.GetRules();
            _filesLoaded = filesLoaded;
            CompiledRuleCount = _rules?.GetRules()?.Count() ?? 0;
            _initialized = _rules != null;
            LastError = _initialized ? null : "YARA compile failed";
            Logger.Info($"YARA initialized: {CompiledRuleCount} rules from {_filesLoaded} files");
            return _initialized;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Logger.Error("YaraScanner init: " + ex.Message);
            return false;
        }
    }

    public List<ThreatInfo> Scan(string filePath)
    {
        var threats = new List<ThreatInfo>();
        if (!_initialized || _rules == null || !File.Exists(filePath))
            return threats;

        var length = ScanPolicy.TryGetFileLength(filePath);
        if (length < 0 || length > ScanPolicy.MaxYaraFileBytes)
            return threats;

        if (!ScanPolicy.CanOpenForScan(filePath))
            return threats;

        lock (_scanLock)
        {
            if (_disposed || _rules == null)
                return threats;

            try
            {
                var scanner = new Scanner();
                var results = scanner.ScanFile(filePath, _rules);
                CollectResults(filePath, results, threats, regionLabel: null);
            }
            catch (IOException) { /* locked file */ }
            catch (UnauthorizedAccessException) { }
            catch (Exception ex)
            {
                Logger.Warn($"YARA skip [{Path.GetFileName(filePath)}]: {ex.Message}");
            }
        }

        return threats;
    }

    /// <summary>Scan a memory buffer (large-file region). Threats attributed to original path.</summary>
    public List<ThreatInfo> ScanMemory(byte[] data, string originalPath, string? regionLabel = null)
    {
        var threats = new List<ThreatInfo>();
        if (!_initialized || _rules == null || data == null || data.Length == 0)
            return threats;

        if (data.Length > ScanPolicy.MaxYaraFileBytes)
            return threats;

        lock (_scanLock)
        {
            if (_disposed || _rules == null)
                return threats;

            try
            {
                var scanner = new Scanner();
                var results = scanner.ScanMemory(data, _rules);
                CollectResults(originalPath, results, threats, regionLabel);
            }
            catch (Exception ex)
            {
                Logger.Warn($"YARA memory skip [{Path.GetFileName(originalPath)}]: {ex.Message}");
            }
        }

        return threats;
    }

    private void CollectResults(
        string filePath, List<YaraScanResult> results, List<ThreatInfo> threats, string? regionLabel)
    {
        foreach (var result in results)
        {
            var threat = MapResult(filePath, result);
            if (!string.IsNullOrEmpty(regionLabel))
                threat.Details = $"{threat.Details} [large:{regionLabel}]";

            if (ThreatSeverityRules.ShouldReport(threat.Severity))
                threats.Add(threat);
            else
                Logger.Info("Advisory YARA: " + threat.ThreatName + " [" + filePath + "]");
        }
    }

    private static ThreatInfo MapResult(string filePath, YaraScanResult result)
    {
        var ruleName = "YARA.Detection";
        try
        {
            if (result.MatchingRule != null && !string.IsNullOrWhiteSpace(result.MatchingRule.Identifier))
                ruleName = result.MatchingRule.Identifier;
            else if (result.Matches != null && result.Matches.Count > 0)
            {
                var firstList = result.Matches.Values.FirstOrDefault();
                if (firstList != null && firstList.Count > 0)
                    ruleName = firstList[0].AsString() ?? ruleName;
            }
        }
        catch
        {
            // keep default
        }

        return new ThreatInfo
        {
            FilePath = filePath,
            ThreatName = ruleName,
            Method = DetectionMethod.YARA,
            Severity = MapRuleSeverity(ruleName),
            Details = ruleName
        };
    }

    private static ThreatSeverity MapRuleSeverity(string ruleName)
    {
        if (ruleName.IndexOf("Test", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("EICAR", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.Test;

        if (ruleName.StartsWith("Packed_", StringComparison.OrdinalIgnoreCase) ||
            ruleName.IndexOf("Shellcode_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Miner_Silent", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.Info;

        if (ruleName.IndexOf("CredTheft_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("WebShell_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("AMSI_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("RAT_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Stealer_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Ransomware_", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.Critical;

        if (ruleName.IndexOf("Ransomware", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Dropper", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Obfuscated", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Encoded", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.High;

        // Admin/dev script heuristics — advisory unless manually scanned
        if (ruleName.IndexOf("LOLBin_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("PS_Downloader", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Macro_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Persist_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("WMI_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Batch_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Lateral_", StringComparison.OrdinalIgnoreCase) >= 0 ||
            ruleName.IndexOf("Miner_", StringComparison.OrdinalIgnoreCase) >= 0)
            return ThreatSeverity.Medium;

        return ThreatSeverity.Medium;
    }

    private void DisposeRules()
    {
        _rules = null;
        _initialized = false;
        _filesLoaded = 0;
        CompiledRuleCount = 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        DisposeRules();
        _context.Dispose();
    }
}
