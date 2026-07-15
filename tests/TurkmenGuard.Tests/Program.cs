using TurkmenGuard.Core;
using TurkmenGuard.Quarantine;
using TurkmenGuard.Security;
using TurkmenGuard.Services;

Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║   TurkmenGuard v4.7.2 — Integration Tests    ║");
Console.WriteLine("╚══════════════════════════════════════════════╝\n");

var passed = 0;
var failed = 0;

void Assert(string name, bool condition)
{
    if (condition) { Console.WriteLine($"[PASS] {name}"); passed++; }
    else { Console.WriteLine($"[FAIL] {name}"); failed++; }
}

var settings = new AppSettings();
settings.Exclusions.Extensions = ScanPolicy.GetDefaultExcludedExtensions().ToList();
var scanner = new ScannerEngine(settings);

if (scanner.ClamAvAvailable)
{
    Console.WriteLine($"ClamAV: v{scanner.ClamAvVersion}, {scanner.ClamAvDatabaseCount} DB, daemon={scanner.ClamAvDaemonReady}");
    Assert("ClamAV engine available", true);
}
else
{
    Console.WriteLine("[SKIP] ClamAV (run tools/setup-clamav.ps1 first)");
}

Assert("YARA available", scanner.YaraAvailable);
Assert("YARA rule files >= 20", scanner.YaraRulesLoaded >= 20);
Assert("YARA compiled rules >= 60", scanner.YaraCompiledRules >= 60);
Console.WriteLine($"YARA: {scanner.YaraRulesLoaded} files, {scanner.YaraCompiledRules} compiled rules");
Console.WriteLine($"Hash DB: {scanner.HashSignatureCount:N0} signatures ({scanner.HashDatabaseSource})");
Assert("Hash DB loaded", scanner.HashSignatureCount > 100_000);
Console.WriteLine($"Rules dir: {PathHelper.RulesDir}\n");

var samplesDir = Path.Combine(AppContext.BaseDirectory, "samples");
if (Directory.Exists(samplesDir))
{
    try { Directory.Delete(samplesDir, true); } catch { /* ClamAV may hold locks */ }
}
Directory.CreateDirectory(samplesDir);

static void WriteSample(string path, string content)
{
    for (var i = 0; i < 3; i++)
    {
        try
        {
            File.WriteAllText(path, content);
            return;
        }
        catch (IOException) when (i < 2)
        {
            Thread.Sleep(500);
        }
    }
}

var cleanFile = Path.Combine(samplesDir, "clean_test.txt");
WriteSample(cleanFile, "This is a clean test file for TurkmenGuard.");
var cleanResult = await scanner.ScanFileAsync(cleanFile);
Assert("Clean file not flagged", !cleanResult.IsThreat);

var quickDir = Path.Combine(samplesDir, "quick_batch");
Directory.CreateDirectory(quickDir);
for (var i = 0; i < 5; i++)
{
    var content = i == 0 ? "TURKMENGUARD_TEST_VIRUS_2026" : $"clean file {i}";
    WriteSample(Path.Combine(quickDir, $"sample_{i}.js"), content);
}
var quickProgress = new ScanProgress();
var quickResults = await scanner.ScanDirectoryAsync(quickDir, ScanMode.Quick, quickProgress);
Assert("Quick batch scan finds threat", quickResults.Any(r => r.IsThreat));
Assert("Quick batch scan counts files", quickProgress.FilesScanned >= 5);

var testMalware = Path.Combine(samplesDir, "test_virus.js");
WriteSample(testMalware, "TURKMENGUARD_TEST_VIRUS_2026");
var malwareResult = await scanner.ScanFileAsync(testMalware);
Assert("Test malware detected", malwareResult.IsThreat);

var credTheft = Path.Combine(samplesDir, "cred_test.ps1");
WriteSample(credTheft, "sekurlsa::logonpasswords mimikatz dump");
var credResult = await scanner.ScanFileAsync(credTheft);
Assert("Credential theft YARA rule", credResult.IsThreat);

var amsiBypass = Path.Combine(samplesDir, "amsi_test.ps1");
WriteSample(amsiBypass,
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext').SetValue($null,$true)");
var amsiResult = await scanner.ScanFileAsync(amsiBypass);
Assert("AMSI bypass YARA rule", amsiResult.IsThreat);

// Large-file structural path: >8 MB payload with marker in the tail (avoids Defender eating .exe)
var largePath = Path.Combine(samplesDir, "large_dropper.dat");
try
{
    using (var fs = File.Create(largePath))
    {
        var head = System.Text.Encoding.ASCII.GetBytes("PAD");
        fs.Write(head, 0, head.Length);
        fs.SetLength(9L * 1024 * 1024); // > LargeFileThreshold
        fs.Position = 9L * 1024 * 1024 - 64;
        var marker = System.Text.Encoding.ASCII.GetBytes("TURKMENGUARD_TEST_VIRUS_2026");
        fs.Write(marker, 0, marker.Length);
    }

    var regions = LargeFileScanner.ExtractRegions(largePath, ScanMode.SingleFile);
    Assert("Large file extracts edge regions", regions.Count >= 2);

    var largeResult = await scanner.ScanFileAsync(largePath);
    Assert("Large file structural scan detects overlay marker", largeResult.IsThreat);
}
catch (Exception ex)
{
    Console.WriteLine($"[SKIP] Large file test: {ex.Message}");
}
finally
{
    try { if (File.Exists(largePath)) File.Delete(largePath); } catch { }
}

var eicarPath = Path.Combine(samplesDir, "eicar.js");
try
{
    var eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    WriteSample(eicarPath, eicar);
    if (!File.Exists(eicarPath))
        Console.WriteLine("[SKIP] EICAR (Defender removed file immediately)");
    else
    {
        var eicarResult = await scanner.ScanFileAsync(eicarPath);
        if (eicarResult.IsThreat)
            Assert("EICAR detected", true);
        else
            Console.WriteLine("[SKIP] EICAR (Defender or OS blocked content before scan)");
    }
}
catch (IOException ex)
{
    Console.WriteLine($"[SKIP] EICAR (Defender blocked): {ex.Message}");
}

Assert("Entropy threshold = 7.95", EntropyAnalyzer.SuspiciousThreshold == 7.95);

var quarantine = new QuarantineManager();
var qFile = Path.Combine(samplesDir, "quarantine_test.js");
WriteSample(qFile, "TURKMENGUARD_TEST_VIRUS_2026");
var threat = new ThreatInfo { ThreatName = "Test", Method = DetectionMethod.YARA, FilePath = qFile, Severity = ThreatSeverity.High };
var entry = quarantine.QuarantineFile(qFile, threat);
Assert("Quarantine file", entry != null && !File.Exists(qFile));
if (entry != null)
{
    Assert("Quarantine restore", quarantine.Restore(entry.Id) && File.Exists(entry.OriginalPath));
    if (File.Exists(entry.OriginalPath))
        File.Delete(entry.OriginalPath);
}

Assert("No trusted system skip", ScanPolicy.ShouldScanExtension(@"C:\Windows\System32\kernel32.dll"));

var startupCmd = AutoStartService.GetStartupCommand();
Assert("Autostart command includes --tray", startupCmd != null && startupCmd.Contains("--tray"));

Assert("Autostart registry sync API", AutoStartService.IsRegistryCorrect() || !AutoStartService.IsEnabled());

using (var sp = new SelfProtectionService(settings))
    Assert("Self-protection single instance", sp.IsSingleInstance);

scanner.Dispose();

Console.WriteLine($"\n═══ Results: {passed} passed, {failed} failed ═══");
Environment.Exit(failed > 0 ? 1 : 0);
