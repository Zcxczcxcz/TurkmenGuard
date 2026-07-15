# Quick scan diagnostic — run from repo root after Release build
$ErrorActionPreference = "Stop"
$exeDir = Join-Path $PSScriptRoot "..\src\TurkmenGuard\bin\Release"
if (-not (Test-Path (Join-Path $exeDir "TurkmenGuard.exe"))) {
    Write-Host "Build Release first: dotnet build TurkmenGuard.sln -c Release"
    exit 1
}

$diagCode = @'
using System;
using System.Threading;
using System.Threading.Tasks;
using TurkmenGuard.Core;
using TurkmenGuard.Services;

class ScanDiag
{
    static async Task<int> Main()
    {
        var settings = SettingsService.Load();
        Console.WriteLine("ClamAV dir: " + PathHelper.ClamAvDir);
        var scanner = new ScannerEngine(settings);
        Console.WriteLine($"ClamAV: available={scanner.ClamAvAvailable} daemon={scanner.ClamAvDaemonReady} v={scanner.ClamAvVersion}");
        Console.WriteLine($"YARA: {scanner.YaraCompiledRules} rules, Hash: {scanner.HashSignatureCount:N0}");

        var samples = Path.Combine(Path.GetTempPath(), "tg-diag-" + Guid.NewGuid().ToString("N").Substring(0,8));
        Directory.CreateDirectory(samples);
        var testJs = Path.Combine(samples, "test_virus.js");
        File.WriteAllText(testJs, "TURKMENGUARD_TEST_VIRUS_2026");

        Console.WriteLine("\n--- Single file scan ---");
        var single = await scanner.ScanFileAsync(testJs, ScanMode.SingleFile);
        Console.WriteLine($"SingleFile: threat={single.IsThreat} threats={single.Threats.Count} ms={single.ScanDurationMs}");

        Console.WriteLine("\n--- Quick scan paths ---");
        foreach (var root in PathHelper.GetQuickScanPaths())
            Console.WriteLine($"  {root} exists={Directory.Exists(root)} skip={settings.ShouldSkipDirectory(root)}");

        var lastProgress = new ScanProgress();
        scanner.OnProgress += p => {
            lastProgress = p;
            if (p.FilesScanned % 50 == 0 || !p.IsRunning)
                Console.WriteLine($"  progress: {p.FilesScanned}/{p.TotalFiles} threats={p.ThreatsFound} file={Path.GetFileName(p.CurrentFile)}");
        };

        Console.WriteLine("\n--- Quick scan (10s timeout) ---");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            var results = await scanner.RunScanAsync(ScanMode.Quick, cts.Token);
            Console.WriteLine($"Quick done: threats={results.Count} filesScanned={lastProgress.FilesScanned} total={lastProgress.TotalFiles}");
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine($"Quick CANCELLED/TIMEOUT: filesScanned={lastProgress.FilesScanned} total={lastProgress.TotalFiles}");
        }

        try { Directory.Delete(samples, true); } catch { }
        scanner.Dispose();
        return 0;
    }
}
'@

$projDir = Join-Path $PSScriptRoot "..\src\TurkmenGuard"
Push-Location $projDir
dotnet build -c Release -v q
Pop-Location

$refs = @(
    (Join-Path $exeDir "TurkmenGuard.exe"),
    (Join-Path $exeDir "CommunityToolkit.Mvvm.dll"),
    (Join-Path $exeDir "MaterialDesignThemes.Wpf.dll"),
    (Join-Path $exeDir "MaterialDesignColors.dll"),
    (Join-Path $exeDir "Microsoft.Xaml.Behaviors.dll"),
    (Join-Path $exeDir "Newtonsoft.Json.dll"),
    (Join-Path $exeDir "System.Text.Json.dll"),
    (Join-Path $exeDir "System.Memory.dll"),
    (Join-Path $exeDir "System.Buffers.dll"),
    (Join-Path $exeDir "System.Runtime.CompilerServices.Unsafe.dll"),
    (Join-Path $exeDir "System.Threading.Tasks.Extensions.dll"),
    (Join-Path $exeDir "System.Numerics.Vectors.dll"),
    (Join-Path $exeDir "System.ValueTuple.dll"),
    (Join-Path $exeDir "Microsoft.Bcl.AsyncInterfaces.dll"),
    (Join-Path $exeDir "System.Text.Encodings.Web.dll")
) | Where-Object { Test-Path $_ }

$refArgs = ($refs | ForEach-Object { "/reference:$_" }) -join " "
$srcFile = Join-Path $env:TEMP "ScanDiag.cs"
Set-Content -Path $srcFile -Value $diagCode -Encoding UTF8

$csc = "${env:WINDIR}\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /out:(Join-Path $env:TEMP "ScanDiag.exe") $refArgs $srcFile
Copy-Item (Join-Path $exeDir "TurkmenGuard.exe.config") (Join-Path $env:TEMP "ScanDiag.exe.config") -Force
Push-Location $exeDir
& (Join-Path $env:TEMP "ScanDiag.exe")
Pop-Location
