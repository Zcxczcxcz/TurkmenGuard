#Requires -Version 5.1
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$Version = "4.5.2"
)

$ErrorActionPreference = "Stop"
$distRoot = Join-Path $Root "dist"
$distDir = Join-Path $distRoot "TurkmenGuard-v$Version"
$buildOut = Join-Path $Root "src\TurkmenGuard\bin\Release"
$zipPath = Join-Path $distRoot "TurkmenGuard-v$Version-win-x64.zip"

Write-Host "=== TurkmenGuard publish v$Version ==="

if (-not (Test-Path (Join-Path $Root "ThirdParty\ClamAV\clamscan.exe"))) {
    Write-Host "ClamAV not found - running setup-clamav.ps1 ..."
    & (Join-Path $Root "tools\setup-clamav.ps1")
}

Write-Host "Building Release..."
Push-Location $Root
try {
    dotnet build TurkmenGuard.sln -c Release
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }
} finally {
    Pop-Location
}

if (-not (Test-Path (Join-Path $buildOut "TurkmenGuard.exe"))) {
    throw "TurkmenGuard.exe not found at $buildOut"
}

Write-Host "Creating clean dist folder..."
if (Test-Path $distDir) { Remove-Item $distDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$excludeDirs = @("UserManual", "unpacked", "clamav-download", "samples")
function Copy-CleanTree($src, $dest) {
    if (-not (Test-Path $src)) { return }
    Get-ChildItem $src -Force | ForEach-Object {
        if ($excludeDirs -contains $_.Name) { return }
        $target = Join-Path $dest $_.Name
        if ($_.PSIsContainer) {
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            Copy-CleanTree $_.FullName $target
        } else {
            Copy-Item $_.FullName $target -Force
        }
    }
}

Get-ChildItem $buildOut -File | Copy-Item -Destination $distDir -Force
foreach ($dir in @("Rules", "Data", "ClamAV")) {
    $src = Join-Path $buildOut $dir
    if (Test-Path $src) {
        $dest = Join-Path $distDir $dir
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-CleanTree $src $dest
    }
}

Copy-Item (Join-Path $Root "start.bat") $distDir -Force
Copy-Item (Join-Path $Root "stop-turkmenguard.bat") $distDir -Force
Copy-Item (Join-Path $Root "README.md") $distDir -Force

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($distDir, $zipPath)

$sizeMb = [math]::Round((Get-ChildItem $distDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host ""
Write-Host "Publish complete."
Write-Host "  Folder: $distDir"
Write-Host "  Zip:    $zipPath"
Write-Host "  Size:   $sizeMb MB"
Write-Host ""
Write-Host "Run: $distDir\TurkmenGuard.exe"
