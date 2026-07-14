#Requires -Version 5.1
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$ClamVersion = "1.5.3"
)

$ErrorActionPreference = "Continue"
$ThirdParty = Join-Path $Root "ThirdParty"
$ZipPath = Join-Path $ThirdParty "clamav-$ClamVersion.win.x64.zip"
$MinBytes = 229959640
$ExactBytes = 229959640
$Urls = @(
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$ClamVersion/clamav-$ClamVersion.win.x64.zip",
    "https://www.clamav.net/downloads/production/clamav-$ClamVersion.win.x64.zip"
)

function Test-ZipIntegrity([string]$Path) {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $ok = $zip.Entries.Count -gt 0
        $zip.Dispose()
        return $ok
    } catch {
        return $false
    }
}

if ((Test-Path $ZipPath) -and (Get-Item $ZipPath).Length -ge $MinBytes) {
    if ((Test-ZipIntegrity $ZipPath) -and ((Get-Item $ZipPath).Length -le ($ExactBytes + 1048576))) {
        Write-Host "Already complete: $ZipPath"
        exit 0
    }
    Write-Warning "Existing zip is corrupt, will re-download"
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
}

$attempt = 0
while ($true) {
    $attempt++
    $size = if (Test-Path $ZipPath) { (Get-Item $ZipPath).Length } else { 0 }
    if ($size -ge $MinBytes) {
        if ((Test-ZipIntegrity $ZipPath) -and ((Get-Item $ZipPath).Length -le ($ExactBytes + 1048576))) {
            Write-Host "Download complete: $([math]::Round($size/1MB,1)) MB"
            exit 0
        }
        Write-Warning "Zip corrupt or wrong size ($size bytes), re-downloading from scratch..."
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
        $size = 0
    }

    Write-Host "Attempt $attempt resume from $([math]::Round($size/1MB,1)) MB"
    $urlIndex = (($attempt - 1) % $Urls.Count)
    $Url = $Urls[$urlIndex]
    Write-Host "URL: $Url"
    & curl.exe -L --retry 5 --retry-delay 10 --connect-timeout 120 -C - -o $ZipPath $Url
    $code = $LASTEXITCODE
    $size = if (Test-Path $ZipPath) { (Get-Item $ZipPath).Length } else { 0 }
    Write-Host "curl exit=$code size=$([math]::Round($size/1MB,1)) MB"

    if ($size -ge $MinBytes) {
        if ((Test-ZipIntegrity $ZipPath) -and ($size -le ($ExactBytes + 1048576))) {
            Write-Host "Download complete."
            exit 0
        }
        Write-Warning "Zip corrupt after download, retrying..."
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    }

    if ($attempt -ge 50) {
        Write-Error "Too many attempts, have $size bytes"
        exit 1
    }
    Start-Sleep -Seconds 15
}
