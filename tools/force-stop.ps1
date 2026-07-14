#Requires -Version 5.1
<#
.SYNOPSIS
    Force-stops TurkmenGuard and all related ClamAV processes.
    Disables autostart and aggressive self-protection flags in settings.
#>
param(
    [switch]$Quiet
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Status($msg) {
    if (-not $Quiet) { Write-Host $msg }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-ProcessTree([int]$ProcessId) {
    if ($ProcessId -le 0) { return $false }

    $null = & taskkill.exe /F /T /PID $ProcessId 2>&1
    return $LASTEXITCODE -eq 0
}

function Stop-ByImage([string]$ImageName) {
    if ([string]::IsNullOrWhiteSpace($ImageName)) { return $false }

    $exe = if ($ImageName.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) {
        $ImageName
    } else {
        "$ImageName.exe"
    }

    $null = & taskkill.exe /F /T /IM $exe 2>&1
    return $LASTEXITCODE -eq 0
}

function Get-TargetProcesses {
    $names = @(
        "TurkmenGuard.exe",
        "TurkmenGuard.Tests.exe",
        "clamscan.exe",
        "clamd.exe",
        "clamdscan.exe",
        "freshclam.exe"
    )

    $byName = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $names -contains $_.Name }

    $byPath = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $path = $_.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($path)) { return $false }
            $path -match 'TurkmenGuard|\\ClamAV\\|\\clamav\\'
        }

    ($byName + $byPath) |
        Sort-Object ProcessId -Unique
}

$imageNames = @(
    "TurkmenGuard",
    "TurkmenGuard.Tests",
    "clamscan",
    "clamd",
    "clamdscan",
    "freshclam"
)

Write-Status "=== TurkmenGuard force stop ==="

if (-not (Test-IsAdmin)) {
    Write-Status "Note: not running as Administrator. Some processes may survive."
}

# Disable flags first so watchdog/autostart do not fight the kill.
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path $runKey -Name "TurkmenGuard" -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKey -Name "TurkmenGuard" -Force
    Write-Status "Autostart registry entry removed."
} else {
    Write-Status "Autostart registry entry not found (already off)."
}

$settingsPath = Join-Path $env:APPDATA "TurkmenGuard\settings.json"
if (Test-Path $settingsPath) {
    try {
        $json = Get-Content $settingsPath -Raw -Encoding UTF8
        $settings = $json | ConvertFrom-Json
        $settings.AutoStart = $false
        $settings.RealTimeEnabled = $false
        $settings.SelfProtectionEnabled = $false
        $settings.ProcessMonitorEnabled = $false
        $settings | ConvertTo-Json -Depth 10 | Set-Content $settingsPath -Encoding UTF8
        Write-Status "Settings updated: AutoStart/RealTime/SelfProtection/ProcessMonitor = off"
    } catch {
        Write-Status "Warning: could not update settings.json ($($_.Exception.Message))"
    }
}

$pidFile = Join-Path $env:APPDATA "TurkmenGuard\clamav\clamd.pid"
if (Test-Path $pidFile) {
    Remove-Item $pidFile -Force
    Write-Status "Removed stale clamd.pid"
}

# Pass 1: kill full trees by image name.
foreach ($name in $imageNames) {
    if (Stop-ByImage $name) {
        Write-Status "taskkill /F /T /IM ${name}.exe"
    }
}

Start-Sleep -Milliseconds 700

# Pass 2: kill every matching PID (including orphans and path matches).
$targets = @(Get-TargetProcesses)
foreach ($proc in $targets) {
    Write-Status "Stopping tree: $($proc.Name) PID $($proc.ProcessId)"
    Stop-ProcessTree $proc.ProcessId
}

Start-Sleep -Milliseconds 700

# Pass 3: image names again for respawned children.
foreach ($name in $imageNames) {
    Stop-ByImage $name | Out-Null
}

Start-Sleep -Milliseconds 500

$remaining = @(Get-TargetProcesses)
if ($remaining.Count -gt 0) {
    Write-Status ""
    Write-Status "WARNING: still running:"
    foreach ($proc in $remaining) {
        $path = $proc.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($path)) { $path = "(path unknown)" }
        Write-Status "  - $($proc.Name) PID $($proc.ProcessId)  $path"
    }
    Write-Status ""
    if (-not (Test-IsAdmin)) {
        Write-Status "Run stop-turkmenguard.bat as Administrator (right-click -> Run as administrator)."
    } else {
        Write-Status "Processes survived even with admin rights. Close Task Manager manually or reboot."
    }
    exit 1
}

Write-Status ""
Write-Status "Done. TurkmenGuard and ClamAV processes are stopped."
exit 0
