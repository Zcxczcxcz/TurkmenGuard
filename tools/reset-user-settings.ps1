#Requires -Version 5.1
<#
.SYNOPSIS
    Resets TurkmenGuard user settings and counters to factory defaults.
#>
param(
    [switch]$Quiet
)

$settingsPath = Join-Path $env:APPDATA "TurkmenGuard\settings.json"

if (Test-Path $settingsPath) {
    Remove-Item $settingsPath -Force
    if (-not $Quiet) { Write-Host "Removed: $settingsPath" }
} else {
    if (-not $Quiet) { Write-Host "Settings file not found (already clean)." }
}

$defaults = @{
    AutoStart = $false
    RealTimeEnabled = $false
    SelfProtectionEnabled = $false
    ProcessMonitorEnabled = $false
}
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path $runKey -Name "TurkmenGuard" -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKey -Name "TurkmenGuard" -Force
    if (-not $Quiet) { Write-Host "Autostart registry entry removed." }
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "Done. Counters and settings reset. Next launch uses v4.5 defaults."
}
