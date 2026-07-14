# Creates GitHub repo and uploads release zip (run once after: gh auth login)
param(
    [string]$Owner = "Zcxczcxcz",
    [string]$RepoName = "TurkmenGuard",
    [string]$Version = "4.5.0",
    [switch]$Private
)

$ErrorActionPreference = "Stop"
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$root\.git")) { $root = Split-Path $PSScriptRoot -Parent }
Set-Location $root

$visibility = if ($Private) { "--private" } else { "--public" }
$zip = Join-Path $root "dist\TurkmenGuard-v$Version-win-x64.zip"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "GitHub CLI (gh) not found. Install: winget install GitHub.cli"
}

gh auth status 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Run first: gh auth login"
    exit 1
}

$remote = git remote get-url origin 2>$null
if (-not $remote) {
    gh repo create $RepoName $visibility --source=. --remote=origin --push `
        --description "Autonomous Windows antivirus (WPF, ClamAV, YARA) v$Version"
} else {
    git push -u origin HEAD
}

if (Test-Path $zip) {
    gh release create "v$Version" $zip --title "TurkmenGuard v$Version" `
        --notes "Deploy release. Run publish.bat locally for dist folder."
    Write-Host "Release uploaded: v$Version"
} else {
    Write-Host "Zip not found ($zip). Run publish.bat first, then re-run this script."
}

Write-Host "Done."
