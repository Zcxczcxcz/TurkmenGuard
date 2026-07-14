#Requires -Version 5.1
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$ClamVersion = "1.5.3",
    [switch]$SkipEngine,
    [switch]$SkipDatabase
)

$ErrorActionPreference = "Stop"
$ThirdParty = Join-Path $Root "ThirdParty"
$ZipPath = Join-Path $ThirdParty "clamav-$ClamVersion.win.x64.zip"
$ClamDir = Join-Path $ThirdParty "ClamAV"
$DbDir = Join-Path $ClamDir "database"
$MinZipBytes = 229959640
$ExactZipBytes = 229959640

New-Item -ItemType Directory -Force -Path $ThirdParty | Out-Null

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

function Test-ClamEngine {
    return (Test-Path (Join-Path $ClamDir "clamscan.exe")) -and
           (Test-Path (Join-Path $ClamDir "clamd.exe")) -and
           (Test-Path (Join-Path $ClamDir "clamdscan.exe"))
}

function Download-File($Url, $Dest) {
    Write-Host "Downloading $Url -> $Dest"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        # Resume partial downloads; long retries for slow links
        & curl.exe -L --retry 15 --retry-delay 5 --connect-timeout 60 -C - -o $Dest $Url
        if ($LASTEXITCODE -ne 0) {
            throw "curl failed with exit code $LASTEXITCODE"
        }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    }
}

function Copy-EngineFromProgramFiles {
    $candidates = @(
        "${env:ProgramFiles}\ClamAV",
        "${env:ProgramFiles}\ClamAV*",
        "${env:ProgramFiles(x86)}\ClamAV"
    )
    foreach ($pattern in $candidates) {
        $dirs = Get-Item $pattern -ErrorAction SilentlyContinue
        foreach ($d in $dirs) {
            if (Test-Path (Join-Path $d.FullName "clamscan.exe")) {
                New-Item -ItemType Directory -Force -Path $ClamDir | Out-Null
                Get-ChildItem $d.FullName -File | Copy-Item -Destination $ClamDir -Force
                Get-ChildItem $d.FullName -Directory | Where-Object { $_.Name -ne 'database' } |
                    ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $ClamDir $_.Name) -Recurse -Force }
                Write-Host "Copied ClamAV engine from $($d.FullName)"
                return $true
            }
        }
    }
    return $false
}

if (-not $SkipEngine) {
    if (-not (Test-ClamEngine)) {
        if (Copy-EngineFromProgramFiles) {
            Write-Host "Using ClamAV from Program Files."
        } else {
        $urls = @(
            "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$ClamVersion/clamav-$ClamVersion.win.x64.zip",
            "https://www.clamav.net/downloads/production/clamav-$ClamVersion.win.x64.zip"
        )

        $needDownload = $true
        if (Test-Path $ZipPath) {
            $size = (Get-Item $ZipPath).Length
            if ($size -ge $MinZipBytes -and (Test-ZipIntegrity $ZipPath) -and ($size -le ($ExactZipBytes + 1048576))) {
                $needDownload = $false
            } else {
                if ($size -gt 0) {
                    Write-Host "Invalid or corrupt zip ($size bytes), will re-download"
                    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Host "Incomplete zip ($size bytes), will download to .part"
                }
            }
        }

        if ($needDownload) {
            $ok = $false
            # Prefer resuming the largest partial file we already have
            $tmpZip = "$ZipPath.part"
            $resumeTarget = $tmpZip
            $zipSize = if (Test-Path $ZipPath) { (Get-Item $ZipPath).Length } else { 0 }
            $partSize = if (Test-Path $tmpZip) { (Get-Item $tmpZip).Length } else { 0 }
            if ($zipSize -ge $partSize -and $zipSize -gt 0 -and $zipSize -lt $MinZipBytes) {
                Write-Host "Resuming existing zip ($zipSize bytes)..."
                $resumeTarget = $ZipPath
            } elseif ($partSize -gt 0 -and $partSize -lt $MinZipBytes) {
                Write-Host "Resuming existing .part ($partSize bytes)..."
            }

            foreach ($u in $urls) {
                try {
                    Download-File $u $resumeTarget
                    $finalSize = (Get-Item $resumeTarget).Length
                    if ($finalSize -ge $MinZipBytes -and (Test-ZipIntegrity $resumeTarget) -and ($finalSize -le ($ExactZipBytes + 1048576))) {
                        if ($resumeTarget -ne $ZipPath) {
                            if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue }
                            Move-Item $resumeTarget $ZipPath -Force
                        }
                        if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue }
                        $ok = $true
                        break
                    }
                    Write-Warning "Incomplete after $u ($finalSize bytes)"
                } catch {
                    Write-Warning "Failed: $u - $($_.Exception.Message)"
                }
            }
            if (-not $ok) {
                $left = if (Test-Path $resumeTarget) { (Get-Item $resumeTarget).Length } else { 0 }
                throw "Could not download ClamAV engine zip (have $left bytes, need >= 200 MB). Re-run script to resume."
            }
        }

        $extractRoot = Join-Path $ThirdParty "_clam_extract"
        if (Test-Path $extractRoot) { Remove-Item $extractRoot -Recurse -Force }
        Expand-Archive -Path $ZipPath -DestinationPath $extractRoot -Force

        $inner = Get-ChildItem $extractRoot -Directory | Select-Object -First 1
        if ($null -eq $inner) {
            $hasExe = Test-Path (Join-Path $extractRoot "clamscan.exe")
            if ($hasExe) { $inner = Get-Item $extractRoot }
            else { throw "Unexpected zip layout" }
        }

        New-Item -ItemType Directory -Force -Path $ClamDir | Out-Null
        Get-ChildItem $inner.FullName -File | Copy-Item -Destination $ClamDir -Force
        Get-ChildItem $inner.FullName -Directory | Where-Object { $_.Name -ne 'database' } |
            ForEach-Object { Copy-Item $_.FullName -Destination (Join-Path $ClamDir $_.Name) -Recurse -Force }
        Remove-Item $extractRoot -Recurse -Force
        Write-Host "ClamAV engine extracted to $ClamDir (existing database/ preserved)"
        }
    } else {
        Write-Host "ClamAV engine already present."
    }
}

if (-not $SkipDatabase) {
    New-Item -ItemType Directory -Force -Path $DbDir | Out-Null
    $cvdCount = @(Get-ChildItem $DbDir -Filter "*.cvd" -ErrorAction SilentlyContinue).Count

    if ($cvdCount -lt 2) {
        $freshclam = Join-Path $ClamDir "freshclam.exe"
        if (Test-Path $freshclam) {
            $conf = Join-Path $ClamDir "freshclam.conf"
            if (-not (Test-Path $conf)) {
                $db = $DbDir.Replace('\', '/')
                $log = (Join-Path $DbDir "freshclam.log").Replace('\', '/')
                $lines = @(
                    "DatabaseDirectory $db",
                    "UpdateLogFile $log",
                    "DatabaseMirror database.clamav.net",
                    "MaxAttempts 3",
                    "CompressLocalDatabase yes"
                )
                Set-Content -Path $conf -Value $lines -Encoding UTF8
            }
            Write-Host "Updating CVD databases via freshclam..."
            & $freshclam --config-file="$conf" 2>&1 | ForEach-Object { Write-Host $_ }
        }

        $cvdCount = @(Get-ChildItem $DbDir -Filter "*.cvd" -ErrorAction SilentlyContinue).Count
    }

    if ($cvdCount -lt 2) {
        Write-Host "freshclam incomplete, trying cvdupdate (pip)..."
        $pip = Get-Command pip -ErrorAction SilentlyContinue
        if ($pip) {
            & pip install cvdupdate --quiet 2>$null
            $cvdupdate = Get-Command cvdupdate -ErrorAction SilentlyContinue
            if ($cvdupdate) {
                & cvdupdate config set -d $DbDir 2>&1 | ForEach-Object { Write-Host $_ }
                & cvdupdate update -V 2>&1 | ForEach-Object { Write-Host $_ }
            }
        }
    }

    $cvds = @(Get-ChildItem $DbDir -Filter "*.cvd" -ErrorAction SilentlyContinue)
    if ($cvds.Count -lt 2) {
        throw "CVD databases missing in $DbDir. Install pip + cvdupdate or run freshclam manually."
    }
    Write-Host "Database: $($cvds.Count) CVD files in $DbDir"
}

if (-not (Test-ClamEngine)) {
    throw "clamscan.exe not found after setup"
}

Write-Host ""
Write-Host "ClamAV setup complete."
Write-Host "  Engine: $ClamDir"
Write-Host "  Database: $DbDir"
