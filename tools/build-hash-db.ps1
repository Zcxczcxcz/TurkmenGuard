# Builds hash-signatures.db from hash-signatures.json
param(
    [string]$JsonPath = "..\Data\hash-signatures.json",
    [string]$OutputPath = "..\Data\hash-signatures.db"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$jsonFull = Resolve-Path (Join-Path $root $JsonPath)
$outputFull = Join-Path $root $OutputPath

Write-Host "Building hash DB..."
Write-Host "  JSON:   $jsonFull"
Write-Host "  Output: $outputFull"

$slnRoot = Resolve-Path (Join-Path $root "..")
$testProj = Join-Path $slnRoot "tests\TurkmenGuard.Tests\TurkmenGuard.Tests.csproj"
dotnet build $testProj -c Release --verbosity quiet | Out-Null

$testDir = Join-Path $slnRoot "tests\TurkmenGuard.Tests\bin\Release"
$sqliteDll = Get-ChildItem -Path $testDir -Filter "System.Data.SQLite.dll" -Recurse | Select-Object -First 1
if (-not $sqliteDll) { throw "System.Data.SQLite.dll not found. Build tests first." }

Add-Type -Path $sqliteDll.FullName
$json = Get-Content $jsonFull -Raw | ConvertFrom-Json

if (Test-Path $outputFull) { Remove-Item $outputFull -Force }
[System.Data.SQLite.SQLiteConnection]::CreateFile($outputFull)

$conn = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$outputFull;Version=3;"
$conn.Open()

$cmd = $conn.CreateCommand()
$cmd.CommandText = @"
CREATE TABLE signatures (sha256 TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, severity INTEGER NOT NULL DEFAULT 4);
CREATE INDEX idx_signatures_sha256 ON signatures(sha256);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
"@
$cmd.ExecuteNonQuery() | Out-Null

$insert = $conn.CreateCommand()
$insert.CommandText = "INSERT OR IGNORE INTO signatures (sha256, name, severity) VALUES (@h, @n, @s);"
$pH = $insert.CreateParameter(); $pH.ParameterName = "@h"; $insert.Parameters.Add($pH) | Out-Null
$pN = $insert.CreateParameter(); $pN.ParameterName = "@n"; $insert.Parameters.Add($pN) | Out-Null
$pS = $insert.CreateParameter(); $pS.ParameterName = "@s"; $insert.Parameters.Add($pS) | Out-Null

$count = 0
foreach ($e in $json) {
    if (-not $e.sha256) { continue }
    $pH.Value = $e.sha256.ToLower()
    $pN.Value = if ($e.name) { $e.name } else { "Unknown" }
    $sev = switch -Regex ($e.severity) { "Test" {0} "Info" {1} "Low" {2} "Medium" {3} "Critical" {5} default {4} }
    $pS.Value = [int]$sev
    $insert.ExecuteNonQuery() | Out-Null
    $count++
}

$meta = $conn.CreateCommand()
$meta.CommandText = "INSERT INTO meta (key, value) VALUES ('version', @v);"
$meta.Parameters.AddWithValue("@v", (Get-Date -Format "yyyy.MM.dd")) | Out-Null
$meta.ExecuteNonQuery() | Out-Null
$conn.Close()

Write-Host "Done: $count signatures"
