@echo off

cd /d "%~dp0"

if not exist "ThirdParty\ClamAV\clamscan.exe" (
  echo ClamAV engine not found — running setup...
  powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
  if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
)

dotnet build src\TurkmenGuard\TurkmenGuard.csproj -c Release

if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

start "" "src\TurkmenGuard\bin\Release\TurkmenGuard.exe"

