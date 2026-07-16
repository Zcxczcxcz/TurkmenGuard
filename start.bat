@echo off
setlocal
chcp 65001 >nul 2>&1
title TurkmenGuard

cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║        T U R K M E N  G U A R D          ║
echo  ╚══════════════════════════════════════════╝
echo.

:: Check .NET SDK
where dotnet >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] .NET SDK not found. Install .NET 8.0 SDK.
    echo         https://dotnet.microsoft.com/download
    goto :fail
)

:: Check source
if not exist "src\TurkmenGuard\TurkmenGuard.csproj" (
    echo [ERROR] Source not found: src\TurkmenGuard\TurkmenGuard.csproj
    goto :fail
)

:: Check ClamAV in source
if not exist "ThirdParty\ClamAV\clamscan.exe" (
    echo [WARN] ClamAV not found in ThirdParty\ClamAV\
    echo        Running setup...
    if exist "tools\setup-clamav.ps1" (
        powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
        if %ERRORLEVEL% neq 0 goto :fail
    ) else (
        echo [ERROR] tools\setup-clamav.ps1 not found.
        goto :fail
    )
)

:: Build Release
echo [BUILD] Compiling Release...
dotnet build src\TurkmenGuard\TurkmenGuard.csproj -c Release -v quiet
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed.
    goto :fail
)

:: Verify output
set "EXE=src\TurkmenGuard\bin\Release\TurkmenGuard.exe"
if not exist "%EXE%" (
    echo [ERROR] Build output not found: %EXE%
    goto :fail
)

:: Check if already running
tasklist /FI "IMAGENAME eq TurkmenGuard.exe" 2>nul | find /I "TurkmenGuard.exe" >nul
if %ERRORLEVEL% equ 0 (
    echo [INFO] TurkmenGuard is already running.
    choice /C YN /M "Kill existing instance and restart" /T 5 /D N >nul
    if %ERRORLEVEL% equ 1 (
        taskkill /F /IM TurkmenGuard.exe >nul 2>&1
        timeout /t 1 >nul
    ) else (
        goto :end
    )
)

echo [OK]    Launching TurkmenGuard...
echo.
start "" "%EXE%"
goto :end

:fail
echo.
echo [FAILED] Fix errors above and try again.
echo.
pause
exit /b 1

:end
exit /b 0
