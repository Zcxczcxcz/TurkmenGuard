@echo off
setlocal
title TurkmenGuard Force Stop

cd /d "%~dp0"

:: Auto-elevate to Administrator (required for stubborn/hung processes).
net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo.
    echo Requesting Administrator rights...
    echo.
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================
echo  TurkmenGuard - FORCE STOP
echo ============================================
echo.
echo Stops:
echo   - TurkmenGuard.exe (process tree)
echo   - clamscan / clamd / clamdscan / freshclam
echo   - autostart registry entry
echo   - realtime / self-protection flags in settings
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\force-stop.ps1"
set EXITCODE=%ERRORLEVEL%

echo.
if "%EXITCODE%"=="0" goto ok
echo WARNING: some processes may still be running.
echo Check Task Manager for TurkmenGuard.exe or clamscan.exe
goto end

:ok
echo All TurkmenGuard services stopped.

:end
echo.
pause
endlocal & exit /b %EXITCODE%
