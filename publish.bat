@echo off
setlocal
cd /d "%~dp0"
echo Publishing TurkmenGuard v4.5.2...
powershell -NoProfile -ExecutionPolicy Bypass -File tools\publish-release.ps1
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo.
echo Done. See dist\TurkmenGuard-v4.5.2\
pause
