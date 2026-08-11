@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-preflight.ps1"
set "labcourt_exit=%ERRORLEVEL%"
pause
exit /b %labcourt_exit%
