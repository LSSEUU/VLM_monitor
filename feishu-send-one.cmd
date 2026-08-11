@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-send-one.ps1"
set "labcourt_exit=%ERRORLEVEL%"
pause
exit /b %labcourt_exit%
