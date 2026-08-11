@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-demo-notification-acknowledge.ps1"
set "labcourt_exit=%ERRORLEVEL%"
pause
exit /b %labcourt_exit%
