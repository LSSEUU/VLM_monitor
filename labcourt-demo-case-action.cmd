@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-demo-case-action.ps1"
set "labcourt_exit=%ERRORLEVEL%"
pause
exit /b %labcourt_exit%
