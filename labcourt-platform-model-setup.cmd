@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup_perception_worker.ps1"
set "labcourt_exit=%ERRORLEVEL%"
if not "%labcourt_exit%"=="0" pause
exit /b %labcourt_exit%
