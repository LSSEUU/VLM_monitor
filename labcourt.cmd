@echo off
setlocal
cd /d "%~dp0"

if "%~1"=="" goto help
if /i "%~1"=="help" goto help
if /i "%~1"=="--help" goto help
if /i "%~1"=="-h" goto help
if /i "%~1"=="setup" goto setup
if /i "%~1"=="platform" goto platform
if /i "%~1"=="demo" goto demo
if /i "%~1"=="offline-demo" goto offline_demo
if /i "%~1"=="model-setup" goto model_setup
if /i "%~1"=="qwen-setup" goto qwen_setup
if /i "%~1"=="qwen-demo" goto qwen_demo
if /i "%~1"=="feishu" goto feishu
goto cli

:setup
uv sync --all-groups --locked
exit /b %ERRORLEVEL%

:platform
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-platform-start.ps1"
exit /b %ERRORLEVEL%

:demo
if "%~2"=="" goto demo_start
if /i "%~2"=="start" goto demo_start
if /i "%~2"=="e2e" goto demo_e2e
if not "%~3"=="" goto cli
for %%A in (api bootstrap camera case-action notification notification-deliver notification-acknowledge ppe-case ppe-notification ppe-notification-deliver ppe-notification-reply ppe-appeal-resolve ppe-outcome-notification ppe-outcome-deliver ppe-outcome-acknowledge student-appeal) do if /i "%~2"=="%%A" goto demo_action
goto cli

:demo_action
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-demo.ps1" -Action "%~2"
exit /b %ERRORLEVEL%

:demo_start
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-demo-start.ps1"
exit /b %ERRORLEVEL%

:demo_e2e
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-demo-e2e.ps1"
exit /b %ERRORLEVEL%

:offline_demo
uv run --locked python "%~dp0scripts\run_m6_demo.py"
exit /b %ERRORLEVEL%

:model_setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup_perception_worker.ps1"
exit /b %ERRORLEVEL%

:qwen_setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\setup-m8-qwen-hearing-env.ps1"
exit /b %ERRORLEVEL%

:qwen_demo
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\run-m8-qwen-hearing-demo.ps1"
exit /b %ERRORLEVEL%

:feishu
if "%~2"=="" goto cli
if not "%~3"=="" goto cli
if /i "%~2"=="setup" goto feishu_setup
if /i "%~2"=="demo-card" goto feishu_demo_card
if /i "%~2"=="demo-emergency" goto feishu_demo_emergency
if /i "%~2"=="preflight" goto feishu_preflight
if /i "%~2"=="webhook" goto feishu_webhook
if /i "%~2"=="send-one" goto feishu_send_one
if /i "%~2"=="live" goto feishu_live
goto cli

:feishu_setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-setup.ps1"
exit /b %ERRORLEVEL%

:feishu_demo_card
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-demo-card.ps1"
exit /b %ERRORLEVEL%

:feishu_demo_emergency
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-demo-emergency.ps1"
exit /b %ERRORLEVEL%

:feishu_preflight
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-preflight.ps1"
exit /b %ERRORLEVEL%

:feishu_webhook
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-webhook.ps1"
exit /b %ERRORLEVEL%

:feishu_send_one
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\feishu-send-one.ps1"
exit /b %ERRORLEVEL%

:feishu_live
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\labcourt-feishu-live-start.ps1"
exit /b %ERRORLEVEL%

:cli
uv run --locked labcourt %*
exit /b %ERRORLEVEL%

:help
echo LabCourt Windows launcher
echo.
echo   labcourt.cmd setup
echo   labcourt.cmd platform
echo   labcourt.cmd demo [start^|e2e^|ACTION]
echo   labcourt.cmd offline-demo
echo   labcourt.cmd model-setup
echo   labcourt.cmd qwen-setup ^| qwen-demo
echo   labcourt.cmd feishu [setup^|demo-card^|demo-emergency^|preflight^|webhook^|send-one^|live]
echo   labcourt.cmd COMMAND [ARGS]  ^(passes a top-level command to the LabCourt CLI^)
exit /b 0
