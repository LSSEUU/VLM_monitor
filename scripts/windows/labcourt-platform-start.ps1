Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$supervisor = $null
$supervisorFlag = $null
$exitCode = 0
try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-platform-demo"
    $media = Join-Path $projectRoot "inputs\goggles-missing.mp4"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    if (-not (Test-Path -LiteralPath $media -PathType Leaf)) {
        throw "The authorized inputs\goggles-missing.mp4 recording was not found."
    }
    foreach ($name in @(
        "LABCOURT_SCREENING_ENDPOINT",
        "LABCOURT_SCREENING_API_KEY",
        "LABCOURT_SCREENING_MODEL",
        "LABCOURT_SCREENING_REVISION",
        "LABCOURT_QWEN_ENDPOINT",
        "LABCOURT_QWEN_API_KEY",
        "LABCOURT_FEISHU_APP_ID",
        "LABCOURT_FEISHU_APP_SECRET",
        "LABCOURT_FEISHU_TEST_OPEN_ID",
        "LABCOURT_FEISHU_WORKER_TOKEN"
    )) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            $userValue = [Environment]::GetEnvironmentVariable($name, "User")
            if ($userValue) {
                [Environment]::SetEnvironmentVariable($name, $userValue, "Process")
            }
        }
    }
    $workerPython = Join-Path $projectRoot ".venv-perception\Scripts\python.exe"
    if (Test-Path -LiteralPath $workerPython -PathType Leaf) {
        [Environment]::SetEnvironmentVariable(
            "LABCOURT_PERCEPTION_PYTHON", $workerPython, "Process"
        )
    }

    & $executable demo platform --output $output --input $media --port 8877 --check
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform preflight failed. Exit code: $LASTEXITCODE."
    }

    $feishuRequired = @(
        "LABCOURT_FEISHU_APP_ID",
        "LABCOURT_FEISHU_APP_SECRET",
        "LABCOURT_FEISHU_TEST_OPEN_ID",
        "LABCOURT_FEISHU_WORKER_TOKEN",
        "LABCOURT_QWEN_ENDPOINT",
        "LABCOURT_QWEN_API_KEY"
    )
    $feishuConfigured = $true
    foreach ($name in $feishuRequired) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            $feishuConfigured = $false
        }
    }
    if ($feishuConfigured) {
        & $executable feishu live-supervise --output $output --input $media --check
        if ($LASTEXITCODE -eq 0) {
            $lifecycleDirectory = Join-Path $output "feishu-live"
            $logDirectory = Join-Path $lifecycleDirectory "logs"
            New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
            $supervisorFlag = Join-Path $lifecycleDirectory "platform-$PID.run"
            Set-Content -LiteralPath $supervisorFlag -Value "owned" -Encoding Ascii
            $arguments = @(
                "feishu", "live-supervise",
                "--output", $output,
                "--input", $media,
                "--stop-file", $supervisorFlag
            )
            $supervisor = Start-Process `
                -FilePath $executable `
                -ArgumentList $arguments `
                -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $logDirectory "supervisor.stdout.log") `
                -RedirectStandardError (Join-Path $logDirectory "supervisor.stderr.log") `
                -PassThru
            Start-Sleep -Milliseconds 800
            if ($supervisor.HasExited) {
                Write-Warning "Feishu live supervisor did not start; the platform remains available in offline mode."
                $supervisor = $null
                Remove-Item -LiteralPath $supervisorFlag -Force -ErrorAction SilentlyContinue
                $supervisorFlag = $null
            }
        }
        else {
            Write-Warning "Feishu live authority is not ready; the platform remains available in offline mode."
        }
    }
    else {
        Write-Warning "Feishu live configuration is incomplete; the platform remains available in offline mode."
    }

    Start-Process "http://127.0.0.1:8877/"
    & $executable demo platform --output $output --input $media --port 8877
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform stopped unexpectedly. Exit code: $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $exitCode = 2
}
finally {
    if ($supervisorFlag) {
        Remove-Item -LiteralPath $supervisorFlag -Force -ErrorAction SilentlyContinue
    }
    if ($supervisor -and -not $supervisor.HasExited) {
        if (-not $supervisor.WaitForExit(5000)) {
            Stop-Process -Id $supervisor.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
if ($exitCode -ne 0) {
    exit $exitCode
}
