Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-platform-demo"
    $media = Join-Path $projectRoot "inputs\goggles-missing.mp4"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Install the feishu-live extra first."
    }
    if (-not (Test-Path -LiteralPath $media -PathType Leaf)) {
        throw "The authorized platform input recording was not found."
    }

    $required = @(
        "LABCOURT_FEISHU_APP_ID",
        "LABCOURT_FEISHU_APP_SECRET",
        "LABCOURT_FEISHU_TEST_OPEN_ID",
        "LABCOURT_FEISHU_WORKER_TOKEN",
        "LABCOURT_QWEN_ENDPOINT",
        "LABCOURT_QWEN_API_KEY"
    )
    foreach ($name in $required) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            $userValue = [Environment]::GetEnvironmentVariable($name, "User")
            if ($userValue) {
                [Environment]::SetEnvironmentVariable($name, $userValue, "Process")
            }
        }
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            throw "Required user environment variable is missing: $name"
        }
    }

    $arguments = @(
        "feishu", "live-supervise",
        "--output", $output,
        "--input", $media
    )
    & $executable @arguments --check
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt Feishu live supervisor preflight failed."
    }

    $logDirectory = Join-Path $output "feishu-live\logs"
    New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
    $supervisor = Start-Process `
        -FilePath $executable `
        -ArgumentList $arguments `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDirectory "supervisor.stdout.log") `
        -RedirectStandardError (Join-Path $logDirectory "supervisor.stderr.log") `
        -PassThru
    Start-Sleep -Seconds 2
    if ($supervisor.HasExited) {
        throw "Feishu live supervisor exited during startup validation."
    }
    Write-Output "LabCourt Feishu live supervisor started. Process ID: $($supervisor.Id)"
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
