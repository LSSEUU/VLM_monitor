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

    $components = @("LONG_CONNECTION", "AUTHORITY_WORKER", "DELIVERY_WORKER")
    $processes = @()
    foreach ($component in $components) {
        $arguments = @(
            "feishu", "live-run",
            "--component", $component,
            "--output", $output,
            "--input", $media
        )
        $processes += Start-Process `
            -FilePath $executable `
            -ArgumentList $arguments `
            -WindowStyle Hidden `
            -PassThru
    }
    Start-Sleep -Seconds 2
    $failed = @($processes | Where-Object { $_.HasExited })
    if ($failed.Count -gt 0) {
        throw "One or more Feishu live components failed startup validation."
    }
    $ids = ($processes | ForEach-Object { $_.Id }) -join ", "
    Write-Output "LabCourt Feishu live components started. Process IDs: $ids"
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
