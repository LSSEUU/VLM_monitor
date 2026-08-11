Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-LabCourtStep {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE."
    }
}

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }

    Invoke-LabCourtStep $executable @("demo", "bootstrap", "--output", $output) `
        "LabCourt personal demo bootstrap failed."
    Invoke-LabCourtStep $executable @("demo", "camera-register", "--output", $output) `
        "LabCourt personal demo camera registration failed."

    $routeReceipt = Join-Path $output "notification-route-receipt.json"
    if (-not (Test-Path -LiteralPath $routeReceipt -PathType Leaf)) {
        Invoke-LabCourtStep $executable @("demo", "notification-route", "--output", $output) `
            "LabCourt personal demo notification routing failed."
    }
    $deliveryReceipt = Join-Path $output "notification-delivery-receipt.json"
    $acknowledgementReceipt = Join-Path $output "notification-acknowledgement-receipt.json"
    if ((-not (Test-Path -LiteralPath $deliveryReceipt -PathType Leaf)) -and `
        (-not (Test-Path -LiteralPath $acknowledgementReceipt -PathType Leaf))) {
        Invoke-LabCourtStep $executable @("demo", "notification-deliver", "--output", $output) `
            "LabCourt personal demo offline notification delivery failed."
    }

    Invoke-LabCourtStep $executable @("demo", "api", "--output", $output, "--port", "8877", "--check") `
        "LabCourt personal demo API preflight failed."
    Write-Host "LabCourt PERSONAL DEMO is ready. Starting http://127.0.0.1:8877"
    Invoke-LabCourtStep $executable @("demo", "api", "--output", $output, "--port", "8877") `
        "LabCourt personal demo API stopped unexpectedly."
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
