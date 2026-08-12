Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

try {
    $configPath = Get-LabCourtFeishuConfigPath
    $null = Read-LabCourtFeishuConfig
    Invoke-LabCourt @(
        "feishu", "demo-emergency", "--check", "--config", $configPath
    )
    $confirmation = Read-Host "Offline smoke scenario passed. Type SEND to send one SIMULATED EMERGENCY card"
    if ($confirmation -cne "SEND") {
        throw "Explicit simulated-emergency confirmation was not supplied."
    }
    Invoke-LabCourt @(
        "feishu", "demo-emergency", "--confirmed", "--config", $configPath,
        "--output", (Join-Path (Get-LabCourtProjectRoot) ".labcourt-local\feishu-emergency-demo-runs")
    )
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
