Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

try {
    $configPath = Get-LabCourtFeishuConfigPath
    $null = Read-LabCourtFeishuConfig
    Invoke-LabCourt @(
        "feishu", "demo-card", "--check", "--config", $configPath
    )
    $confirmation = Read-Host "Local check passed. Type SEND to send one PERSONAL DEMO card"
    if ($confirmation -cne "SEND") {
        throw "Explicit demo-card confirmation was not supplied."
    }
    Invoke-LabCourt @(
        "feishu", "demo-card", "--confirmed", "--config", $configPath,
        "--output", (Join-Path (Get-LabCourtProjectRoot) ".labcourt-local\feishu-demo-runs")
    )
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
