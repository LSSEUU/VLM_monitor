Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $confirmation = Read-Host "Local notification is DELIVERED. Type APPLY to acknowledge as safety officer"
    if ($confirmation -cne "APPLY") {
        throw "Acknowledgement cancelled; exact APPLY confirmation was not provided."
    }
    & $executable demo notification-acknowledge --output (Join-Path $projectRoot ".labcourt-local\labcourt-demo") --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo notification acknowledgement failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
