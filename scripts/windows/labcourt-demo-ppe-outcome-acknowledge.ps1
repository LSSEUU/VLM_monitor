Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $confirmation = Read-Host "Type APPLY to acknowledge the final PPE appeal outcome as the student"
    if ($confirmation -cne "APPLY") {
        throw "Explicit student acknowledgement was not supplied."
    }
    & $executable demo ppe-outcome-notification-acknowledge --output (Join-Path $projectRoot ".labcourt-local\labcourt-demo") --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo PPE outcome acknowledgement failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
