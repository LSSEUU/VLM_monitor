Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $resolution = (Read-Host "Appeal resolution (UPHELD or OVERTURNED)").ToUpperInvariant()
    if ($resolution -notin @("UPHELD", "OVERTURNED")) {
        throw "Appeal resolution must be UPHELD or OVERTURNED."
    }
    $reason = Read-Host "Safety officer resolution reason"
    $confirmation = Read-Host "Type APPLY to resolve this appeal and close the Case"
    if ($confirmation -cne "APPLY") {
        throw "Explicit safety-officer confirmation was not supplied."
    }
    & $executable demo ppe-appeal-resolve --output $output --resolution $resolution --reason $reason --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo PPE appeal resolution failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
