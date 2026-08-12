Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $reason = Read-Host "Student appeal reason"
    $confirmation = Read-Host "Type APPLY to submit this student appeal"
    if ($confirmation -cne "APPLY") {
        throw "Explicit student appeal confirmation was not supplied."
    }
    & $executable demo student-appeal --output $output --reason $reason --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo student appeal failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
