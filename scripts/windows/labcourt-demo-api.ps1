Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    & $executable demo api --output $output --port 8877 --check
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo API check failed with exit code $LASTEXITCODE."
    }
    & $executable demo api --output $output --port 8877
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo API stopped with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
