Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    & $executable demo bootstrap --output (Join-Path $projectRoot ".labcourt-local\labcourt-demo")
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo bootstrap failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
