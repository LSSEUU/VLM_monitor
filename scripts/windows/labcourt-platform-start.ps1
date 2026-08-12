Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-platform-demo"
    $media = Join-Path $projectRoot "inputs\goggles-missing.mp4"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    if (-not (Test-Path -LiteralPath $media -PathType Leaf)) {
        throw "The authorized inputs\goggles-missing.mp4 recording was not found."
    }

    & $executable demo platform --output $output --input $media --port 8877 --check
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform preflight failed. Exit code: $LASTEXITCODE."
    }
    Start-Process "http://127.0.0.1:8877/login"
    & $executable demo platform --output $output --input $media --port 8877
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform stopped unexpectedly. Exit code: $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
