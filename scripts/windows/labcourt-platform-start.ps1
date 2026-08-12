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
    foreach ($name in @(
        "LABCOURT_SCREENING_ENDPOINT",
        "LABCOURT_SCREENING_API_KEY",
        "LABCOURT_SCREENING_MODEL",
        "LABCOURT_SCREENING_REVISION"
    )) {
        if (-not [Environment]::GetEnvironmentVariable($name, "Process")) {
            $userValue = [Environment]::GetEnvironmentVariable($name, "User")
            if ($userValue) {
                [Environment]::SetEnvironmentVariable($name, $userValue, "Process")
            }
        }
    }
    $workerPython = Join-Path $projectRoot ".venv-perception\Scripts\python.exe"
    if (Test-Path -LiteralPath $workerPython -PathType Leaf) {
        [Environment]::SetEnvironmentVariable(
            "LABCOURT_PERCEPTION_PYTHON", $workerPython, "Process"
        )
    }

    & $executable demo platform --output $output --input $media --port 8877 --check
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform preflight failed. Exit code: $LASTEXITCODE."
    }
    Start-Process "http://127.0.0.1:8877/"
    & $executable demo platform --output $output --input $media --port 8877
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt campus platform stopped unexpectedly. Exit code: $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
