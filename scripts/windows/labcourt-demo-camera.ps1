Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    $preferredMedia = Join-Path $projectRoot "inputs\goggles-missing.mp4"
    if (Test-Path -LiteralPath $preferredMedia -PathType Leaf) {
        $media = Get-Item -LiteralPath $preferredMedia
    }
    else {
        $media = Get-ChildItem -LiteralPath (Join-Path $projectRoot "inputs") -File -Filter "*.mp4" |
            Sort-Object -Property Name |
            Select-Object -First 1
    }
    if ($null -eq $media) {
        throw "No authorized MP4 was found under inputs."
    }
    & $executable demo camera-register --output $output
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo camera registration failed with exit code $LASTEXITCODE."
    }
    & $executable demo media-bind --input $media.FullName --output $output
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo media binding failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
