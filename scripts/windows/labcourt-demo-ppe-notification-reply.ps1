Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $kind = (Read-Host "Reply kind (EXPLANATION or APPEAL_REQUEST)").ToUpperInvariant()
    if ($kind -notin @("EXPLANATION", "APPEAL_REQUEST")) {
        throw "Reply kind must be EXPLANATION or APPEAL_REQUEST."
    }
    $replyText = Read-Host "Student reply text"
    $confirmation = Read-Host "Type APPLY to submit this student notification reply"
    if ($confirmation -cne "APPLY") {
        throw "Explicit student reply confirmation was not supplied."
    }
    & $executable demo ppe-notification-reply --output $output --kind $kind --text $replyText --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo student notification reply failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
