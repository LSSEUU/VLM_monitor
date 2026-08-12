Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $target = (Read-Host "Target: EMERGENCY_SMOKE or PPE_CANDIDATE (default EMERGENCY_SMOKE)").ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($target)) {
        $target = "EMERGENCY_SMOKE"
    }
    $action = (Read-Host "Action: CONFIRM, REJECT, REQUEST_EVIDENCE, RETURN_TO_VERIFICATION, or RESOLVE").ToUpperInvariant()
    $reason = Read-Host "Human reason summary"
    $confirmation = Read-Host "Type APPLY to commit this Case action"
    if ($confirmation -cne "APPLY") {
        throw "Explicit Case-action confirmation was not supplied."
    }
    & $executable demo case-action --output $output --target $target --action $action --reason $reason --confirmed
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt personal demo Case action failed with exit code $LASTEXITCODE."
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
