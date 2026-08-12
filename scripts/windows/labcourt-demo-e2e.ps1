Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-LabCourtStep {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE."
    }
}

function Require-Apply {
    param([Parameter(Mandatory = $true)][string]$Prompt)
    if ((Read-Host $Prompt) -cne "APPLY") {
        throw "Explicit human confirmation was not supplied."
    }
}

$apiProcess = $null
try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }
    $runName = "run-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss-fff")
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-e2e-runs\$runName"
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    Invoke-LabCourtStep $executable @("demo", "bootstrap", "--output", $output) `
        "Demo bootstrap failed."
    Invoke-LabCourtStep $executable @("demo", "camera-register", "--output", $output) `
        "Camera registration failed."
    $preferredMedia = Join-Path $projectRoot "inputs\goggles-missing.mp4"
    if (Test-Path -LiteralPath $preferredMedia -PathType Leaf) {
        $media = Get-Item -LiteralPath $preferredMedia
    }
    else {
        $media = Get-ChildItem -LiteralPath (Join-Path $projectRoot "inputs") -File -Filter "*.mp4" |
            Sort-Object -Property Name | Select-Object -First 1
    }
    if ($null -eq $media) { throw "No MP4 was found under inputs." }
    Invoke-LabCourtStep $executable @("demo", "media-bind", "--input", $media.FullName, "--output", $output) `
        "Recorded media binding failed."
    Invoke-LabCourtStep $executable @("demo", "ppe-case-create", "--output", $output) `
        "PPE candidate creation failed."
    Invoke-LabCourtStep $executable @("demo", "api", "--output", $output, "--port", "18877", "--check") `
        "API preflight failed."

    $port = 18877
    $apiProcess = Start-Process -FilePath $executable -ArgumentList @(
        "demo", "api", "--output", $output, "--port", "$port"
    ) -PassThru -WindowStyle Hidden
    $access = Get-Content -LiteralPath (Join-Path $output "api-access.json") -Raw | ConvertFrom-Json
    $baseUrl = "http://127.0.0.1:$port"
    $ready = $false
    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        try {
            Invoke-RestMethod -Uri "$baseUrl/api/m8/session" -Headers @{
                Authorization = "Bearer $($access.tokens.safety)"
            } | Out-Null
            $ready = $true
            break
        }
        catch {
            if ($apiProcess.HasExited) { throw "Demo API exited during startup." }
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $ready) { throw "Demo API did not become ready." }

    Require-Apply "Safety officer: type APPLY to confirm the PPE candidate"
    Invoke-LabCourtStep $executable @(
        "demo", "case-action", "--output", $output, "--target", "PPE_CANDIDATE",
        "--action", "CONFIRM", "--reason", "Safety officer verified the PPE Demo candidate.",
        "--confirmed"
    ) "PPE confirmation failed."
    Invoke-LabCourtStep $executable @("demo", "ppe-notification-route", "--output", $output) `
        "Student notification routing failed."
    Invoke-LabCourtStep $executable @("demo", "ppe-notification-deliver", "--output", $output) `
        "Student notification delivery failed."

    $explanation = Read-Host "Student explanation"
    Require-Apply "Student: type APPLY to submit this explanation"
    Invoke-LabCourtStep $executable @(
        "demo", "ppe-notification-reply", "--output", $output, "--kind", "EXPLANATION",
        "--text", $explanation, "--confirmed"
    ) "Student explanation failed."
    $appealReason = Read-Host "Student appeal reason"
    Require-Apply "Student: type APPLY to submit the appeal"
    Invoke-LabCourtStep $executable @(
        "demo", "student-appeal", "--output", $output, "--reason", $appealReason, "--confirmed"
    ) "Student appeal failed."

    $resolution = (Read-Host "Safety resolution (UPHELD or OVERTURNED)").ToUpperInvariant()
    if ($resolution -notin @("UPHELD", "OVERTURNED")) {
        throw "Resolution must be UPHELD or OVERTURNED."
    }
    $resolutionReason = Read-Host "Safety resolution reason"
    Require-Apply "Safety officer: type APPLY to resolve the appeal and close the Case"
    Invoke-LabCourtStep $executable @(
        "demo", "ppe-appeal-resolve", "--output", $output, "--resolution", $resolution,
        "--reason", $resolutionReason, "--confirmed"
    ) "Appeal resolution failed."
    Invoke-LabCourtStep $executable @("demo", "ppe-outcome-notification-route", "--output", $output) `
        "Outcome notification routing failed."
    Invoke-LabCourtStep $executable @("demo", "ppe-outcome-notification-deliver", "--output", $output) `
        "Outcome notification delivery failed."
    Require-Apply "Student: type APPLY to acknowledge the final appeal outcome"
    Invoke-LabCourtStep $executable @(
        "demo", "ppe-outcome-notification-acknowledge", "--output", $output, "--confirmed"
    ) "Outcome acknowledgement failed."

    $safetyHeaders = @{ Authorization = "Bearer $($access.tokens.safety)" }
    $studentHeaders = @{ Authorization = "Bearer $($access.tokens.student)" }
    $caseReceipt = Get-Content -LiteralPath (Join-Path $output "ppe-case-receipt.json") -Raw |
        ConvertFrom-Json
    $finalCase = Invoke-RestMethod -Uri "$baseUrl/api/m8/cases/$($caseReceipt.case_id)" `
        -Headers $studentHeaders
    $studentNotifications = Invoke-RestMethod -Uri "$baseUrl/api/m8/notifications" `
        -Headers $studentHeaders
    $users = Invoke-RestMethod -Uri "$baseUrl/api/m8/users" -Headers $safetyHeaders
    $rules = Invoke-RestMethod -Uri "$baseUrl/api/m8/rules" -Headers $safetyHeaders
    $sensors = Invoke-RestMethod -Uri "$baseUrl/api/m8/campuses/campus-demo/sensors" `
        -Headers $safetyHeaders
    $health = Invoke-RestMethod -Uri "$baseUrl/api/m8/campuses/campus-demo/device-health" `
        -Headers $safetyHeaders
    if ($finalCase.status -ne "APPEAL_RESOLVED") { throw "Final Case status gate failed." }
    if ($studentNotifications.Count -ne 2) { throw "Student notification count gate failed." }
    if ($users.Count -ne 4) { throw "User permission inventory gate failed." }
    if ($rules.rules.Count -lt 1) { throw "Rule configuration gate failed." }
    if ($sensors.Count -lt 1 -or $health.Count -lt $sensors.Count) {
        throw "Device health and sensor discovery gate failed."
    }
    $acceptance = [ordered]@{
        schema_version = "labcourt-personal-demo-e2e-acceptance-v1"
        run_name = $runName
        final_case_status = $finalCase.status
        outcome_notification_status = "ACKNOWLEDGED"
        student_notification_count = $studentNotifications.Count
        user_count = $users.Count
        rule_count = $rules.rules.Count
        sensor_count = $sensors.Count
        device_health_count = $health.Count
        default_network_mode = "LOOPBACK_ONLY"
        feishu_send_attempted = $false
        direct_disciplinary_action_permitted = $false
    }
    $acceptance | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output "acceptance.json") `
        -Encoding utf8
    Write-Host "LabCourt PERSONAL DEMO E2E ACCEPTED. Artifacts: $output"
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
finally {
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
