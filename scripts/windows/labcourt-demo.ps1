[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet(
        "api",
        "bootstrap",
        "camera",
        "case-action",
        "notification",
        "notification-deliver",
        "notification-acknowledge",
        "ppe-case",
        "ppe-notification",
        "ppe-notification-deliver",
        "ppe-notification-reply",
        "ppe-appeal-resolve",
        "ppe-outcome-notification",
        "ppe-outcome-deliver",
        "ppe-outcome-acknowledge",
        "student-appeal"
    )]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-LabCourt {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )
    & $executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE."
    }
}

function Require-Apply {
    param([Parameter(Mandatory = $true)][string]$Prompt)
    if ((Read-Host $Prompt) -cne "APPLY") {
        throw "Explicit APPLY confirmation was not supplied."
    }
}

try {
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $executable = Join-Path $projectRoot ".venv\Scripts\labcourt.exe"
    $output = Join-Path $projectRoot ".labcourt-local\labcourt-demo"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt executable was not found. Run uv sync --all-groups --locked first."
    }

    switch ($Action) {
        "api" {
            Invoke-LabCourt @("demo", "api", "--output", $output, "--port", "8877", "--check") "LabCourt personal demo API check failed."
            Invoke-LabCourt @("demo", "api", "--output", $output, "--port", "8877") "LabCourt personal demo API stopped."
        }
        "bootstrap" {
            Invoke-LabCourt @("demo", "bootstrap", "--output", $output) "LabCourt personal demo bootstrap failed."
        }
        "camera" {
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
            Invoke-LabCourt @("demo", "camera-register", "--output", $output) "LabCourt personal demo camera registration failed."
            Invoke-LabCourt @("demo", "media-bind", "--input", $media.FullName, "--output", $output) "LabCourt personal demo media binding failed."
        }
        "case-action" {
            $target = (Read-Host "Target: EMERGENCY_SMOKE or PPE_CANDIDATE (default EMERGENCY_SMOKE)").ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($target)) { $target = "EMERGENCY_SMOKE" }
            $caseAction = (Read-Host "Action: CONFIRM, REJECT, REQUEST_EVIDENCE, RETURN_TO_VERIFICATION, or RESOLVE").ToUpperInvariant()
            $reason = Read-Host "Human reason summary"
            Require-Apply "Type APPLY to commit this Case action"
            Invoke-LabCourt @("demo", "case-action", "--output", $output, "--target", $target, "--action", $caseAction, "--reason", $reason, "--confirmed") "LabCourt personal demo Case action failed."
        }
        "notification" {
            Invoke-LabCourt @("demo", "notification-route", "--output", $output) "LabCourt personal demo notification routing failed."
        }
        "notification-deliver" {
            Invoke-LabCourt @("demo", "notification-deliver", "--output", $output) "LabCourt personal demo notification delivery failed."
        }
        "notification-acknowledge" {
            Require-Apply "Local notification is DELIVERED. Type APPLY to acknowledge as safety officer"
            Invoke-LabCourt @("demo", "notification-acknowledge", "--output", $output, "--confirmed") "LabCourt personal demo notification acknowledgement failed."
        }
        "ppe-case" {
            Invoke-LabCourt @("demo", "ppe-case-create", "--output", $output) "LabCourt personal demo PPE candidate Case creation failed."
        }
        "ppe-notification" {
            Invoke-LabCourt @("demo", "ppe-notification-route", "--output", $output) "LabCourt personal demo PPE student notification routing failed."
        }
        "ppe-notification-deliver" {
            Invoke-LabCourt @("demo", "ppe-notification-deliver", "--output", $output) "LabCourt personal demo PPE student notification delivery failed."
        }
        "ppe-notification-reply" {
            $kind = (Read-Host "Reply kind (EXPLANATION or APPEAL_REQUEST)").ToUpperInvariant()
            if ($kind -notin @("EXPLANATION", "APPEAL_REQUEST")) { throw "Reply kind must be EXPLANATION or APPEAL_REQUEST." }
            $replyText = Read-Host "Student reply text"
            Require-Apply "Type APPLY to submit this student notification reply"
            Invoke-LabCourt @("demo", "ppe-notification-reply", "--output", $output, "--kind", $kind, "--text", $replyText, "--confirmed") "LabCourt personal demo student notification reply failed."
        }
        "ppe-appeal-resolve" {
            $resolution = (Read-Host "Appeal resolution (UPHELD or OVERTURNED)").ToUpperInvariant()
            if ($resolution -notin @("UPHELD", "OVERTURNED")) { throw "Appeal resolution must be UPHELD or OVERTURNED." }
            $reason = Read-Host "Safety officer resolution reason"
            Require-Apply "Type APPLY to resolve this appeal and close the Case"
            Invoke-LabCourt @("demo", "ppe-appeal-resolve", "--output", $output, "--resolution", $resolution, "--reason", $reason, "--confirmed") "LabCourt personal demo PPE appeal resolution failed."
        }
        "ppe-outcome-notification" {
            Invoke-LabCourt @("demo", "ppe-outcome-notification-route", "--output", $output) "LabCourt personal demo PPE outcome notification routing failed."
        }
        "ppe-outcome-deliver" {
            Invoke-LabCourt @("demo", "ppe-outcome-notification-deliver", "--output", $output) "LabCourt personal demo PPE outcome delivery failed."
        }
        "ppe-outcome-acknowledge" {
            Require-Apply "Type APPLY to acknowledge the final PPE appeal outcome as the student"
            Invoke-LabCourt @("demo", "ppe-outcome-notification-acknowledge", "--output", $output, "--confirmed") "LabCourt personal demo PPE outcome acknowledgement failed."
        }
        "student-appeal" {
            $reason = Read-Host "Student appeal reason"
            Require-Apply "Type APPLY to submit this student appeal"
            Invoke-LabCourt @("demo", "student-appeal", "--output", $output, "--reason", $reason, "--confirmed") "LabCourt personal demo student appeal failed."
        }
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
