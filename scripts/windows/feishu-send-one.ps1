Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

try {
    & (Join-Path $PSScriptRoot "feishu-preflight.ps1") -Scope Outbox
    if ($LASTEXITCODE -ne 0) { throw "Outbox preflight failed; no message was sent." }
    $confirmation = Read-Host "Preflight passed. Type SEND to make exactly one sandbox delivery attempt"
    if ($confirmation -cne "SEND") { throw "Explicit send confirmation was not supplied." }

    $config = Read-LabCourtFeishuConfig
    Set-LabCourtFeishuProcessEnvironment -Config $config
    Invoke-LabCourt @(
        "feishu", "outbox-run-one",
        "--database", (Resolve-LabCourtLocalPath $config.runtime.database_path),
        "--notification-id", $config.runtime.notification_id,
        "--candidate-authority-id", $config.runtime.candidate_authority_id,
        "--recipient-binding-authority-id", $config.runtime.recipient_binding_authority_id,
        "--workflow", (Resolve-LabCourtLocalPath $config.runtime.workflow_path),
        "--app-id-env", $config.environment_names.app_id,
        "--app-secret-env", $config.environment_names.app_secret,
        "--receive-id-env", $config.environment_names.test_open_id,
        "--worker-token-env", $config.environment_names.worker_token,
        "--repository-manifest-id", $config.runtime.repository_manifest_id,
        "--assessment-manifest-id", $config.runtime.assessment_manifest_id,
        "--runtime-manifest-id", $config.runtime.runtime_manifest_id
    )
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
