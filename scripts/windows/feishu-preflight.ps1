param([ValidateSet("All", "Webhook", "Outbox")][string]$Scope = "All")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

try {
    $config = Read-LabCourtFeishuConfig
    Assert-LabCourtFeishuArtifacts -Config $config -Scope $Scope
    Set-LabCourtFeishuProcessEnvironment -Config $config
    $database = Resolve-LabCourtLocalPath $config.runtime.database_path

    if ($Scope -in @("All", "Outbox")) {
        Invoke-LabCourt @(
            "feishu", "outbox-activate", "--database", $database,
            "--activation-intent", (Resolve-LabCourtLocalPath $config.outbox_activation.activation_intent_path),
            "--runtime-config", (Resolve-LabCourtLocalPath $config.outbox_activation.runtime_config_path),
            "--runtime-config-storage-manifest-id", $config.outbox_activation.runtime_config_storage_manifest_id,
            "--repository-manifest-id", $config.runtime.repository_manifest_id,
            "--assessment-manifest-id", $config.runtime.assessment_manifest_id
        )
        Invoke-LabCourt @(
            "feishu", "outbox-run-one", "--check", "--database", $database,
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

    if ($Scope -in @("All", "Webhook")) {
        Invoke-LabCourt @(
            "feishu", "webhook-activate", "--database", $database,
            "--activation-intent", (Resolve-LabCourtLocalPath $config.webhook_activation.activation_intent_path),
            "--runtime-config", (Resolve-LabCourtLocalPath $config.webhook_activation.runtime_config_path),
            "--runtime-config-storage-manifest-id", $config.webhook_activation.runtime_config_storage_manifest_id,
            "--repository-manifest-id", $config.runtime.repository_manifest_id,
            "--assessment-manifest-id", $config.runtime.assessment_manifest_id
        )
        Invoke-LabCourt @(
            "feishu", "webhook-serve", "--check", "--database", $database,
            "--candidate-authority-id", $config.runtime.candidate_authority_id,
            "--encrypt-key-env", $config.environment_names.encrypt_key,
            "--verification-token-env", $config.environment_names.verification_token,
            "--runtime-manifest-id", $config.runtime.runtime_manifest_id
        )
    }
    Write-Host "Feishu $Scope preflight passed. Check mode made no provider call."
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
