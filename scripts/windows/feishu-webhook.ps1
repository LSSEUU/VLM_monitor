Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

try {
    & (Join-Path $PSScriptRoot "feishu-preflight.ps1") -Scope Webhook
    if ($LASTEXITCODE -ne 0) { throw "Webhook preflight failed; server was not started." }
    $config = Read-LabCourtFeishuConfig
    Set-LabCourtFeishuProcessEnvironment -Config $config
    Write-Warning "Loopback webhook only. Public HTTPS/TLS and reverse proxy are not managed by this script."
    Invoke-LabCourt @(
        "feishu", "webhook-serve",
        "--database", (Resolve-LabCourtLocalPath $config.runtime.database_path),
        "--candidate-authority-id", $config.runtime.candidate_authority_id,
        "--encrypt-key-env", $config.environment_names.encrypt_key,
        "--verification-token-env", $config.environment_names.verification_token,
        "--runtime-manifest-id", $config.runtime.runtime_manifest_id
    )
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
