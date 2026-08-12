param(
    [switch]$ConfigureOnly,
    [switch]$FullAuthority
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "feishu-common.ps1")

function Read-RequiredValue {
    param([Parameter(Mandatory = $true)][string]$Prompt)

    $value = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Prompt is required."
    }
    return $value
}

function Read-ValueWithDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$Default
    )

    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Read-RequiredSecret {
    param([Parameter(Mandatory = $true)][string]$Prompt)

    $secure = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ([string]::IsNullOrWhiteSpace($value)) { throw "$Prompt is required." }
        return $value
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

try {
    Assert-LabCourtFeishuConfigIgnored
    $configPath = Get-LabCourtFeishuConfigPath
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $answer = Read-Host "Local plaintext config already exists. Type REPLACE to overwrite it"
        if ($answer -cne "REPLACE") { throw "Configuration was not replaced." }
    }

    $localDirectory = Split-Path -Parent $configPath
    $null = New-Item -ItemType Directory -Path $localDirectory -Force
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls $localDirectory /inheritance:r /grant:r "*${sid}:(OI)(CI)(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not restrict the local credential directory ACL; no config was written."
    }

    Write-Host "PERSONAL DEMO only. Values are stored as local plaintext and are never printed."
    $appId = Read-RequiredSecret "Feishu App ID"
    $appSecret = Read-RequiredSecret "Feishu App Secret"
    $testOpenId = Read-RequiredSecret "Test recipient Open ID"
    $encryptKey = $null
    $verificationToken = $null
    if ($FullAuthority) {
        $encryptKey = Read-RequiredSecret "Feishu Encrypt Key"
        $verificationToken = Read-RequiredSecret "Feishu Verification Token"
    }
    $randomBytes = New-Object byte[] 32
    $randomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $randomGenerator.GetBytes($randomBytes) }
    finally { $randomGenerator.Dispose() }
    $workerToken = [Convert]::ToBase64String($randomBytes)

    $runtime = $null
    $outboxActivation = $null
    $webhookActivation = $null
    if ($FullAuthority) {
        $databasePath = Read-ValueWithDefault "SQLite authority path" ".labcourt-local/labcourt.sqlite3"
        $workflowPath = Read-ValueWithDefault "Notification workflow path" ".labcourt-local/notification-workflow.json"
        $outboxIntent = Read-ValueWithDefault "Outbox activation intent path" ".labcourt-local/outbox-activation-intent.json"
        $outboxRuntime = Read-ValueWithDefault "Outbox runtime config path" ".labcourt-local/outbox-runtime-config.json"
        $webhookIntent = Read-ValueWithDefault "Webhook activation intent path" ".labcourt-local/webhook-activation-intent.json"
        $webhookRuntime = Read-ValueWithDefault "Webhook runtime config path" ".labcourt-local/webhook-runtime-config.json"
        $runtime = [ordered]@{
            database_path = $databasePath
            candidate_authority_id = Read-RequiredValue "Candidate authority ID (64 hex)"
            recipient_binding_authority_id = Read-RequiredValue "Recipient binding authority ID (64 hex)"
            notification_id = Read-RequiredValue "Test notification ID (64 hex)"
            workflow_path = $workflowPath
            repository_manifest_id = Read-RequiredValue "Repository manifest ID (64 hex)"
            assessment_manifest_id = Read-RequiredValue "Assessment manifest ID (64 hex)"
            runtime_manifest_id = Read-RequiredValue "Runtime manifest ID (64 hex)"
        }
        $outboxActivation = [ordered]@{
            activation_intent_path = $outboxIntent
            runtime_config_path = $outboxRuntime
            runtime_config_storage_manifest_id = Read-RequiredValue "Outbox runtime-config storage manifest ID (64 hex)"
        }
        $webhookActivation = [ordered]@{
            activation_intent_path = $webhookIntent
            runtime_config_path = $webhookRuntime
            runtime_config_storage_manifest_id = Read-RequiredValue "Webhook runtime-config storage manifest ID (64 hex)"
        }
    }

    $config = [ordered]@{
        schema_version = "m8-feishu-local-demo-config-v1"
        display_badge = "PERSONAL DEMO $([char]0x00B7) LOCAL PLAINTEXT CREDENTIALS"
        credentials = [ordered]@{
            app_id = $appId; app_secret = $appSecret; test_open_id = $testOpenId
            encrypt_key = $encryptKey; verification_token = $verificationToken
            worker_token = $workerToken
        }
        environment_names = [ordered]@{
            app_id = "LABCOURT_FEISHU_APP_ID"; app_secret = "LABCOURT_FEISHU_APP_SECRET"
            test_open_id = "LABCOURT_FEISHU_TEST_OPEN_ID"; encrypt_key = "LABCOURT_FEISHU_ENCRYPT_KEY"
            verification_token = "LABCOURT_FEISHU_VERIFICATION_TOKEN"; worker_token = "LABCOURT_FEISHU_WORKER_TOKEN"
        }
        runtime = $runtime
        outbox_activation = $outboxActivation
        webhook_activation = $webhookActivation
        personal_demo_only = $true
        plaintext_credentials_persisted_locally = $true
        default_preflight_required = $true
        public_https_managed_by_scripts = $false
        automatic_send_permitted = $false
        production_ready = $false
        case_transition_permitted = $false
        direct_disciplinary_action_permitted = $false
    }

    $temporaryPath = "$configPath.tmp"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temporaryPath, ($config | ConvertTo-Json -Depth 8), $encoding)
    Move-Item -LiteralPath $temporaryPath -Destination $configPath -Force
    Remove-Variable appId, appSecret, testOpenId, encryptKey, verificationToken, workerToken, config -ErrorAction SilentlyContinue

    $null = Read-LabCourtFeishuConfig
    Write-Host "Local config passed strict validation. Credential values were not displayed."
    if (-not $ConfigureOnly) {
        if ($FullAuthority) {
            & (Join-Path $PSScriptRoot "feishu-preflight.ps1") -Scope All
            if ($LASTEXITCODE -ne 0) { throw "Default authority preflight failed." }
        }
        else {
            Invoke-LabCourt @(
                "feishu", "demo-card", "--check", "--config", $configPath
            )
            Write-Host "Quick PERSONAL DEMO preflight passed. No network call was made."
        }
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
