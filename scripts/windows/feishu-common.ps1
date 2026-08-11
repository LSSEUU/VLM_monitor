Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-LabCourtProjectRoot {
    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
}

function Get-LabCourtExecutable {
    $executable = Join-Path (Get-LabCourtProjectRoot) ".venv\Scripts\labcourt.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "LabCourt virtual environment is missing. Create .venv and install the project first."
    }
    return $executable
}

function Get-LabCourtFeishuConfigPath {
    return Join-Path (Get-LabCourtProjectRoot) ".labcourt-local\feishu-secrets.json"
}

function Assert-LabCourtFeishuConfigIgnored {
    $projectRoot = Get-LabCourtProjectRoot
    Push-Location $projectRoot
    try {
        & git check-ignore --quiet -- ".labcourt-local/feishu-secrets.json"
        if ($LASTEXITCODE -ne 0) {
            throw "Refusing to use local plaintext credentials because the exact file is not Git-ignored."
        }
    }
    finally {
        Pop-Location
    }
}

function Resolve-LabCourtLocalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path (Get-LabCourtProjectRoot) $Path))
}

function Invoke-LabCourt {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & (Get-LabCourtExecutable) @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "LabCourt command failed with exit code $LASTEXITCODE."
    }
}

function Read-LabCourtFeishuConfig {
    Assert-LabCourtFeishuConfigIgnored
    $configPath = Get-LabCourtFeishuConfigPath
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Local Feishu config is missing. Run feishu-setup.cmd first."
    }

    $validationOutput = & (Get-LabCourtExecutable) feishu local-config-check --config $configPath --json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Local Feishu config failed strict validation; no credential value was displayed."
    }
    $null = $validationOutput
    try {
        return Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Local Feishu config could not be loaded after validation."
    }
}

function Set-LabCourtFeishuProcessEnvironment {
    param([Parameter(Mandatory = $true)][object]$Config)

    $mapping = @(
        @($Config.environment_names.app_id, $Config.credentials.app_id),
        @($Config.environment_names.app_secret, $Config.credentials.app_secret),
        @($Config.environment_names.test_open_id, $Config.credentials.test_open_id),
        @($Config.environment_names.encrypt_key, $Config.credentials.encrypt_key),
        @($Config.environment_names.verification_token, $Config.credentials.verification_token),
        @($Config.environment_names.worker_token, $Config.credentials.worker_token)
    )
    foreach ($entry in $mapping) {
        Set-Item -LiteralPath ("Env:" + [string]$entry[0]) -Value ([string]$entry[1])
    }
}

function Assert-LabCourtFeishuArtifacts {
    param(
        [Parameter(Mandatory = $true)][object]$Config,
        [ValidateSet("All", "Webhook", "Outbox")][string]$Scope = "All"
    )

    $paths = @([string]$Config.runtime.database_path)
    if ($Scope -in @("All", "Outbox")) {
        $paths += @(
            [string]$Config.runtime.workflow_path,
            [string]$Config.outbox_activation.activation_intent_path,
            [string]$Config.outbox_activation.runtime_config_path
        )
    }
    if ($Scope -in @("All", "Webhook")) {
        $paths += @(
            [string]$Config.webhook_activation.activation_intent_path,
            [string]$Config.webhook_activation.runtime_config_path
        )
    }
    foreach ($path in $paths) {
        $resolved = Resolve-LabCourtLocalPath $path
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "Required local authority artifact is missing: $path"
        }
    }
}
