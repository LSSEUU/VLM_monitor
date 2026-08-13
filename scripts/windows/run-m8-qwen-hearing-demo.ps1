[CmdletBinding()]
param(
    [string]$Output = '.labcourt-local/m8-qwen-hearing-demo',

    [ValidateRange(0, 65535)]
    [int]$Port = 0
)

function Import-LabCourtUserEnvironmentVariable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $processValue = [Environment]::GetEnvironmentVariable(
        $Name,
        [EnvironmentVariableTarget]::Process
    )
    if (-not [string]::IsNullOrWhiteSpace($processValue)) {
        return $false
    }
    $userValue = [Environment]::GetEnvironmentVariable(
        $Name,
        [EnvironmentVariableTarget]::User
    )
    if ([string]::IsNullOrWhiteSpace($userValue)) {
        throw "Required user environment variable is missing: $Name"
    }
    [Environment]::SetEnvironmentVariable(
        $Name,
        $userValue,
        [EnvironmentVariableTarget]::Process
    )
    return $true
}

$importedEndpoint = $false
$importedApiKey = $false
try {
    $importedEndpoint = Import-LabCourtUserEnvironmentVariable 'LABCOURT_QWEN_ENDPOINT'
    $importedApiKey = Import-LabCourtUserEnvironmentVariable 'LABCOURT_QWEN_API_KEY'
    uv run --locked labcourt hearing qwen-demo run --confirmed --output $Output --port $Port
    exit $LASTEXITCODE
}
finally {
    if ($importedEndpoint) {
        Remove-Item Env:LABCOURT_QWEN_ENDPOINT -ErrorAction SilentlyContinue
    }
    if ($importedApiKey) {
        Remove-Item Env:LABCOURT_QWEN_API_KEY -ErrorAction SilentlyContinue
    }
}
