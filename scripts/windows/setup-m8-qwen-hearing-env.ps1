[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,126}[A-Za-z0-9]$')]
    [string]$WorkspaceId = ''
)

$endpoint = $null
if ([string]::IsNullOrWhiteSpace($WorkspaceId)) {
    $screeningEndpoint = [Environment]::GetEnvironmentVariable(
        'LABCOURT_SCREENING_ENDPOINT',
        [EnvironmentVariableTarget]::User
    )
    $beijingWorkspaceEndpoint = '^https://[A-Za-z0-9][A-Za-z0-9-]{0,126}[A-Za-z0-9]\.cn-beijing\.maas\.aliyuncs\.com/compatible-mode/v1/chat/completions$'
    if ($screeningEndpoint -notmatch $beijingWorkspaceEndpoint) {
        throw 'No reusable Beijing L3 endpoint was found; rerun with -WorkspaceId.'
    }
    $endpoint = $screeningEndpoint
}
else {
    $endpoint = "https://$WorkspaceId.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
}

$secureKey = Read-Host 'New Alibaba Cloud Model Studio API key for M8 hearing' -AsSecureString
$keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
    $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
    if ([string]::IsNullOrWhiteSpace($plainKey)) {
        throw 'The M8 Qwen API key cannot be empty.'
    }

    [Environment]::SetEnvironmentVariable(
        'LABCOURT_QWEN_ENDPOINT',
        $endpoint,
        [EnvironmentVariableTarget]::User
    )
    [Environment]::SetEnvironmentVariable(
        'LABCOURT_QWEN_API_KEY',
        $plainKey,
        [EnvironmentVariableTarget]::User
    )

    [pscustomobject]@{
        kind = 'READY'
        scope = 'CURRENT_USER'
        endpoint_variable = 'LABCOURT_QWEN_ENDPOINT'
        api_key_variable = 'LABCOURT_QWEN_API_KEY'
        api_key_value_exposed = $false
    } | ConvertTo-Json -Compress
}
finally {
    if ($keyPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
    }
    $plainKey = $null
    $secureKey = $null
}
