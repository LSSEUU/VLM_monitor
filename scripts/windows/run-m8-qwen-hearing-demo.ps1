[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,126}[A-Za-z0-9]$')]
    [string]$WorkspaceId,

    [string]$Output = '.labcourt-local/m8-qwen-hearing-demo',

    [ValidateRange(0, 65535)]
    [int]$Port = 0
)

$secureKey = Read-Host 'Alibaba Cloud Model Studio API key' -AsSecureString
$keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
    $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
    $env:LABCOURT_QWEN_ENDPOINT = "https://$WorkspaceId.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
    $env:LABCOURT_QWEN_API_KEY = $plainKey
    uv run --locked labcourt hearing qwen-demo run --confirmed --output $Output --port $Port
    exit $LASTEXITCODE
}
finally {
    Remove-Item Env:LABCOURT_QWEN_ENDPOINT -ErrorAction SilentlyContinue
    Remove-Item Env:LABCOURT_QWEN_API_KEY -ErrorAction SilentlyContinue
    if ($keyPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
    }
    $plainKey = $null
    $secureKey = $null
}
