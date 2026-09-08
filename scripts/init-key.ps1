$ErrorActionPreference = 'Stop'
$taskSecretDirectory = Join-Path $PSScriptRoot '..\secrets'
$taskKeyPath = Join-Path $taskSecretDirectory 'config.key'
New-Item -ItemType Directory -Force -Path $taskSecretDirectory | Out-Null
if (Test-Path -LiteralPath $taskKeyPath) {
    Write-Output 'Preserved existing encryption key.'
    exit 0
}
$taskKeyBytes = New-Object byte[] 32
$taskRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $taskRandom.GetBytes($taskKeyBytes) } finally { $taskRandom.Dispose() }
$taskEncodedKey = [Convert]::ToBase64String($taskKeyBytes).Replace('+', '-').Replace('/', '_')
[System.IO.File]::WriteAllText($taskKeyPath, $taskEncodedKey, (New-Object System.Text.UTF8Encoding $false))
Write-Output 'Created secrets/config.key. Keep this key private and back it up separately from the data volume.'
