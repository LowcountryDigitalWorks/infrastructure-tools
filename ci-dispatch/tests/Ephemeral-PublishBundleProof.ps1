[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree
)
$ErrorActionPreference = 'Stop'
$repoRoot = (git rev-parse --show-toplevel 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or $repoRoot -cnotmatch '[\\/]infrastructure-tools$') { throw 'PROOF_REPO_ROOT_INVALID' }
$sourcePath = Join-Path $repoRoot 'ci-dispatch/Publish-Bundle.ps1'
$source = Get-Content -LiteralPath $sourcePath -Raw
$instrumented = $source.Replace(
    '$repo = Split-Path $PSScriptRoot -Parent',
    "`$repo = '$($repoRoot.Replace("'","''"))'"
).Replace(
    '$code = [string]$_.Exception.Message',
    '$code = [string]$_.Exception.Message; ''RAW_PUBLISH_ERROR=''+$_.Exception.Message'
)
if ($instrumented -ceq $source) { throw 'PROOF_INSTRUMENTATION_FAILED' }
$tempScript = Join-Path $env:RUNNER_TEMP ('Publish-Bundle-proof-' + [guid]::NewGuid().ToString('N') + '.ps1')
Set-Content -LiteralPath $tempScript -Value $instrumented -Encoding utf8
Push-Location $repoRoot
try {
    & $tempScript -Commit $Commit -Tree $Tree
} finally {
    Pop-Location
    if (Test-Path -LiteralPath $tempScript) { Remove-Item -LiteralPath $tempScript -Force }
}
