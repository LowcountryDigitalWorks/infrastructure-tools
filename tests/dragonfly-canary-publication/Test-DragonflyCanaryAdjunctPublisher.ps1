$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$modulePath = Join-Path $repo 'ci-dispatch/DragonflyCanaryAdjunctPublisher.psm1'
$module = Import-Module $modulePath -Force -PassThru

function Assert-True {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-ThrowsMessage {
    param([scriptblock]$Action,[string]$Expected,[string]$Message)
    $ok = $false
    try { & $Action } catch { $ok = $_.Exception.Message -ceq $Expected }
    Assert-True $ok $Message
}

$exports = @(Get-Command -Module $module.Name | Select-Object -ExpandProperty Name | Sort-Object)
Assert-True ($exports.Count -eq 2) 'ADJUNCT_EXPORT_COUNT_INVALID'
Assert-True (-not @(Compare-Object @('Publish-LdwDragonflyCanaryAdjunct','Test-LdwDragonflyCanaryAdjunct') $exports -CaseSensitive).Count) 'ADJUNCT_EXPORT_SURFACE_INVALID'

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-adjunct-test-' + [guid]::NewGuid().ToString('N'))
try {
    $first = & $module { param($RepositoryRoot,$Root) New-LdwDragonflyCanaryAdjunctCore -RepositoryRoot $RepositoryRoot -Root $Root } $repo $root
    Assert-True $first.Published 'ADJUNCT_FIRST_PUBLISH_FAILED'
    Assert-True ($first.CanaryCommit -ceq '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca') 'ADJUNCT_CANARY_COMMIT_INVALID'
    Assert-True ($first.ManifestSha256 -cmatch '^[a-f0-9]{64}$') 'ADJUNCT_MANIFEST_SHA_INVALID'

    $manifestPath = Join-Path $first.ReleaseRoot 'manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Assert-True ($manifest.schema -eq 1) 'ADJUNCT_SCHEMA_INVALID'
    Assert-True ($manifest.artifact -ceq 'ldw-dragonfly-canary-adjunct-v1') 'ADJUNCT_ARTIFACT_INVALID'
    Assert-True (@($manifest.files).Count -eq 4) 'ADJUNCT_FILE_COUNT_INVALID'
    Assert-True ($manifest.containsCredential -eq $false -and $manifest.containsBootstrap -eq $false -and $manifest.containsPrivateEndpoint -eq $false) 'ADJUNCT_SECRET_BOUNDARY_INVALID'
    Assert-True ($manifest.dispatchAuthority.blob -ceq 'c862dd503b98060ec984206e63ef9efa5f957e8f') 'ADJUNCT_DISPATCH_BLOB_INVALID'
    Assert-True ($manifest.dispatchAuthority.rawSha256 -ceq '76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675') 'ADJUNCT_DISPATCH_RAW_SHA_INVALID'
    Assert-True ($manifest.dispatchAuthority.windowsSha256 -ceq '0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72') 'ADJUNCT_DISPATCH_WINDOWS_SHA_INVALID'

    $dispatch = Join-Path $first.ReleaseRoot 'ci-dispatch/Dispatch.psm1'
    Assert-True ((Get-FileHash -LiteralPath $dispatch -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $manifest.dispatchAuthority.windowsSha256) 'ADJUNCT_DISPATCH_MATERIALIZATION_INVALID'
    $currentDispatchBlob = (& git -C $repo rev-parse 'HEAD:ci-dispatch/Dispatch.psm1').Trim()
    Assert-True ($currentDispatchBlob -cne $manifest.dispatchAuthority.blob) 'ADJUNCT_CURRENT_DISPATCH_ACCIDENTALLY_ACCEPTED'

    $verified = & $module { param($release,$sha) Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $sha } $first.ReleaseRoot $first.ManifestSha256
    Assert-True $verified.Valid 'ADJUNCT_VERIFY_FAILED'

    $second = & $module { param($RepositoryRoot,$Root) New-LdwDragonflyCanaryAdjunctCore -RepositoryRoot $RepositoryRoot -Root $Root } $repo $root
    Assert-True ($second.ManifestSha256 -ceq $first.ManifestSha256) 'ADJUNCT_IDEMPOTENT_MANIFEST_DRIFT'

    $entry = Join-Path $first.ReleaseRoot 'ci-dispatch/Invoke-DragonflyCanaryProduction.ps1'
    Add-Content -LiteralPath $entry -Value '# tamper'
    Assert-ThrowsMessage {
        & $module { param($release,$sha) Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $sha } $first.ReleaseRoot $first.ManifestSha256 | Out-Null
    } 'ADJUNCT_FILE_HASH_DRIFT' 'ADJUNCT_TAMPER_NOT_REFUSED'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Module $module.Name -Force -ErrorAction SilentlyContinue
}

'DRAGONFLY_CANARY_ADJUNCT_PUBLISHER_CONTRACT=PASS'
