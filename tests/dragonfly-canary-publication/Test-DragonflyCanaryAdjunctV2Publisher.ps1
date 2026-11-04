# Contract-only V2 publication proof: two immutable releases must coexist.
# Runs against synthetic temporary folders; never under protected LDW ProgramData.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$legacy = Import-Module (Join-Path $repo 'ci-dispatch/DragonflyCanaryAdjunctPublisher.psm1') -Force -PassThru
$v2 = Import-Module (Join-Path $repo 'ci-dispatch/DragonflyCanaryAdjunctV2Publisher.psm1') -Force -PassThru

function Assert-True([bool]$Ok,[string]$Classification) {
    if (-not $Ok) { throw $Classification }
}
function Assert-ThrowsExact([scriptblock]$Action,[string]$Expected) {
    $actual = $null
    try { & $Action | Out-Null }
    catch { $actual = [string]$_.Exception.Message }
    if ($actual -cne $Expected) { throw ('V2_WRONG_FAILURE:' + $Expected + ':' + $actual) }
}

$exports = @(Get-Command -Module $v2.Name | Select-Object -ExpandProperty Name | Sort-Object)
Assert-True ($exports.Count -eq 2 -and
    -not @(Compare-Object @('Publish-LdwDragonflyCanaryAdjunctV2','Test-LdwDragonflyCanaryAdjunctV2') $exports -CaseSensitive).Count) 'ADJUNCT_V2_EXPORT_SURFACE_INVALID'
$releaseId = '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca-feca05f0efecf29f4bf58d251c6da5d71c7c2750'
$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-adjunct-v2-contract-' + [guid]::NewGuid().ToString('N'))

try {
    # Publish and validate the pre-existing V1 package in a disposable directory.
    $old = & $legacy {
        param($repo,$root)
        New-LdwDragonflyCanaryAdjunctCore -RepositoryRoot $repo -Root $root
    } $repo $root
    Assert-True $old.Published 'V2_LEGACY_SYNTHETIC_PUBLISH_FAILED'
    Assert-True ((Split-Path $old.ReleaseRoot -Leaf) -ceq '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca') 'V2_LEGACY_ID_DRIFT'
    $oldManifestPath = Join-Path $old.ReleaseRoot 'manifest.json'
    $oldManifestHash = (Get-FileHash -LiteralPath $oldManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $oldEntryPath = Join-Path $old.ReleaseRoot 'ci-dispatch/Invoke-DragonflyCanaryProduction.ps1'
    $oldEntryHash = (Get-FileHash -LiteralPath $oldEntryPath -Algorithm SHA256).Hash.ToLowerInvariant()

    # The V2 pin binds the PR #205 corrected entrypoint without touching V1.
    $new = & $v2 {
        param($repo,$root)
        New-LdwDragonflyCanaryAdjunctV2Core -RepositoryRoot $repo -Root $root
    } $repo $root
    Assert-True $new.Published 'V2_FIRST_PUBLISH_FAILED'
    Assert-True ((Split-Path $new.ReleaseRoot -Leaf) -ceq $releaseId) 'V2_RELEASE_ID_INVALID'
    Assert-True ($new.ReleaseRoot -cne $old.ReleaseRoot) 'V2_COLLIDES_WITH_ACCEPTED_RELEASE'
    $newManifest = Get-Content -LiteralPath (Join-Path $new.ReleaseRoot 'manifest.json') -Raw | ConvertFrom-Json
    Assert-True ($newManifest.schema -eq 2 -and
        $newManifest.artifact -ceq 'ldw-dragonfly-canary-adjunct-v2' -and
        $newManifest.releaseIdentity -ceq $releaseId -and
        $newManifest.entryCommit -ceq 'feca05f0efecf29f4bf58d251c6da5d71c7c2750') 'V2_MANIFEST_IDENTITY_INVALID'
    Assert-True ($newManifest.containsCredential -eq $false -and
        $newManifest.containsBootstrap -eq $false -and
        $newManifest.containsPrivateEndpoint -eq $false) 'V2_SECRET_BOUNDARY_INVALID'
    $newEntry = @($newManifest.files | Where-Object path -CEQ 'ci-dispatch/Invoke-DragonflyCanaryProduction.ps1')
    Assert-True ($newEntry.Count -eq 1 -and $newEntry[0].gitBlob -ceq '47d172ac015edfb8f0713c0422d1585b4d2e2ff2') 'V2_ENTRY_BLOB_INVALID'

    $newVerified = & $v2 {
        param($release,$sha)
        Test-LdwDragonflyCanaryAdjunctV2Core -ReleaseRoot $release -ManifestSha256 $sha
    } $new.ReleaseRoot $new.ManifestSha256
    Assert-True $newVerified.Valid 'V2_READBACK_FAILED'

    $second = & $v2 {
        param($repo,$root)
        New-LdwDragonflyCanaryAdjunctV2Core -RepositoryRoot $repo -Root $root
    } $repo $root
    Assert-True ($second.ManifestSha256 -ceq $new.ManifestSha256 -and
        $second.ReleaseRoot -ceq $new.ReleaseRoot) 'V2_IDEMPOTENCE_FAILED'

    # Legacy receipt and entrypoint bytes remain unchanged and still verify.
    Assert-True ((Get-FileHash -LiteralPath $oldManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $oldManifestHash) 'V2_LEGACY_MANIFEST_CHANGED'
    Assert-True ((Get-FileHash -LiteralPath $oldEntryPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $oldEntryHash) 'V2_LEGACY_ENTRY_CHANGED'
    $oldVerified = & $legacy {
        param($release,$sha)
        Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $sha
    } $old.ReleaseRoot $old.ManifestSha256
    Assert-True $oldVerified.Valid 'V2_LEGACY_READBACK_FAILED'

    # A non-identical existing immutable V2 release must be refused, not overwritten.
    $v2EntryPath = Join-Path $new.ReleaseRoot 'ci-dispatch/Invoke-DragonflyCanaryProduction.ps1'
    Add-Content -LiteralPath $v2EntryPath -Value '# synthetic corruption'
    Assert-ThrowsExact {
        & $v2 {
            param($repo,$root)
            New-LdwDragonflyCanaryAdjunctV2Core -RepositoryRoot $repo -Root $root
        } $repo $root
    } 'ADJUNCT_FILE_HASH_DRIFT'
    Assert-True ((Get-FileHash -LiteralPath $oldManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $oldManifestHash) 'V2_COLLISION_MODIFIED_V1'
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Remove-Module $v2.Name -Force -ErrorAction SilentlyContinue
    Remove-Module $legacy.Name -Force -ErrorAction SilentlyContinue
}
'DRAGONFLY_IMMUTABLE_V2_COEXISTENCE=PASS'
