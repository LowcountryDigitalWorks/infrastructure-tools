Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One historical release, not a caller-configurable hash allowlist. Changes require review.
$script:ReleaseCommit = 'ae2c7a564d7ea3d31f4c4961c681ae72d43e5f80'
$script:ReleaseTree = 'b44453f6c2767d2f7c1e845e2f87850461e942f2'
$script:ArchiveSha = '874b26bfe5fee9dc27fea115214da255d2433504339887abd39f53cf0e56b0de'
$script:ManifestSha = 'fa4a884d69e3d2d36fbd6bfbcdd149034cb5416c64771144d4e6d844cad062d6'
$script:Files = @(
    @{ name='LDW.AdminBroker.Host.exe'; sha256='72ea1fafb2a483bf22770618f09b6cabcb14385794460f2104885af59a36ec96'; bytes=37706854L },
    @{ name='LDW.LocalSecretProbe.exe'; sha256='fe9a4ca642180af14491c6183334728d70d1bc96a418aa9d66ca0edd76b69120'; bytes=37630999L },
    @{ name='manifest.json'; sha256=$script:ManifestSha; bytes=639L }
)

function Read-Git([string]$Root, [string[]]$Arguments) {
    $result = @(& git -C $Root @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) { throw 'BROKER_PROVENANCE_GIT_FAILED' }
    return $result
}

function Get-SourceInputs([string]$Root, [string]$Commit) {
    if ($Commit -cnotmatch '^[a-f0-9]{40}$') { throw 'BROKER_PROVENANCE_COMMIT_INVALID' }
    # Complete transitive ProjectReference closure. Pin whole project directories so
    # added source/resources/imports and project-reference changes cannot escape.
    $paths = @(
        'host-agent/src/LDW.AdminBroker.Host', 'host-agent/src/LDW.AdminBroker',
        'host-agent/src/LDW.LocalSecretStore', 'host-agent/src/LDW.LocalSecretProbe',
        'host-agent/src/LDW.HostAgent.Core',
        'host-agent/deploy/Publish-AdminBrokerProofPackage.ps1',
        '.github/workflows/host-agent-persistent-helper-validation.yml'
    )
    $rows = @(Read-Git $Root (@('ls-tree','-r',$Commit,'--') + $paths))
    # Include ALL direct files at every ancestor, including currently absent future
    # Directory.Build.*, Directory.Packages.props, global.json, NuGet.Config and rsp.
    foreach ($directory in @('', 'host-agent', 'host-agent/src')) {
        $tree = if ($directory) { "${Commit}:$directory" } else { $Commit }
        foreach ($row in @(Read-Git $Root @('ls-tree',$tree))) {
            if ($row -cmatch '^([0-9]{6}) blob ([a-f0-9]{40})\t(.+)$') {
                $path = if ($directory) { "$directory/$($Matches[3])" } else { $Matches[3] }
                $rows += "$($Matches[1]) blob $($Matches[2])`t$path"
            } elseif ($row -cnotmatch '^040000 tree ') {
                throw 'BROKER_PROVENANCE_INPUT_TYPE_REFUSED'
            }
        }
    }
    foreach ($row in $rows) {
        if ($row -cnotmatch '^100644 blob [a-f0-9]{40}\t[A-Za-z0-9_./-]+$') {
            throw 'BROKER_PROVENANCE_INPUT_TYPE_REFUSED'
        }
    }
    [string[]]$canonical = $rows
    [Array]::Sort($canonical, [StringComparer]::Ordinal)
    return $canonical
}

function Assert-SourceInputs([string]$Root, [string]$Head) {
    $tree = @(Read-Git $Root @('rev-parse',"$script:ReleaseCommit`^{tree}"))[0]
    if ($tree -cne $script:ReleaseTree) { throw 'BROKER_PROVENANCE_RELEASE_TREE_MISMATCH' }
    & git -C $Root merge-base --is-ancestor $script:ReleaseCommit $Head 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'BROKER_PROVENANCE_ANCESTRY_REQUIRED' }
    $baseline = @(Get-SourceInputs $Root $script:ReleaseCommit)
    $current = @(Get-SourceInputs $Root $Head)
    if (($baseline -join "`n") -cne ($current -join "`n")) {
        throw 'BROKER_PROVENANCE_SOURCE_INPUTS_CHANGED'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($baseline -join "`n") + "`n")
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Assert-RegularPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw 'BROKER_PROVENANCE_ARCHIVE_REQUIRED' }
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'BROKER_PROVENANCE_REPARSE_REFUSED'
        }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}

function Assert-Archive([string]$Path, [string]$ArchiveSha, [object[]]$Files) {
    Assert-RegularPath $Path
    # Hash and inspect the same locked stream. Never extract or execute a member.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($hash -cne $ArchiveSha) { throw 'BROKER_PROVENANCE_ARCHIVE_HASH_MISMATCH' }
        $stream.Position = 0
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            if ($zip.Entries.Count -ne $Files.Count) { throw 'BROKER_PROVENANCE_INVENTORY_MISMATCH' }
            foreach ($file in $Files) {
                $entries = @($zip.Entries | Where-Object FullName -CEQ $file.name)
                if ($entries.Count -ne 1 -or $entries[0].Length -ne $file.bytes) {
                    throw 'BROKER_PROVENANCE_INVENTORY_MISMATCH'
                }
                $member = $entries[0].Open()
                try { $memberHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($member)).ToLowerInvariant() }
                finally { $member.Dispose() }
                if ($memberHash -cne $file.sha256) { throw 'BROKER_PROVENANCE_MEMBER_HASH_MISMATCH' }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}

function Test-AcceptedAdminBrokerProvenance {
    [CmdletBinding()]
    param()
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    if (@(Read-Git $root @('status','--porcelain','--untracked-files=all')).Count) {
        throw 'BROKER_PROVENANCE_CLEAN_CHECKOUT_REQUIRED'
    }
    $head = @(Read-Git $root @('rev-parse','HEAD'))[0]
    $identity = Assert-SourceInputs $root $head
    # Fixed content-addressed cache; no binary/path/hash/source override parameters.
    $cache = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if (-not $cache) { throw 'BROKER_PROVENANCE_CACHE_UNAVAILABLE' }
    $archive = Join-Path $cache "LowcountryDigitalWorks/AdminBroker/accepted/$script:ArchiveSha/package.zip"
    Assert-Archive $archive $script:ArchiveSha $script:Files
    'ADMIN_BROKER_PROVENANCE=PASS'
    'ADMIN_BROKER_PROVENANCE_SOURCE_HEAD=' + $head
    'ADMIN_BROKER_PROVENANCE_INPUTS_SHA256=' + $identity
    'ADMIN_BROKER_PROVENANCE_RELEASE_COMMIT=' + $script:ReleaseCommit
    'ADMIN_BROKER_PROVENANCE_ARCHIVE_SHA256=' + $script:ArchiveSha
    'ADMIN_BROKER_PROVENANCE_MANIFEST_SHA256=' + $script:ManifestSha
    'ADMIN_BROKER_PROVENANCE_EXE_SHA256=' + $script:Files[0].sha256
    'ADMIN_BROKER_PROVENANCE_RUNTIME_AUTHORIZED=False'
}

Export-ModuleMember -Function Test-AcceptedAdminBrokerProvenance
