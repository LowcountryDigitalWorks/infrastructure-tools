[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$script:AcceptedDispatcherSource = [pscustomobject]@{
    path='ci-dispatch/Dispatch.psm1'
    blob='662981a2955a3cd3f3526aeb666e185f989c4a18'; sha256='bf8da2a7ed95887bb7b7e3ddbf1ba10fe97f9a3ff9eb384ae9e16740674241ef'
}
$script:AcceptedVerifierRecordSource = [pscustomobject]@{
    path='ci-dispatch/verifier-provenance.json'
    blob='f2635eb0eaa24b9da7919c3d0c30fa23f4ea919b'; sha256='b810c526b641c8ed0447863aaf0acba35c753887889d4c55c4e1ac0fe14d3b77'
}
$root = Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$staging = $null
function Assert-Ci10PublisherElevated {
    if ($env:OS -ne 'Windows_NT') { return }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ELEVATED_CONTROLLER_REQUIRED' }
}
function Assert-Ci10PublisherPath([string]$Root, [string]$Path) {
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($fullRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PATH_OUTSIDE_OWNED_ROOT'
    }
    $cursor = $fullPath
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'REPARSE_PATH_REFUSED'
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}
function Protect-Ci10Directory([string]$Path) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
            'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Export-Ci10PinnedSourceFile([string]$Repository, [string]$Path, [string]$Destination, [string]$StageRoot) {
    $acceptedSource = @(@($script:AcceptedDispatcherSource, $script:AcceptedVerifierRecordSource) | Where-Object { $_.path -ceq $Path })
    if ($acceptedSource.Count -ne 1) { throw 'PUBLISH_VERIFIER_PROVENANCE_REFUSED' }
    $source = $acceptedSource[0]
    $actualBlob = & git -C $Repository rev-parse ('HEAD:'+ $source.path) 2>$null
    if ($LASTEXITCODE -ne 0 -or ([string]$actualBlob).Trim() -cne $source.blob) {
        throw 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
    }
    $archive = Join-Path $StageRoot ('source-'+$source.blob+'.zip')
    & git -C $Repository archive --format=zip ('--output='+$archive) HEAD -- $source.path 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PUBLISH_VERIFIER_SOURCE_FAILED' }
    $extract = Join-Path $StageRoot ('source-'+$source.blob)
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$extract)
    $sourcePath = Join-Path $extract $source.path
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $source.sha256) {
        throw 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
    }
    Copy-Item -LiteralPath $sourcePath -Destination $Destination -Force
}
function Assert-Ci10AcceptedHeadDispatcherSource([string]$Repository) {
    $headBlob = & git -C $Repository rev-parse ('HEAD:'+ $script:AcceptedDispatcherSource.path) 2>$null
    $dispatcherPath = Join-Path $Repository $script:AcceptedDispatcherSource.path
    if ($LASTEXITCODE -ne 0 -or ([string]$headBlob).Trim() -cne $script:AcceptedDispatcherSource.blob -or
        -not (Test-Path -LiteralPath $dispatcherPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $dispatcherPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $script:AcceptedDispatcherSource.sha256) {
        throw 'PUBLISH_VERIFIER_PROVENANCE_REFUSED'
    }
}
try {
    $sourceStatus = & git -C $repo status --porcelain 2>$null
    if ($LASTEXITCODE -ne 0 -or $sourceStatus) { throw 'PUBLISH_SOURCE_WORKTREE_DIRTY' }
    Assert-Ci10AcceptedHeadDispatcherSource $repo
    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    Assert-Ci10PublisherElevated
    $liveTree = & git -C $repo rev-parse ($Commit+'^{tree}') 2>$null
    if ($LASTEXITCODE -ne 0 -or $liveTree -cne $Tree) { throw 'PUBLISH_COMMIT_TREE_MISMATCH' }
    $remote = & git -C $repo remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or $remote -cnotmatch '^(https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(\.git)?$') { throw 'PUBLISH_REPOSITORY_REFUSED' }
    Assert-Ci10PublisherPath (Split-Path $root -Parent) $root
    if (Test-Path -LiteralPath $root) { Assert-Ci10ProtectedPath $root } else { Protect-Ci10Directory $root }
    $releases = Join-Path $root 'releases'
    if (Test-Path -LiteralPath $releases) { Assert-Ci10ProtectedPath $releases } else { Protect-Ci10Directory $releases }
    $staging = Join-Path $root ('stage-'+[guid]::NewGuid().ToString('N'))
    Protect-Ci10Directory $staging
    $files = @(Get-Ci10RuntimeFiles)
    $archive = Join-Path $staging 'candidate.zip'
    $verifierPaths = @('ci-dispatch/Dispatch.psm1','ci-dispatch/verifier-provenance.json')
    $targetFiles = @($files | Where-Object { $_ -cnotin $verifierPaths })
    & git -C $repo archive --format=zip ('--output='+$archive) $Commit -- @targetFiles 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PUBLISH_ARCHIVE_FAILED' }
    $bundle = Join-Path $staging 'bundle'
    Protect-Ci10Directory $bundle
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$bundle)

    # Compatibility verifier and its record resolve from fixed reviewed path/blob/SHA-256 identities.
    Export-Ci10PinnedSourceFile $repo $script:AcceptedDispatcherSource.path `
        (Join-Path $bundle $script:AcceptedDispatcherSource.path) $staging
    Export-Ci10PinnedSourceFile $repo $script:AcceptedVerifierRecordSource.path `
        (Join-Path $bundle $script:AcceptedVerifierRecordSource.path) $staging
    $dispatcherProvenance = Get-Content -LiteralPath (Join-Path $bundle 'ci-dispatch/verifier-provenance.json') -Raw | ConvertFrom-Json
    if ($dispatcherProvenance.schema -ne 1 -or
        $dispatcherProvenance.blob -cne $script:AcceptedDispatcherSource.blob -or
        $dispatcherProvenance.sha256 -cne $script:AcceptedDispatcherSource.sha256) { throw 'PUBLISH_VERIFIER_PROVENANCE_REFUSED' }

    $controllerFiles = @($files | Where-Object { $_.StartsWith('ci-runner/') })
    $matchedSnapshot = Get-Ci10MatchedControllerSnapshot -RepositoryRoot $repo -ControllerRoot $bundle -ControllerFiles $controllerFiles -StagingRoot $staging
    $entries = @($files | Sort-Object | ForEach-Object {
        $path = $_
        $hash = (Get-FileHash -LiteralPath (Join-Path $bundle $path) -Algorithm SHA256).Hash.ToLowerInvariant()
        [ordered]@{ path=$path; sha256=$hash }
    })
    # Normalize all object owners, including files created by ZIP extraction.
    foreach ($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    $manifest = [ordered]@{ schema=1; commit=$Commit; tree=$Tree; dispatcher=$dispatcherProvenance;
        controllerCommit=$matchedSnapshot.commit; controllerTree=$matchedSnapshot.tree; files=$entries }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $bundle 'manifest.json') -Encoding utf8NoBOM
    $acl = Get-Acl -LiteralPath (Join-Path $bundle 'manifest.json')
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath (Join-Path $bundle 'manifest.json') -AclObject $acl
    $manifestSha = (Get-FileHash -LiteralPath (Join-Path $bundle 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $destination = Join-Path $releases $Commit
    if (Test-Path -LiteralPath $destination) {
        $null = Assert-Ci10Bundle $destination $manifestSha $Commit $Tree
    } else {
        Move-Item -LiteralPath $bundle -Destination $destination
        $null = Assert-Ci10Bundle $destination $manifestSha $Commit $Tree
    }
    'BUNDLE_PUBLISHED=PASS'
    'BUNDLE_COMMIT='+$Commit
    'BUNDLE_TREE='+$Tree
    'BUNDLE_MANIFEST_SHA256='+$manifestSha
} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code='BUNDLE_PUBLISH_FAILED' }
    'BUNDLE_PUBLISHED=FAIL'; 'CLASSIFICATION='+$code
    exit 1
} finally {
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        # Only the exact fresh stage directory created above is disposable.
        Assert-Ci10PublisherPath $root $staging
        if ((Split-Path $staging -Leaf) -cnotmatch '^stage-[a-f0-9]{32}$') { throw 'STAGING_CLEANUP_OWNERSHIP_INVALID' }
        foreach ($item in @(Get-ChildItem -LiteralPath $staging -Recurse -Force)) { Assert-Ci10PublisherPath $root $item.FullName }
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
