[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Tree
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$root = Join-Path $env:ProgramData 'LDW/CiRunnerDispatch'
$staging = $null
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
try {
    Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1') -Force
    Import-Module (Join-Path $repo 'ci-runner/CiRunner.psm1') -Force
    Assert-Ci7Elevated
    $liveTree = & git -C $repo rev-parse ($Commit+'^{tree}') 2>$null
    if ($LASTEXITCODE -ne 0 -or $liveTree -cne $Tree) { throw 'PUBLISH_COMMIT_TREE_MISMATCH' }
    $remote = & git -C $repo remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or $remote -cnotmatch '^(https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(\.git)?$') { throw 'PUBLISH_REPOSITORY_REFUSED' }
    Assert-Ci7Path (Split-Path $root -Parent) $root
    if (Test-Path -LiteralPath $root) { Assert-Ci10ProtectedPath $root } else { Protect-Ci10Directory $root }
    $releases = Join-Path $root 'releases'
    if (Test-Path -LiteralPath $releases) { Assert-Ci10ProtectedPath $releases } else { Protect-Ci10Directory $releases }
    $staging = Join-Path $root ('stage-'+[guid]::NewGuid().ToString('N'))
    Protect-Ci10Directory $staging
    $files = @(Get-Ci10RuntimeFiles)
    $archive = Join-Path $staging 'candidate.zip'
    & git -C $repo archive --format=zip ('--output='+$archive) $Commit -- @files 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'PUBLISH_ARCHIVE_FAILED' }
    $bundle = Join-Path $staging 'bundle'
    Protect-Ci10Directory $bundle
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$bundle)
    $controllerFiles = @($files | Where-Object { $_.StartsWith('ci-runner/') })
    $acceptedArchive = Join-Path $staging 'accepted.zip'
    & git -C $repo archive --format=zip ('--output='+$acceptedArchive) '49f39f5d3a66251ed18c2e776d843feb25f65fe1' -- @controllerFiles 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'ACCEPTED_CONTROLLER_UNAVAILABLE' }
    $accepted = Join-Path $staging 'accepted'
    [IO.Compression.ZipFile]::ExtractToDirectory($acceptedArchive,$accepted)
    $entries = @($files | Sort-Object | ForEach-Object {
        $path = $_
        $hash = (Get-FileHash -LiteralPath (Join-Path $bundle $path) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($path -cin $controllerFiles -and $hash -cne (Get-FileHash -LiteralPath (Join-Path $accepted $path) -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'ACCEPTED_CONTROLLER_CHANGED'
        }
        [ordered]@{ path=$path; sha256=$hash }
    })
    # Normalize all object owners, including files created by ZIP extraction.
    foreach ($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    $manifest = [ordered]@{ schema=1; commit=$Commit; tree=$Tree;
        controllerCommit='49f39f5d3a66251ed18c2e776d843feb25f65fe1'; controllerTree='4d241fe9bc0fbf190daf2e36be0e9c52966c5a7b'; files=$entries }
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
        Assert-Ci7Path $root $staging
        if ((Split-Path $staging -Leaf) -cnotmatch '^stage-[a-f0-9]{32}$') { throw 'STAGING_CLEANUP_OWNERSHIP_INVALID' }
        foreach ($item in @(Get-ChildItem -LiteralPath $staging -Recurse -Force)) { Assert-Ci7Path $root $item.FullName }
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
