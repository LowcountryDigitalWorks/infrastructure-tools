Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CanaryCommit = '78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca'
$script:CanaryTree = '5f54ee5b76f49250db1358f058745cb30b6587ef'
$script:EntryCommit = 'b8d43672a3e6940a7ed98880db1f35e44ab290b6'
$script:EntryTree = 'b2e0095a23a3ab32b7279a17eb4264666c6534c3'
$script:DispatchCommit = 'ce2bf253556a69dfb43de7bb8e8a4927c41c9e15'
$script:DispatchTree = '57ceb47f2a0a40d3b176cde0818a0ad8c5891dca'
$script:DispatchBlob = 'c862dd503b98060ec984206e63ef9efa5f957e8f'
$script:DispatchRawSha256 = '76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675'
$script:DispatchWindowsSha256 = '0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72'
$script:Files = @(
    [pscustomobject]@{ path='ci-dispatch/DragonflyCanary.psm1'; commit=$script:CanaryCommit; tree=$script:CanaryTree; blob='893c89ae65bd85464f404fa4a4ff762344915520'; representation='raw' },
    [pscustomobject]@{ path='ci-dispatch/DragonflyCanaryRuntime.psm1'; commit=$script:CanaryCommit; tree=$script:CanaryTree; blob='7730f473d2588e885fa6a4f3aec1b486b408dbda'; representation='raw' },
    [pscustomobject]@{ path='ci-dispatch/Invoke-DragonflyCanaryProduction.ps1'; commit=$script:EntryCommit; tree=$script:EntryTree; blob='e8b95a4bc880b0f15cf6aea65246e53b2dd1b811'; representation='raw' },
    [pscustomobject]@{ path='ci-dispatch/Dispatch.psm1'; commit=$script:DispatchCommit; tree=$script:DispatchTree; blob=$script:DispatchBlob; representation='crlf' }
)

function Get-LdwAdjunctGitBlobSha1 {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $prefix = [Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
    $combined = [byte[]]::new($prefix.Length + $bytes.Length)
    [Array]::Copy($prefix,0,$combined,0,$prefix.Length)
    [Array]::Copy($bytes,0,$combined,$prefix.Length,$bytes.Length)
    $sha = [Security.Cryptography.SHA1]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash($combined))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-LdwAdjunctRepository {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    $status = & git -C $RepositoryRoot status --porcelain --untracked-files=normal 2>$null
    if ($LASTEXITCODE -ne 0 -or $status) { throw 'ADJUNCT_SOURCE_WORKTREE_DIRTY' }
    $remote = & git -C $RepositoryRoot remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or ([string]$remote).Trim() -cnotmatch '^(https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(\.git)?$') {
        throw 'ADJUNCT_REPOSITORY_REFUSED'
    }
    foreach ($pair in @(
        @($script:CanaryCommit,$script:CanaryTree),
        @($script:EntryCommit,$script:EntryTree),
        @($script:DispatchCommit,$script:DispatchTree)
    )) {
        $tree = & git -C $RepositoryRoot rev-parse ($pair[0] + '^{tree}') 2>$null
        if ($LASTEXITCODE -ne 0 -or ([string]$tree).Trim() -cne $pair[1]) { throw 'ADJUNCT_SOURCE_TREE_MISMATCH' }
    }
}

function Assert-LdwAdjunctElevated {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'ADJUNCT_WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADJUNCT_ELEVATED_CONTROLLER_REQUIRED' }
}

function Protect-LdwAdjunctDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $null = New-Item -ItemType Directory -Path $Path -Force
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-LdwAdjunctProtectedPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'ADJUNCT_REPARSE_PATH_REFUSED' }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $acl = Get-Acl -LiteralPath $full
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'ADJUNCT_OWNER_UNTRUSTED' }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'ADJUNCT_ACL_UNTRUSTED_WRITE' }
    }
}

function Assert-LdwAdjunctParentBoundary {
    param([Parameter(Mandatory)][string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'ADJUNCT_PARENT_OWNER_UNTRUSTED' }
    $replace = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $replace) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) {
            throw 'ADJUNCT_PARENT_REPLACEMENT_UNTRUSTED'
        }
    }
}

function Export-LdwAdjunctPinnedFile {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][object]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$StageRoot
    )
    $actualBlob = & git -C $RepositoryRoot rev-parse ($Source.commit + ':' + $Source.path) 2>$null
    if ($LASTEXITCODE -ne 0 -or ([string]$actualBlob).Trim() -cne $Source.blob) { throw 'ADJUNCT_SOURCE_BLOB_MISMATCH' }
    # Archive/checkout can apply working-tree EOL/attribute conversions. Read the
    # verified object directly and keep stdout binary (no PowerShell text pipeline).
    $sourcePath = Join-Path $StageRoot ('source-' + $Source.blob)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    foreach ($arg in @('-C',$RepositoryRoot,'cat-file','blob',$Source.blob)) { [void]$psi.ArgumentList.Add([string]$arg) }
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi
    try {
        $output = [IO.File]::Create($sourcePath)
        try {
            if (-not $process.Start()) { throw 'ADJUNCT_SOURCE_EXPORT_FAILED' }
            $stderrTask = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
            $process.StandardOutput.BaseStream.CopyTo($output)
            $process.WaitForExit()
            [void]$stderrTask.GetAwaiter().GetResult()
            if ($process.ExitCode -ne 0) { throw 'ADJUNCT_SOURCE_EXPORT_FAILED' }
        } finally { $output.Dispose() }
    } catch { throw 'ADJUNCT_SOURCE_EXPORT_FAILED' }
    finally { $process.Dispose() }
    $rawBlob = Get-LdwAdjunctGitBlobSha1 $sourcePath
    if ($rawBlob -cne $Source.blob) { throw 'ADJUNCT_SOURCE_BLOB_MISMATCH' }
    $null = New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force
    if ($Source.representation -ceq 'raw') {
        Copy-Item -LiteralPath $sourcePath -Destination $Destination -Force
    } elseif ($Source.representation -ceq 'crlf') {
        $bytes = [IO.File]::ReadAllBytes($sourcePath)
        if ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $script:DispatchRawSha256) {
            throw 'ADJUNCT_DISPATCH_RAW_HASH_MISMATCH'
        }
        $utf8 = [Text.UTF8Encoding]::new($false,$true)
        $text = $utf8.GetString($bytes).Replace("`r`n","`n").Replace("`n","`r`n")
        [IO.File]::WriteAllText($Destination,$text,[Text.UTF8Encoding]::new($false))
        if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $script:DispatchWindowsSha256) {
            throw 'ADJUNCT_DISPATCH_WINDOWS_HASH_MISMATCH'
        }
    } else { throw 'ADJUNCT_SOURCE_REPRESENTATION_REFUSED' }
    [pscustomobject]@{
        path=$Source.path
        sourceCommit=$Source.commit
        sourceTree=$Source.tree
        gitBlob=$Source.blob
        representation=$Source.representation
        sha256=(Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Test-LdwDragonflyCanaryAdjunctCore {
    param(
        [Parameter(Mandatory)][string]$ReleaseRoot,
        [Parameter(Mandatory)][string]$ManifestSha256
    )
    if ($ManifestSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'ADJUNCT_MANIFEST_REFERENCE_INVALID' }
    Assert-LdwAdjunctProtectedPath $ReleaseRoot
    $manifestPath = Join-Path $ReleaseRoot 'manifest.json'
    Assert-LdwAdjunctProtectedPath $manifestPath
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) { throw 'ADJUNCT_MANIFEST_HASH_DRIFT' }
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
    catch { throw 'ADJUNCT_MANIFEST_INVALID' }
    $expectedFields = @('schema','artifact','canaryCommit','canaryTree','entryCommit','entryTree','dispatchAuthority','containsCredential','containsBootstrap','containsPrivateEndpoint','files')
    if (@(Compare-Object $expectedFields @($manifest.PSObject.Properties.Name) -CaseSensitive).Count -or
        $manifest.schema -ne 1 -or $manifest.artifact -cne 'ldw-dragonfly-canary-adjunct-v1' -or
        $manifest.canaryCommit -cne $script:CanaryCommit -or $manifest.canaryTree -cne $script:CanaryTree -or
        $manifest.entryCommit -cne $script:EntryCommit -or $manifest.entryTree -cne $script:EntryTree -or
        $manifest.containsCredential -ne $false -or $manifest.containsBootstrap -ne $false -or $manifest.containsPrivateEndpoint -ne $false -or
        $manifest.dispatchAuthority.commit -cne $script:DispatchCommit -or $manifest.dispatchAuthority.tree -cne $script:DispatchTree -or
        $manifest.dispatchAuthority.blob -cne $script:DispatchBlob -or $manifest.dispatchAuthority.rawSha256 -cne $script:DispatchRawSha256 -or
        $manifest.dispatchAuthority.windowsSha256 -cne $script:DispatchWindowsSha256 -or $manifest.dispatchAuthority.materialization -cne 'crlf') {
        throw 'ADJUNCT_MANIFEST_INVALID'
    }
    $expectedPaths = @($script:Files.path)
    $actualPaths = @(Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -Force -File | ForEach-Object {
        [IO.Path]::GetRelativePath($ReleaseRoot,$_.FullName).Replace('\','/')
    })
    if (@($manifest.files).Count -ne $script:Files.Count -or
        @(Compare-Object $expectedPaths @($manifest.files.path) -CaseSensitive).Count -or
        @(Compare-Object (@($expectedPaths) + @('manifest.json')) $actualPaths -CaseSensitive).Count) {
        throw 'ADJUNCT_FILE_SET_DRIFT'
    }
    foreach ($source in $script:Files) {
        $entry = @($manifest.files | Where-Object path -CEQ $source.path)
        if ($entry.Count -ne 1 -or $entry[0].sourceCommit -cne $source.commit -or $entry[0].sourceTree -cne $source.tree -or
            $entry[0].gitBlob -cne $source.blob -or $entry[0].representation -cne $source.representation -or
            $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'ADJUNCT_MANIFEST_INVALID' }
        $path = Join-Path $ReleaseRoot $source.path
        Assert-LdwAdjunctProtectedPath $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[0].sha256) { throw 'ADJUNCT_FILE_HASH_DRIFT' }
        if ($source.representation -ceq 'raw') {
            if ((Get-LdwAdjunctGitBlobSha1 $path) -cne $source.blob) { throw 'ADJUNCT_FILE_BLOB_DRIFT' }
        } elseif ($entry[0].sha256 -cne $script:DispatchWindowsSha256) { throw 'ADJUNCT_DISPATCH_WINDOWS_HASH_MISMATCH' }
    }
    [pscustomobject]@{ Valid=$true; ReleaseRoot=$ReleaseRoot; ManifestSha256=$ManifestSha256; CanaryCommit=$script:CanaryCommit }
}

function New-LdwDragonflyCanaryAdjunctCore {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Root
    )
    Assert-LdwAdjunctRepository $RepositoryRoot
    if (Test-Path -LiteralPath $Root) { Assert-LdwAdjunctProtectedPath $Root } else { Protect-LdwAdjunctDirectory $Root }
    $releases = Join-Path $Root 'releases'
    if (Test-Path -LiteralPath $releases) { Assert-LdwAdjunctProtectedPath $releases } else { Protect-LdwAdjunctDirectory $releases }
    $release = Join-Path $releases $script:CanaryCommit
    $stage = Join-Path $Root ('stage-' + [guid]::NewGuid().ToString('N'))
    Protect-LdwAdjunctDirectory $stage
    try {
        $bundle = Join-Path $stage 'bundle'
        Protect-LdwAdjunctDirectory $bundle
        $records = @()
        foreach ($source in $script:Files) {
            $destination = Join-Path $bundle $source.path
            $records += Export-LdwAdjunctPinnedFile -RepositoryRoot $RepositoryRoot -Source $source -Destination $destination -StageRoot $stage
        }
        $manifest = [ordered]@{
            schema=1
            artifact='ldw-dragonfly-canary-adjunct-v1'
            canaryCommit=$script:CanaryCommit
            canaryTree=$script:CanaryTree
            entryCommit=$script:EntryCommit
            entryTree=$script:EntryTree
            dispatchAuthority=[ordered]@{commit=$script:DispatchCommit;tree=$script:DispatchTree;blob=$script:DispatchBlob;rawSha256=$script:DispatchRawSha256;windowsSha256=$script:DispatchWindowsSha256;materialization='crlf'}
            containsCredential=$false
            containsBootstrap=$false
            containsPrivateEndpoint=$false
            files=@($records | Sort-Object path)
        }
        $manifestPath = Join-Path $bundle 'manifest.json'
        $manifest | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            foreach ($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) {
                $acl = Get-Acl -LiteralPath $item.FullName
                $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
                Set-Acl -LiteralPath $item.FullName -AclObject $acl
            }
        }
        $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (Test-Path -LiteralPath $release) {
            $null = Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $manifestSha
        } else {
            Move-Item -LiteralPath $bundle -Destination $release
            $null = Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $manifestSha
        }
        [pscustomobject]@{ Published=$true; ReleaseRoot=$release; ManifestSha256=$manifestSha; CanaryCommit=$script:CanaryCommit; CanaryTree=$script:CanaryTree }
    } finally {
        if (Test-Path -LiteralPath $stage) {
            $leaf = Split-Path $stage -Leaf
            if ($leaf -cnotmatch '^stage-[a-f0-9]{32}$') { throw 'ADJUNCT_STAGE_OWNERSHIP_INVALID' }
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
}

function Publish-LdwDragonflyCanaryAdjunct {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$RepositoryRoot)
    Assert-LdwAdjunctElevated
    if ([string]::IsNullOrWhiteSpace($env:ProgramData) -or -not [IO.Path]::IsPathRooted($env:ProgramData)) { throw 'ADJUNCT_PROGRAMDATA_INVALID' }
    $ldwRoot = Join-Path $env:ProgramData 'LDW'
    if (-not (Test-Path -LiteralPath $ldwRoot -PathType Container)) { throw 'ADJUNCT_LDW_ROOT_MISSING' }
    Assert-LdwAdjunctParentBoundary $ldwRoot
    Assert-LdwAdjunctParentBoundary $env:ProgramData
    $root = Join-Path $ldwRoot 'DragonflyCanaryAdjunct'
    New-LdwDragonflyCanaryAdjunctCore -RepositoryRoot $RepositoryRoot -Root $root
}

function Test-LdwDragonflyCanaryAdjunct {
    [CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256)
    if ([string]::IsNullOrWhiteSpace($env:ProgramData) -or -not [IO.Path]::IsPathRooted($env:ProgramData)) { throw 'ADJUNCT_PROGRAMDATA_INVALID' }
    $release = Join-Path $env:ProgramData ('LDW\DragonflyCanaryAdjunct\releases\' + $script:CanaryCommit)
    Test-LdwDragonflyCanaryAdjunctCore -ReleaseRoot $release -ManifestSha256 $ManifestSha256
}

Export-ModuleMember -Function Publish-LdwDragonflyCanaryAdjunct,Test-LdwDragonflyCanaryAdjunct
