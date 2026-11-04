# SOURCE-ONLY read-only provenance verifier; never invokes/publishes the module.
# Unprotected developer checkouts are diagnostics only: loaded code is UNVERIFIED.
# ProtectedPublication requires a separately approved administrator-owned staging
# tree and holds a no-write/no-delete file handle across import AND publication.
# The real operator must run BeforeImport, import, AfterImport, publish, Release in
# ONE trusted PowerShell process, with Release in finally; caller must independently
# pin this gate script itself. No source-only PASS authorizes publication or Gate B.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidateSet('BeforeImport','AfterImport','Release')][string]$Phase,
    [switch]$ProtectedPublication
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedCommit = 'bc29bedbfe7fe8a545ce3a471e0d575c2921cefe'
$acceptedTree = 'a6eb1d42693793cae2986f973f9e1f2ac2438729'
$acceptedBlob = 'e322a071e5e6e31a909447823e737252770fafef'
$publisherRelativePath = 'ci-dispatch/DragonflyCanaryAdjunctV2Publisher.psm1'
$publisherModuleName = 'DragonflyCanaryAdjunctV2Publisher'

if ($ProtectedPublication -and [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'V2_PROVENANCE_PROTECTED_WINDOWS_REQUIRED'
}

# Resolve the actual application, never a PowerShell alias/function named git.
# Privileged publication accepts only the fixed signed Program Files Git.exe.
$script:GitExecutable = if ($ProtectedPublication) {
    if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) { throw 'V2_PROVENANCE_TRUSTED_GIT_MISSING' }
    Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
} else {
    (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}
if (-not (Test-Path -LiteralPath $script:GitExecutable -PathType Leaf)) {
    throw 'V2_PROVENANCE_TRUSTED_GIT_MISSING'
}
if ($ProtectedPublication) {
    $gitItem = Get-Item -LiteralPath $script:GitExecutable -Force
    if ($gitItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'V2_PROVENANCE_TRUSTED_GIT_REPARSE' }
    if ((Get-AuthenticodeSignature -LiteralPath $script:GitExecutable).Status -ne 'Valid') {
        throw 'V2_PROVENANCE_TRUSTED_GIT_SIGNATURE_INVALID'
    }
}


# A protected publication guard is intentionally process-local, never persisted
# to disk or passed to another process. Do not weaken this for test convenience.
$guardName = 'LDW_DRAGONFLY_V2_PROTECTED_PUBLISH_GUARD'
$priorGuard = Get-Variable -Name $guardName -Scope Global -ValueOnly -ErrorAction SilentlyContinue
if ($Phase -ceq 'Release') {
    if (-not $ProtectedPublication -or $null -eq $priorGuard -or
        $priorGuard.OwnerPid -ne $PID) { throw 'V2_PROVENANCE_PROTECTED_GUARD_MISSING' }
    try { $priorGuard.Stream.Dispose() }
    finally { Remove-Variable -Name $guardName -Scope Global -Force -ErrorAction SilentlyContinue }
    'DRAGONFLY_V2_PUBLISHER_PROVENANCE_GUARD_RELEASE=PASS'
    return
}
if ($null -ne $priorGuard -and $Phase -ceq 'BeforeImport') {
    throw 'V2_PROVENANCE_PROTECTED_GUARD_ALREADY_ACTIVE'
}

function Assert-LdwV2ProtectedStaging {
    param([string]$Root,[string]$Folder,[string]$File,[StringComparison]$Comparison)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'V2_PROVENANCE_PROTECTED_WINDOWS_REQUIRED'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'V2_PROVENANCE_PROTECTED_ADMIN_REQUIRED'
    }
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { throw 'V2_PROVENANCE_PROGRAMDATA_INVALID' }
    $ldw = Join-Path $env:ProgramData 'LDW'
    $expected = Join-Path $ldw 'DragonflyV2PublisherSource'
    if (-not [string]::Equals([IO.Path]::GetFullPath($Root),[IO.Path]::GetFullPath($expected),$Comparison)) {
        throw 'V2_PROVENANCE_PROTECTED_STAGE_REQUIRED'
    }
    $allowed = @('S-1-5-18','S-1-5-32-544')
    $replace = [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $write = $replace -bor [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories
    foreach ($target in @($Root,$Folder,$File)) {
        $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'V2_PROVENANCE_PROTECTED_REPARSE_REFUSED' }
        $acl = Get-Acl -LiteralPath $target
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
            throw 'V2_PROVENANCE_PROTECTED_OWNER_UNTRUSTED'
        }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
                $rule.IdentityReference.Value -notin $allowed) {
                throw 'V2_PROVENANCE_PROTECTED_WRITE_UNTRUSTED'
            }
        }
    }
    foreach ($target in @($ldw,$env:ProgramData)) {
        $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'V2_PROVENANCE_PROTECTED_REPARSE_REFUSED' }
        $acl = Get-Acl -LiteralPath $target
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
            throw 'V2_PROVENANCE_PROTECTED_PARENT_OWNER_UNTRUSTED'
        }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and
                -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                ($rule.FileSystemRights -band $replace) -and $rule.IdentityReference.Value -notin $allowed) {
                throw 'V2_PROVENANCE_PROTECTED_PARENT_REPLACE_UNTRUSTED'
            }
        }
    }
}

function Read-LdwV2GitValue {
    param([string]$Root,[string[]]$Arguments)
    $values = @(& $script:GitExecutable -C $Root @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $values.Count -ne 1) { throw 'V2_PROVENANCE_GIT_QUERY_FAILED' }
    ([string]$values[0]).Trim()
}

function Assert-LdwV2NoReparse {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'V2_PROVENANCE_REPARSE_REFUSED'
    }
}

function Get-LdwV2GitBlobSha1 {
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $prefix = [Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
    $raw = [byte[]]::new($prefix.Length + $bytes.Length)
    [Array]::Copy($prefix,0,$raw,0,$prefix.Length)
    [Array]::Copy($bytes,0,$raw,$prefix.Length,$bytes.Length)
    $hash = [Security.Cryptography.SHA1]::Create()
    try { ([BitConverter]::ToString($hash.ComputeHash($raw))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

if (-not [IO.Directory]::Exists($RepositoryRoot)) { throw 'V2_PROVENANCE_CHECKOUT_MISSING' }
$root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar
)
$comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}
Assert-LdwV2NoReparse $root
$top = Read-LdwV2GitValue $root @('rev-parse','--show-toplevel')
$top = [IO.Path]::GetFullPath($top).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar
)
if (-not [string]::Equals($root,$top,$comparison)) { throw 'V2_PROVENANCE_REPOSITORY_ROOT_INVALID' }
$origin = Read-LdwV2GitValue $root @('remote','get-url','origin')
if ($origin -cnotmatch '^(https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(\.git)?$') {
    throw 'V2_PROVENANCE_ORIGIN_INVALID'
}
if ((Read-LdwV2GitValue $root @('rev-parse','HEAD')) -cne $acceptedCommit) {
    throw 'V2_PROVENANCE_HEAD_MISMATCH'
}
if ((Read-LdwV2GitValue $root @('rev-parse','HEAD^{tree}')) -cne $acceptedTree) {
    throw 'V2_PROVENANCE_TREE_MISMATCH'
}
if ((Read-LdwV2GitValue $root @('rev-parse',('HEAD:' + $publisherRelativePath))) -cne $acceptedBlob) {
    throw 'V2_PROVENANCE_COMMITTED_BLOB_MISMATCH'
}
$status = @(& $script:GitExecutable -C $root status --porcelain --untracked-files=all 2>$null)
if ($LASTEXITCODE -ne 0 -or $status.Count -gt 0) { throw 'V2_PROVENANCE_WORKTREE_DIRTY' }

$folder = Join-Path $root 'ci-dispatch'
$file = Join-Path $folder 'DragonflyCanaryAdjunctV2Publisher.psm1'
Assert-LdwV2NoReparse $folder
Assert-LdwV2NoReparse $file
if ((Get-LdwV2GitBlobSha1 $file) -cne $acceptedBlob) {
    throw 'V2_PROVENANCE_ON_DISK_BLOB_MISMATCH'
}

if ($ProtectedPublication -and $Phase -ceq 'AfterImport') {
    if ($null -eq $priorGuard -or $priorGuard.OwnerPid -ne $PID -or
        $priorGuard.Stream.SafeFileHandle.IsClosed -or
        -not [string]::Equals($priorGuard.Root,$root,$comparison)) {
        throw 'V2_PROVENANCE_PROTECTED_GUARD_MISSING'
    }
}
if ($ProtectedPublication) {
    Assert-LdwV2ProtectedStaging -Root $root -Folder $folder -File $file -Comparison $comparison
}

$loaded = @(Get-Module -Name $publisherModuleName -ErrorAction SilentlyContinue)
if ($Phase -ceq 'BeforeImport') {
    if ($loaded.Count -ne 0) { throw 'V2_PROVENANCE_PREIMPORT_MODULE_ALREADY_LOADED' }
    if ($ProtectedPublication) {
        # Windows FileShare.Read refuses other writers/renames until Release.
        # Open AFTER staging/ACL validation; re-read hash/status UNDER the handle
        # to close the gap between the earlier checkout check and lock acquisition.
        $stream = [IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if ((Get-LdwV2GitBlobSha1 $file) -cne $acceptedBlob) {
                throw 'V2_PROVENANCE_ON_DISK_BLOB_MISMATCH'
            }
            $freshStatus = @(& $script:GitExecutable -C $root status --porcelain --untracked-files=all 2>$null)
            if ($LASTEXITCODE -ne 0 -or $freshStatus.Count -gt 0) {
                throw 'V2_PROVENANCE_WORKTREE_DIRTY'
            }
            Set-Variable -Name $guardName -Scope Global -Value ([pscustomobject]@{
                Stream = $stream
                Root = $root
                OwnerPid = $PID
            }) -Force
        } catch {
            $stream.Dispose()
            throw
        }
        'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS_PROTECTED'
    } else {
        'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS_SOURCE_ONLY'
    }
    return
}
if ($loaded.Count -ne 1) { throw 'V2_PROVENANCE_LOADED_MODULE_NOT_UNIQUE' }
$modulePath = [IO.Path]::GetFullPath([string]$loaded[0].Path)
if (-not [string]::Equals($modulePath,[IO.Path]::GetFullPath($file),$comparison)) {
    throw 'V2_PROVENANCE_LOADED_MODULE_PATH_MISMATCH'
}
$command = @(Get-Command Publish-LdwDragonflyCanaryAdjunctV2 -CommandType Function -All -ErrorAction SilentlyContinue)
if ($command.Count -ne 1 -or $null -eq $command[0].Module -or
    -not [string]::Equals([IO.Path]::GetFullPath([string]$command[0].Module.Path),$modulePath,$comparison)) {
    throw 'V2_PROVENANCE_PUBLISH_COMMAND_MISMATCH'
}
if (-not $ProtectedPublication) {
    # Correctness rule: a same-path module can contain substituted loaded code
    # even if malicious bytes were restored before this second disk hash check.
    throw 'V2_PROVENANCE_LOADED_CODE_UNVERIFIED'
}
if ($null -eq $priorGuard -or $priorGuard.Stream.SafeFileHandle.IsClosed) {
    throw 'V2_PROVENANCE_PROTECTED_GUARD_MISSING'
}
'DRAGONFLY_V2_PUBLISHER_PROVENANCE_AFTER_IMPORT=PASS_PROTECTED'
