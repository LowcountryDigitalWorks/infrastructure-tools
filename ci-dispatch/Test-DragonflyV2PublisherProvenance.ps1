# SOURCE-ONLY, READ-ONLY publication provenance gate. Never invokes the publisher.
# Must be called BEFORE Import-Module, then AFTER Import-Module in the same operator
# PowerShell process; a PASS does not authorize protected publication or Gate B.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidateSet('BeforeImport','AfterImport')][string]$Phase
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$acceptedCommit = 'bc29bedbfe7fe8a545ce3a471e0d575c2921cefe'
$acceptedTree = 'a6eb1d42693793cae2986f973f9e1f2ac2438729'
$acceptedBlob = 'e322a071e5e6e31a909447823e737252770fafef'
$publisherRelativePath = 'ci-dispatch/DragonflyCanaryAdjunctV2Publisher.psm1'
$publisherModuleName = 'DragonflyCanaryAdjunctV2Publisher'

function Read-LdwV2GitValue {
    param([string]$Root,[string[]]$Arguments)
    $values = @(& git -C $Root @Arguments 2>$null)
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
$status = @(& git -C $root status --porcelain --untracked-files=all 2>$null)
if ($LASTEXITCODE -ne 0 -or $status.Count -gt 0) { throw 'V2_PROVENANCE_WORKTREE_DIRTY' }

$folder = Join-Path $root 'ci-dispatch'
$file = Join-Path $folder 'DragonflyCanaryAdjunctV2Publisher.psm1'
Assert-LdwV2NoReparse $folder
Assert-LdwV2NoReparse $file
if ((Get-LdwV2GitBlobSha1 $file) -cne $acceptedBlob) {
    throw 'V2_PROVENANCE_ON_DISK_BLOB_MISMATCH'
}

$loaded = @(Get-Module -Name $publisherModuleName -ErrorAction SilentlyContinue)
if ($Phase -ceq 'BeforeImport') {
    if ($loaded.Count -ne 0) { throw 'V2_PROVENANCE_PREIMPORT_MODULE_ALREADY_LOADED' }
    'DRAGONFLY_V2_PUBLISHER_PROVENANCE_BEFORE_IMPORT=PASS'
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
'DRAGONFLY_V2_PUBLISHER_PROVENANCE_AFTER_IMPORT=PASS'
