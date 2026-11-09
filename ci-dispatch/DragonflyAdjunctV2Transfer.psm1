# Normal-user only: build the pinned V2 package transfer envelope.
# Source-only. No SSH execution, elevation, installer, token, or provider call.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\DragonflyCanaryAdjunctV2Publisher.psm1"

function Assert-LdwDragonflyAdjunctV2TransferPrincipal {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'TRANSFER_WINDOWS_REQUIRED' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'TRANSFER_ELEVATED_REFUSED' }
}

function Get-LdwDragonflyAdjunctV2TransferPackageRoot {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA) -or -not [IO.Path]::IsPathRooted($env:LOCALAPPDATA)) {
        throw 'TRANSFER_LOCAL_APPDATA_INVALID'
    }
    Join-Path $env:LOCALAPPDATA ('LDW\DragonflyCanaryAdjunct\normal-user-staging\' + $script:ReleaseIdentity)
}

function Assert-LdwDragonflyAdjunctV2NormalUserPackage {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)]$Manifest)
    $expectedRoot = Get-LdwDragonflyAdjunctV2TransferPackageRoot
    if (-not ([IO.Path]::GetFullPath($Root)).Equals([IO.Path]::GetFullPath($expectedRoot),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'TRANSFER_PACKAGE_ROOT_REFUSED'
    }
    $cursor = [IO.Path]::GetFullPath($Root)
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'TRANSFER_REPARSE_PATH_REFUSED' }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    $expectedFields = @('schema','artifact','releaseIdentity','canaryCommit','canaryTree','entryCommit','entryTree','dispatchAuthority','containsCredential','containsBootstrap','containsPrivateEndpoint','files')
    if (@(Compare-Object $expectedFields @($Manifest.PSObject.Properties.Name) -CaseSensitive).Count -or
        $Manifest.schema -ne 2 -or $Manifest.artifact -cne 'ldw-dragonfly-canary-adjunct-v2' -or
        $Manifest.releaseIdentity -cne $script:ReleaseIdentity -or
        $Manifest.canaryCommit -cne $script:CanaryCommit -or $Manifest.canaryTree -cne $script:CanaryTree -or
        $Manifest.entryCommit -cne $script:EntryCommit -or $Manifest.entryTree -cne $script:EntryTree -or
        $Manifest.containsCredential -ne $false -or $Manifest.containsBootstrap -ne $false -or
        $Manifest.containsPrivateEndpoint -ne $false) { throw 'TRANSFER_MANIFEST_PIN_MISMATCH' }
    $authority = $Manifest.dispatchAuthority
    $expectedAuthority = @('commit','tree','blob','rawSha256','windowsSha256','materialization')
    if ($null -eq $authority -or
        @(Compare-Object $expectedAuthority @($authority.PSObject.Properties.Name) -CaseSensitive).Count -or
        $authority.commit -cne $script:DispatchCommit -or $authority.tree -cne $script:DispatchTree -or
        $authority.blob -cne $script:DispatchBlob -or $authority.rawSha256 -cne $script:DispatchRawSha256 -or
        $authority.windowsSha256 -cne $script:DispatchWindowsSha256 -or
        $authority.materialization -cne 'crlf') { throw 'TRANSFER_DISPATCH_PIN_MISMATCH' }
    if (@($Manifest.files).Count -ne $script:Files.Count) { throw 'TRANSFER_FILE_SET_DRIFT' }
    $expectedPaths = @($script:Files.path) + @('manifest.json','ci-dispatch')
    $actualPaths = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction Stop | ForEach-Object {
        if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'TRANSFER_REPARSE_PATH_REFUSED' }
        Get-LdwAdjunctRelativePath -Root $Root -Path $_.FullName
    })
    if (@(Compare-Object $expectedPaths $actualPaths -CaseSensitive).Count) { throw 'TRANSFER_FILE_SET_DRIFT' }
    foreach ($source in $script:Files) {
        $entry = @($Manifest.files | Where-Object path -CEQ $source.path)
        if ($entry.Count -ne 1 -or
            @(Compare-Object @('path','sourceCommit','sourceTree','gitBlob','representation','sha256') @($entry[0].PSObject.Properties.Name) -CaseSensitive).Count -or
            $entry[0].sourceCommit -cne $source.commit -or $entry[0].sourceTree -cne $source.tree -or
            $entry[0].gitBlob -cne $source.blob -or $entry[0].representation -cne $source.representation -or
            $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'TRANSFER_MANIFEST_FILE_PIN_MISMATCH' }
        $file = Join-Path $Root $source.path
        $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'TRANSFER_REPARSE_PATH_REFUSED'
        }
        if ($item.PSIsContainer) { throw 'TRANSFER_FILE_SET_DRIFT' }
        $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sha -cne $entry[0].sha256) { throw 'TRANSFER_FILE_HASH_DRIFT' }
        if ($source.representation -ceq 'raw') {
            if ((Get-LdwAdjunctGitBlobSha1 $file) -cne $source.blob) { throw 'TRANSFER_FILE_BLOB_DRIFT' }
        } elseif ($sha -cne $script:DispatchWindowsSha256) {
            throw 'TRANSFER_DISPATCH_WINDOWS_HASH_MISMATCH'
        }
    }
}

function Build-LdwDragonflyAdjunctV2TransferEnvelope {
    [CmdletBinding()]param()
    Assert-LdwDragonflyAdjunctV2TransferPrincipal
    # The caller cannot choose the source directory, manifest or release.
    $PackageRoot = Get-LdwDragonflyAdjunctV2TransferPackageRoot
    if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) { throw 'TRANSFER_PACKAGE_ROOT_MISSING' }
    $manifestPath = Join-Path $PackageRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'TRANSFER_MANIFEST_MISSING' }
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
    catch { throw 'TRANSFER_MANIFEST_INVALID' }
    # User-writable staging is never a protected publisher root. Validate
    # exact package data without claiming protected ACL/owner authority.
    Assert-LdwDragonflyAdjunctV2NormalUserPackage -Root $PackageRoot -Manifest $manifest
    $files = @{}
    foreach ($source in $script:Files) {
        $path = Join-Path $PackageRoot $source.path
        $bytes = [IO.File]::ReadAllBytes($path)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $entry = @($manifest.files | Where-Object path -CEQ $source.path)
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cne $digest) { throw 'TRANSFER_FILE_HASH_DRIFT' }
        if ($source.representation -ceq 'raw') {
            $prefix = [Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
            $joined = [byte[]]::new($prefix.Length + $bytes.Length)
            [Array]::Copy($prefix,0,$joined,0,$prefix.Length)
            [Array]::Copy($bytes,0,$joined,$prefix.Length,$bytes.Length)
            $h = [Security.Cryptography.SHA1]::Create()
            try { $blob = ([BitConverter]::ToString($h.ComputeHash($joined))).Replace('-','').ToLowerInvariant() }
            finally { $h.Dispose() }
            if ($blob -cne $source.blob) { throw 'TRANSFER_FILE_BLOB_DRIFT' }
        } elseif ($digest -cne $script:DispatchWindowsSha256) {
            throw 'TRANSFER_DISPATCH_WINDOWS_HASH_MISMATCH'
        }
        $files[$source.path] = @{ sha256=$digest; content=[Convert]::ToBase64String($bytes) }
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $finalManifestSha = ([BitConverter]::ToString($sha.ComputeHash($manifestBytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($finalManifestSha -cne $manifestSha) { throw 'TRANSFER_MANIFEST_DRIFT' }
    [ordered]@{
        schema = 1
        marker = 'DRAGONFLY-V2-PACKAGE-TRANSFER-001'
        release_identity = $script:ReleaseIdentity
        manifest_sha256 = $manifestSha
        manifest = $manifest
        manifest_content = [Convert]::ToBase64String($manifestBytes)
        files = $files
    }
}

Export-ModuleMember -Function Assert-LdwDragonflyAdjunctV2TransferPrincipal,Get-LdwDragonflyAdjunctV2TransferPackageRoot,Build-LdwDragonflyAdjunctV2TransferEnvelope
