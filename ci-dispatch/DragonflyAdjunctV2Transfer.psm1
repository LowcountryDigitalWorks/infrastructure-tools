# Normal-user, source-only bounded transfer builder for the pinned Dragonfly adjunct V2 release.
# Does not execute ssh, mint credentials, or call elevated publisher helpers.
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

function Build-LdwDragonflyAdjunctV2TransferEnvelope {
    [CmdletBinding()]param([Parameter(Mandatory)][string]$PackageRoot)
    Assert-LdwDragonflyAdjunctV2TransferPrincipal
    if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) { throw 'TRANSFER_PACKAGE_ROOT_MISSING' }
    $manifestPath = Join-Path $PackageRoot 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'TRANSFER_MANIFEST_MISSING' }
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
    catch { throw 'TRANSFER_MANIFEST_INVALID' }
    $null = Test-LdwDragonflyCanaryAdjunctV2Core -ReleaseRoot $PackageRoot -ManifestSha256 $manifestSha
    $files = @{}
    foreach ($source in $script:Files) {
        $path = Join-Path $PackageRoot $source.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'TRANSFER_FILE_MISSING' }
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $entry = @($manifest.files | Where-Object path -CEQ $source.path)
        if ($entry.Count -ne 1 -or $entry[0].sha256 -cne $sha) { throw 'TRANSFER_FILE_HASH_DRIFT' }
        $bytes = [IO.File]::ReadAllBytes($path)
        $files[$source.path] = @{
            sha256 = $sha
            content = [Convert]::ToBase64String($bytes)
        }
    }
    [ordered]@{
        schema = 1
        marker = 'DRAGONFLY-V2-PACKAGE-TRANSFER-001'
        release_identity = $script:ReleaseIdentity
        manifest_sha256 = $manifestSha
        manifest = $manifest
        files = $files
    }
}

Export-ModuleMember -Function Assert-LdwDragonflyAdjunctV2TransferPrincipal,Get-LdwDragonflyAdjunctV2TransferPackageRoot,Build-LdwDragonflyAdjunctV2TransferEnvelope
