$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\DragonflyAdjunctV2Transfer.psm1') -Force

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-v2-transfer-contract-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
    $fakePrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($fakePrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output 'SKIP_ELEVATED_SESSION'
        exit 0
    }
    $builder = Get-Command Build-LdwDragonflyAdjunctV2TransferEnvelope -ErrorAction Stop
    if ($builder.Parameters.ContainsKey('PackageRoot')) { throw 'TRANSFER_CALLER_SELECTED_ROOT_REFUSED' }
    $staging = Join-Path ([IO.Path]::GetTempPath()) ('ldw-v2-staging-cap-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        for ($i = 0; $i -lt 33; $i++) {
            [IO.File]::WriteAllText((Join-Path $staging "extra$i.txt"), 'x')
        }
        try {
            Get-LdwDragonflyAdjunctV2BoundedStagingPaths -Root $staging | Out-Null
            throw 'EXPECTED_REFUSAL: TRANSFER_STAGING_ENTRY_CAP_EXCEEDED'
        }
        catch {
            if ($_.Exception.Message -cne 'TRANSFER_STAGING_ENTRY_CAP_EXCEEDED') { throw }
        }

        $staging2 = Join-Path ([IO.Path]::GetTempPath()) ('ldw-v2-staging-size-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $staging2 -Force | Out-Null
        try {
            $big = Join-Path $staging2 'oversized.bin'
            $stream = [IO.File]::Create($big)
            $stream.SetLength(524289)
            $stream.Dispose()
            try {
                Get-LdwDragonflyAdjunctV2BoundedStagingPaths -Root $staging2 | Out-Null
                throw 'EXPECTED_REFUSAL: TRANSFER_STAGING_FILE_TOO_LARGE'
            }
            catch {
                if ($_.Exception.Message -cne 'TRANSFER_STAGING_FILE_TOO_LARGE') { throw }
            }
        }
        finally {
            if (Test-Path -LiteralPath $staging2) { Remove-Item -LiteralPath $staging2 -Recurse -Force }
        }
    }
    finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }

    Write-Output 'TRANSFER_STAGING_PREFLIGHT_OK'

    $expectedRoot = Get-LdwDragonflyAdjunctV2TransferPackageRoot
    if ($expectedRoot -notmatch 'normal-user-staging') { throw 'TRANSFER_PACKAGE_ROOT_SHAPE_INVALID' }
    if ($expectedRoot -notmatch '^[a-f0-9]{40}-[a-f0-9]{40}$') {
        if ($expectedRoot.Split('\')[-1] -notmatch '^[a-f0-9]{40}-[a-f0-9]{40}$') { throw 'TRANSFER_RELEASE_IDENTITY_REFUSED' }
    }
    Write-Output 'TRANSFER_CONTRACT_OK'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
