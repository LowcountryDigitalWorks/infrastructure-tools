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
    $expectedRoot = Get-LdwDragonflyAdjunctV2TransferPackageRoot
    if ($expectedRoot -notmatch 'normal-user-staging') { throw 'TRANSFER_PACKAGE_ROOT_SHAPE_INVALID' }
    if ($expectedRoot -notmatch '^[a-f0-9]{40}-[a-f0-9]{40}$') {
        if ($expectedRoot.Split('\')[-1] -notmatch '^[a-f0-9]{40}-[a-f0-9]{40}$') { throw 'TRANSFER_RELEASE_IDENTITY_REFUSED' }
    }
    Write-Output 'TRANSFER_CONTRACT_OK'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
