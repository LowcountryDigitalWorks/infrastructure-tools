[CmdletBinding()]
param([string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'), [switch]$ExpandVerifiedBase)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force
Assert-Ci7Elevated
Initialize-Ci7Root $Root
$controllerLock = Enter-Ci7ControllerLock $Root
try {
if (@(Get-ChildItem -LiteralPath (Join-Path $Root 'runs') -Directory).Count -or @(Get-VM | Where-Object Name -CMatch '^ci7-').Count) { throw 'BASE_PREPARATION_REQUIRES_NO_DISPOSABLE_INSTANCES' }
$directory = Join-Path $Root 'base'
Assert-Ci7Path $Root $directory
[void](New-Item -ItemType Directory -Path $directory -Force)
$url = 'https://cloud-images.ubuntu.com/releases/noble/release-20260926/'
$expected = '6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2'
$source = Join-Path $directory 'ubuntu-noble-20260926.qcow2'
$raw = Join-Path $directory 'ubuntu-noble-20260926.raw'
$vhd = Join-Path $directory 'ubuntu-noble-20260926.vhd'
$base = Join-Path $directory 'ubuntu-noble-20260926.vhdx'
$manifest = Join-Path $directory 'provenance.json'
if (Test-Path -LiteralPath $manifest) {
    Assert-Ci7Base $Root
    if ($ExpandVerifiedBase) {
        foreach ($vm in Get-VM) {
            foreach ($disk in Get-VMHardDiskDrive -VM $vm) {
                $info = Get-VHD -Path $disk.Path
                if ([IO.Path]::GetFullPath($disk.Path) -ceq [IO.Path]::GetFullPath($base) -or
                    ($info.ParentPath -and [IO.Path]::GetFullPath($info.ParentPath) -ceq [IO.Path]::GetFullPath($base))) { throw 'BASE_ACTIVE_REFERENCE_REFUSED' }
            }
        }
        try {
            (Get-Item -LiteralPath $base).IsReadOnly = $false
            Resize-VHD -Path $base -SizeBytes 16GB -ErrorAction Stop
            $contract = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
            $contract.VirtualSize = (Get-VHD -Path $base).Size
            $contract.BaseSha256 = (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant()
            $contract | ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding utf8NoBOM
        } finally { (Get-Item -LiteralPath $base).IsReadOnly = $true }
        Assert-Ci7Base $Root
    }
    'BASE_IMAGE_VERIFICATION=PASS'; exit 0
}
if ((Test-Path -LiteralPath $raw) -or (Test-Path -LiteralPath $vhd) -or (Test-Path -LiteralPath $base)) { throw 'BASE_PREPARATION_INCOMPLETE' }
$published = Invoke-WebRequest ($url + 'SHA256SUMS') -TimeoutSec 60
$hashes = if ($published.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($published.Content) } else { [string]$published.Content }
if ($hashes -notmatch ('(?m)^' + $expected + ' \*ubuntu-24\.04-server-cloudimg-amd64\.img\r?$')) { throw 'AUTHORITATIVE_BASE_HASH_CHANGED' }
if (-not (Test-Path -LiteralPath $source)) {
    Invoke-WebRequest ($url + 'ubuntu-24.04-server-cloudimg-amd64.img') -OutFile $source -TimeoutSec 900
}
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw 'BASE_SOURCE_HASH_MISMATCH' }
if (-not ('LDW.CiRunner.Native' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Native.cs') }
[LDW.CiRunner.Native]::QcowToRaw($source, $raw)
[LDW.CiRunner.Native]::RawToFixedVhd($raw, $vhd)
Convert-VHD -Path $vhd -DestinationPath $base -VHDType Dynamic -ErrorAction Stop | Out-Null
Resize-VHD -Path $base -SizeBytes 16GB -ErrorAction Stop
$info = Get-VHD -Path $base -ErrorAction Stop
if ($info.VhdType -ne 'Dynamic' -or $info.ParentPath) { throw 'BASE_DISK_TYPE_INVALID' }
$baseHash = (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant()
[ordered]@{ Schema = 1; Release = 'noble-20260926'; SourceSha256 = $expected; BaseSha256 = $baseHash; VirtualSize = $info.Size } |
    ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding utf8NoBOM
(Get-Item -LiteralPath $base).IsReadOnly = $true
Remove-Item -LiteralPath $raw, $vhd
Assert-Ci7Base $Root
'BASE_IMAGE_VERIFICATION=PASS'
} catch {
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z0-9_]+$') { $code = 'BASE_PREPARATION_FAILED' }
    'BASE_IMAGE_VERIFICATION=FAIL'
    'CLASSIFICATION=' + $code
    exit 1
} finally { $controllerLock.Dispose() }
