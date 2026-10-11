[CmdletBinding()]
param([string]$Root = (Join-Path $env:ProgramData 'LDW/CiRunnerEphemeral'))
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'CiRunner.psm1') -Force
Assert-Ci7Elevated
Initialize-Ci7Root $Root
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
if (Test-Path -LiteralPath $manifest) { Assert-Ci7Base $Root; 'BASE_IMAGE_VERIFICATION=PASS'; exit 0 }
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
$info = Get-VHD -Path $base -ErrorAction Stop
if ($info.VhdType -ne 'Dynamic' -or $info.ParentPath) { throw 'BASE_DISK_TYPE_INVALID' }
$baseHash = (Get-FileHash -LiteralPath $base -Algorithm SHA256).Hash.ToLowerInvariant()
[ordered]@{ Schema = 1; Release = 'noble-20260926'; SourceSha256 = $expected; BaseSha256 = $baseHash; VirtualSize = $info.Size } |
    ConvertTo-Json | Set-Content -LiteralPath $manifest -Encoding utf8NoBOM
(Get-Item -LiteralPath $base).IsReadOnly = $true
Remove-Item -LiteralPath $raw, $vhd
Assert-Ci7Base $Root
'BASE_IMAGE_VERIFICATION=PASS'
