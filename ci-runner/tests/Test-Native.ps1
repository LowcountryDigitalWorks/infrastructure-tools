[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (-not ('LDW.CiRunner.Native' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot '../Native.cs') }
$directory = Join-Path ([IO.Path]::GetTempPath()) ('ci7-native-tests-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $directory)
$total = 0
function Assert([bool]$Value) { if (-not $Value) { throw 'NATIVE_TEST_ASSERTION_FAILED' } }
function Put32([byte[]]$Bytes,[int]$Offset,[uint32]$Value) { for($i=0;$i -lt 4;$i++) { $Bytes[$Offset+$i]=[byte](($Value -shr (24-8*$i)) -band 255) } }
function Put64([byte[]]$Bytes,[int]$Offset,[uint64]$Value) { for($i=0;$i -lt 8;$i++) { $Bytes[$Offset+$i]=[byte](($Value -shr (56-8*$i)) -band 255) } }
function Get32([byte[]]$Bytes,[int]$Offset) { [uint32]$value=0; for($i=0;$i -lt 4;$i++){$value=($value -shl 8) -bor $Bytes[$Offset+$i]}; $value }
function Fixture([switch]$Compressed) {
    $bytes=[byte[]]::new(16384)
    Put32 $bytes 0 0x514649fb; Put32 $bytes 4 3; Put32 $bytes 20 12
    Put64 $bytes 24 1048576; Put32 $bytes 36 1; Put64 $bytes 40 4096; Put32 $bytes 100 104
    Put64 $bytes 4096 (([uint64]1 -shl 63) -bor 8192)
    $data=[byte[]]::new(4096); for($i=0;$i -lt $data.Length;$i++){$data[$i]=[byte]($i%251)}
    if($Compressed){
        $stream=[IO.MemoryStream]::new()
        $deflate=[IO.Compression.DeflateStream]::new($stream,[IO.Compression.CompressionLevel]::Optimal,$true)
        $deflate.Write($data,0,$data.Length); $deflate.Dispose(); $packed=$stream.ToArray(); $stream.Dispose()
        $sectors=[math]::Ceiling($packed.Length/512)
        Put64 $bytes 8192 (([uint64]1 -shl 62) -bor ([uint64]($sectors-1) -shl 58) -bor 12288)
        [Array]::Copy($packed,0,$bytes,12288,$packed.Length)
    }else{
        Put64 $bytes 8192 (([uint64]1 -shl 63) -bor 12288)
        [Array]::Copy($data,0,$bytes,12288,$data.Length)
    }
    Put64 $bytes 8200 1
    @{Bytes=$bytes;Expected=$data}
}
try {
    foreach($compressed in @($false,$true)){
        $fixture=Fixture -Compressed:$compressed
        $source=Join-Path $directory ('source-'+$compressed+'.qcow2')
        $raw=Join-Path $directory ('disk-'+$compressed+'.raw')
        [IO.File]::WriteAllBytes($source,$fixture.Bytes)
        [LDW.CiRunner.Native]::QcowToRaw($source,$raw)
        $result=[IO.File]::ReadAllBytes($raw)
        Assert ($result.Length -eq 1048576)
        for($i=0;$i -lt 4096;$i++){Assert ($result[$i] -eq $fixture.Expected[$i])}
        for($i=4096;$i -lt $result.Length;$i++){if($result[$i] -ne 0){throw 'SPARSE_CLUSTER_NOT_ZERO'}}
        $total++; 'PASS QCOW2 allocated, compressed, zero and sparse mapping '+$compressed
    }
    foreach($case in @('backing','encryption','incompatible','truncated-l2','reserved-cluster','truncated-deflate')){
        $fixture=Fixture
        switch($case){
            backing {Put64 $fixture.Bytes 8 100}
            encryption {Put32 $fixture.Bytes 32 1}
            incompatible {Put64 $fixture.Bytes 72 8}
            truncated-l2 {Put64 $fixture.Bytes 4096 32768}
            reserved-cluster {Put64 $fixture.Bytes 8192 2}
            truncated-deflate {Put64 $fixture.Bytes 8192 (([uint64]1 -shl 62) -bor 16384)}
        }
        $source=Join-Path $directory ($case+'.qcow2');$raw=Join-Path $directory ($case+'.raw')
        [IO.File]::WriteAllBytes($source,$fixture.Bytes)
        $rejected=$false;try{[LDW.CiRunner.Native]::QcowToRaw($source,$raw)}catch{$rejected=$true}
        Assert $rejected; $total++; 'PASS QCOW2 rejects '+$case
    }
    $raw=Join-Path $directory 'disk-False.raw';$vhd=Join-Path $directory 'fixture.vhd'
    [LDW.CiRunner.Native]::RawToFixedVhd($raw,$vhd)
    $bytes=[IO.File]::ReadAllBytes($vhd);$footer=$bytes[($bytes.Length-512)..($bytes.Length-1)]
    Assert ([Text.Encoding]::ASCII.GetString($footer,0,8) -ceq 'conectix')
    [uint32]$sum=0;for($i=0;$i -lt 512;$i++){if($i -lt 64 -or $i -gt 67){$sum+=$footer[$i]}}
    Assert ((Get32 $footer 64) -eq ([uint32]::MaxValue-$sum))
    Assert ($bytes.Length -eq 1048576+512)
    $info=Get-VHD -Path $vhd -ErrorAction Stop
    Assert ($info.VhdType -eq 'Fixed' -and $info.Size -eq 1048576)
    $total++; 'PASS VHD footer checksum and native Hyper-V import'
    'NATIVE_TESTS=PASS';'TEST_COUNT='+$total
}finally{
    $full=[IO.Path]::GetFullPath($directory);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cnotmatch '^ci7-native-tests-[0-9a-f]{32}$'){throw 'NATIVE_TEST_CLEANUP_PATH_INVALID'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
