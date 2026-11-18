#Requires -Version 5.1
<#
.SYNOPSIS
#186/A0 native WinPS5.1 TEMP-only journal torn-write and replay proof.
No input arguments, protected filesystem action, elevation or runtime mutation.
Even a well-formed COMMITTED record always returns HOLD, never APPLY.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'A0_JOURNAL_WINPS51_X64_REQUIRED'
}

$script:Checks = 0
$script:LF = [string][char]10
$script:StrictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$script:Id = [Guid]::NewGuid().ToString('N')
$script:Pre = 'd7262f4d667814fce0820acbabe2613e352c22614ae7de2105879459c7fbb2a9'
$script:Target = 'd0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41'
$script:Child = '8f40c3b139e861b100c54944e99517c6dad65e9c7ad4831898f97f806af8e626'

function Assert-A0([bool]$Condition, [string]$Name) {
    $script:Checks++
    if (-not $Condition) { throw ('A0_TORN_JOURNAL_ASSERT_' + $Name) }
}
function Get-Sha256Text([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($script:StrictUtf8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}
function New-Record([int]$Sequence, [string]$Phase, [string]$Id, [string]$Child) {
    $payload = ('LDW_A0_TEMP_JOURNAL_V1|' + $Id + '|' + $Sequence + '|' + $Phase +
        '|' + $script:Pre + '|' + $script:Target + '|' + $Child + '|V1_READY_ZERO_TRIGGER')
    return ($payload + '|' + (Get-Sha256Text $payload) + $script:LF)
}
function Test-RecordText([string]$Text) {
    # A digest detects accidental corruption but is NOT an authenticity tag.
    # No input content can ever grant physical recovery or release authority.
    if ([string]::IsNullOrEmpty($Text)) { return 'HOLD_EMPTY' }
    if ($Text.Length -gt 2048 -or $Text.Contains([char]13)) {
        return 'HOLD_ENCODING_OR_SIZE'
    }
    if (-not $Text.EndsWith($script:LF, [StringComparison]::Ordinal)) {
        return 'HOLD_TORN'
    }
    $lines = $Text.Split([char]10)
    if ($lines.Length -lt 2 -or $lines[$lines.Length - 1] -cne '') {
        return 'HOLD_TORN'
    }
    $count = $lines.Length - 1
    if ($count -gt 2) { return 'HOLD_REPLAY' }
    $stages = @('PREPARED','COMMITTED')
    for ($i=0; $i -lt $count; $i++) {
        $part = $lines[$i].Split([char]'|')
        if ($part.Length -ne 9 -or $part[0] -cne 'LDW_A0_TEMP_JOURNAL_V1') {
            return 'HOLD_SHAPE'
        }
        if ($part[1] -cne $script:Id) { return 'HOLD_JOURNAL_ID' }
        if ($part[2] -cne [string]($i+1) -or $part[3] -cne $stages[$i]) {
            return 'HOLD_SEQUENCE'
        }
        if ($part[4] -cne $script:Pre -or $part[5] -cne $script:Target -or
            $part[6] -cne $script:Child -or $part[7] -cne 'V1_READY_ZERO_TRIGGER') {
            return 'HOLD_PIN_DRIFT'
        }
        if ($part[8] -cnotmatch '^[a-f0-9]{64}$') { return 'HOLD_DIGEST_SHAPE' }
        $payload = [string]::Join('|', [string[]]$part[0..7])
        if ((Get-Sha256Text $payload) -cne $part[8]) { return 'HOLD_DIGEST_DRIFT' }
    }
    if ($count -eq 1) { return 'HOLD_PREPARED_UNRESOLVED' }
    return 'HOLD_COMMITTED_UNTRUSTED'
}
function Read-TempJournal([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return 'HOLD_MISSING' }
    $file = $null
    try {
        $file = [IO.FileStream]::new($Path, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::None)
        if ($file.Length -gt 4096 -or $file.Length -eq 0) {
            return 'HOLD_ENCODING_OR_SIZE'
        }
        $b = New-Object byte[] ([int]$file.Length)
        $offset=0
        while($offset -lt $b.Length) {
            $n = $file.Read($b,$offset,($b.Length-$offset))
            if($n -le 0) { return 'HOLD_TORN' }
            $offset += $n
        }
        return (Test-RecordText $script:StrictUtf8.GetString($b))
    }
    catch {
        return 'HOLD_READ_AMBIGUOUS'
    }
    finally { if($null -ne $file) { $file.Dispose() } }
}

$leaf = 'ldw-a0-torn-journal-' + [Guid]::NewGuid().ToString('N')
$root = [IO.Path]::GetFullPath((Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath $leaf))
$programData = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
if ([string]::IsNullOrWhiteSpace($programData) -or
    $root.StartsWith(($programData.TrimEnd('\') + '\'),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'A0_TEMP_ROOT_NOT_DISJOINT'
}
$journal = Join-Path $root 'redrix-ldw-parent-acl-once.journal'
$stream=$null
try {
    [void][IO.Directory]::CreateDirectory($root)
    Assert-A0 (([IO.File]::GetAttributes($root) -band
        [IO.FileAttributes]::ReparsePoint) -eq 0) 'GUID_TEMP_NO_REPARSE'
    Assert-A0 ((Read-TempJournal $journal) -ceq 'HOLD_MISSING') 'MISSING'
    $prep=New-Record 1 'PREPARED' $script:Id $script:Child
    $comm=New-Record 2 'COMMITTED' $script:Id $script:Child
    $stream=[IO.FileStream]::new($journal,[IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,
        [IO.FileOptions]::WriteThrough)
    Assert-A0 ($stream.CanRead -and $stream.CanWrite) 'EXCLUSIVE_CREATE'
    $pb=$script:StrictUtf8.GetBytes($prep)
    $stream.Write($pb,0,$pb.Length)
    $stream.Flush($true)
    $stream.Position=0
    $readPrep=New-Object byte[] ($pb.Length)
    Assert-A0 ($stream.Read($readPrep,0,$readPrep.Length) -eq $readPrep.Length) 'PREPARED_SAME_HANDLE_READ'
    Assert-A0 ((Test-RecordText $script:StrictUtf8.GetString($readPrep)) -ceq
        'HOLD_PREPARED_UNRESOLVED') 'PREPARED_NEVER_APPLY'
    $collision=$false
    try {
        $other=[IO.FileStream]::new($journal,[IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $other.Dispose()
    }
    catch [IO.IOException] { $collision=$true }
    Assert-A0 $collision 'CREATE_NEW_COLLISION'
    $cb=$script:StrictUtf8.GetBytes($comm)
    $stream.Position=$stream.Length
    $stream.Write($cb,0,$cb.Length)
    $stream.Flush($true)
    $stream.Position=0
    $all=New-Object byte[] ([int]$stream.Length)
    Assert-A0 ($stream.Read($all,0,$all.Length) -eq $all.Length) 'COMMITTED_SAME_HANDLE_READ'
    Assert-A0 ((Test-RecordText $script:StrictUtf8.GetString($all)) -ceq
        'HOLD_COMMITTED_UNTRUSTED') 'COMMITTED_NOT_AUTHORITY'
    $stream.Dispose()
    $stream=$null
    Assert-A0 ((Read-TempJournal $journal) -ceq
        'HOLD_COMMITTED_UNTRUSTED') 'CLOSE_REOPEN_HOLD'

    # Simulate a torn on-disk record. No actual reboot/power loss is asserted.
    $stream=[IO.FileStream]::new($journal,[IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $stream.SetLength($stream.Length-7)
    $stream.Flush($true)
    $stream.Dispose()
    $stream=$null
    Assert-A0 ((Read-TempJournal $journal) -ceq 'HOLD_TORN') 'TORN_FILE'
    Assert-A0 ((Test-RecordText $prep) -ceq 'HOLD_PREPARED_UNRESOLVED') 'PREPARED_ONLY'
    Assert-A0 ((Test-RecordText $comm) -ceq 'HOLD_SEQUENCE') 'COMMITTED_WITHOUT_PREPARED'
    Assert-A0 ((Test-RecordText ($prep+$comm+$comm)) -ceq 'HOLD_REPLAY') 'DUPLICATE_COMMIT'
    Assert-A0 ((Test-RecordText ($prep+$prep)) -ceq 'HOLD_SEQUENCE') 'DUPLICATE_PREPARED'
    Assert-A0 ((Test-RecordText ($prep+'BROKEN')) -ceq 'HOLD_TORN') 'PARTIAL_APPEND'
    Assert-A0 ((Test-RecordText ($prep+$comm+[char]13)) -ceq
        'HOLD_ENCODING_OR_SIZE') 'CR_DRIFT'
    $badPre=$prep.Replace($script:Pre,('0'*64))
    Assert-A0 ((Test-RecordText $badPre) -ceq 'HOLD_PIN_DRIFT') 'PREIMAGE_DRIFT'
    $forge=New-Record 1 'PREPARED' $script:Id ('1'*64)
    Assert-A0 ((Test-RecordText $forge) -ceq 'HOLD_PIN_DRIFT') 'FORGED_DIGEST_NEW_PIN'
    $foreign=New-Record 1 'PREPARED' ([Guid]::NewGuid().ToString('N')) $script:Child
    Assert-A0 ((Test-RecordText $foreign) -ceq 'HOLD_JOURNAL_ID') 'REPLAY_ID'
    $checksum=$prep.Substring(0,$prep.Length-3)+'00'+$script:LF
    Assert-A0 ((Test-RecordText $checksum) -ceq 'HOLD_DIGEST_DRIFT') 'BAD_DIGEST'
    Write-Output ('REDRIX_A0_TORN_JOURNAL_TEMP_ONLY=PASS assertions='+$script:Checks)
    Write-Output 'REDRIX_A0_TORN_JOURNAL_POWER_CUT_PROVEN=FALSE'
    Write-Output 'REDRIX_A0_TORN_JOURNAL_SYSTEM_OWNER_PROVEN=FALSE'
    Write-Output 'REDRIX_A0_TORN_JOURNAL_PHYSICAL_AUTHORITY=HOLD_SECURITY'
}
finally {
    if($null -ne $stream) { $stream.Dispose() }
    if(Test-Path -LiteralPath $root -PathType Container) {
        if (([IO.File]::GetAttributes($root) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A0_JOURNAL_CLEANUP_ROOT_REPARSE_REFUSED'
        }
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
