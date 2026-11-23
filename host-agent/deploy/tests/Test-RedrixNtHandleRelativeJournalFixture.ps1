#Requires -Version 5.1
# TEMP-only nonprivileged #186 research. NO production parent ACL/installer/privileged code.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSEdition -eq 'Core' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) {
    throw 'WINPS51_NATIVE_X64_REQUIRED'
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LdwJournalResearch {
    [StructLayout(LayoutKind.Sequential)]
    public struct UnicodeString {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectAttributes {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IoStatusBlock {
        public IntPtr StatusOrPointer;
        public IntPtr Information;
    }
    public static class Native {
        public static int ObjectAttributesBytes() { return Marshal.SizeOf(typeof(ObjectAttributes)); }
        public static int ObjectNameCollisionStatus() { return unchecked((int)0xC0000035); }
        public static int UnicodeStringBytes() { return Marshal.SizeOf(typeof(UnicodeString)); }
        public static int IoStatusBlockBytes() { return Marshal.SizeOf(typeof(IoStatusBlock)); }
        [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern SafeFileHandle OpenDirectory(
            string path, uint access, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flags, IntPtr template);
        [DllImport("ntdll.dll", ExactSpelling=true)]
        public static extern int NtCreateFile(
            out SafeFileHandle file, uint access, ref ObjectAttributes attributes,
            out IoStatusBlock ioStatus, IntPtr allocationSize, uint fileAttributes,
            uint shareAccess, uint createDisposition, uint createOptions,
            IntPtr eaBuffer, uint eaLength);

        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityInfo(
            SafeFileHandle handle, int objectType, uint requestedInfo,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl,
            out IntPtr securityDescriptor);
        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);
        [DllImport("kernel32.dll", ExactSpelling=true)]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static byte[] ReadFixtureSecurityByHandle(SafeFileHandle journal) {
            if (journal == null || journal.IsInvalid || journal.IsClosed)
                throw new InvalidOperationException("FIXTURE_JOURNAL_HANDLE_INVALID");
            IntPtr sd = IntPtr.Zero;
            // SE_FILE_OBJECT = 1. OWNER | GROUP | DACL = 1 | 2 | 4.
            uint code = GetSecurityInfo(
                journal, 1, 7, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, out sd);
            try {
                if (code != 0 || sd == IntPtr.Zero)
                    throw new InvalidOperationException("FIXTURE_GET_SECURITY_INFO_FAILED_" + code);
                uint length = GetSecurityDescriptorLength(sd);
                if (length < 20 || length > 4096)
                    throw new InvalidOperationException("FIXTURE_SECURITY_LENGTH_INVALID");
                var data = new byte[checked((int)length)];
                Marshal.Copy(sd, data, 0, data.Length);
                return data;
            }
            finally {
                if (sd != IntPtr.Zero && LocalFree(sd) != IntPtr.Zero)
                    throw new InvalidOperationException("FIXTURE_LOCALFREE_FAILED");
            }
        }
    }
}
'@ -ErrorAction Stop
$script:assertions = 0
function Assert([bool]$Condition, [string]$Id) {
    $script:assertions++
    if (-not $Condition) { throw ('NT_JOURNAL_FIXTURE_ASSERT_' + $Id) }
}
function Invoke-FixtureCreate(
    [Microsoft.Win32.SafeHandles.SafeFileHandle]$Root,
    [string]$Leaf, [byte[]]$SecurityBytes) {
    if ($Leaf -cne 'proof-once.journal') { throw 'FIXTURE_NONCANONICAL_LEAF_REFUSED' }
    if ($Root.IsInvalid -or $Root.IsClosed) { throw 'FIXTURE_INVALID_DIRECTORY_HANDLE' }
    $namePtr = [IntPtr]::Zero
    $unicodePtr = [IntPtr]::Zero
    $sdPtr = [IntPtr]::Zero
    try {
        $namePtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Leaf)
        $u = New-Object LdwJournalResearch.UnicodeString
        $u.Length = [uint16]($Leaf.Length * 2)
        $u.MaximumLength = [uint16](($Leaf.Length + 1) * 2)
        $u.Buffer = $namePtr
        $unicodePtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(
            [LdwJournalResearch.Native]::UnicodeStringBytes())
        [Runtime.InteropServices.Marshal]::StructureToPtr($u, $unicodePtr, $false)
        $sdPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($SecurityBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($SecurityBytes, 0, $sdPtr, $SecurityBytes.Length)
        $a = New-Object LdwJournalResearch.ObjectAttributes
        $a.Length = [uint32][LdwJournalResearch.Native]::ObjectAttributesBytes()
        $a.RootDirectory = $Root.DangerousGetHandle()
        $a.ObjectName = $unicodePtr
        $a.Attributes = [uint32]0x1040 # OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE
        $a.SecurityDescriptor = $sdPtr
        $io = New-Object LdwJournalResearch.IoStatusBlock
        # READ/WRITE_DATA, READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE;
        # FILE_CREATE with no share; write-through, non-directory, synchronous, no reparse follow.
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$file = $null
        $status = [LdwJournalResearch.Native]::NtCreateFile(
            [ref]$file, [uint32]0x00120083, [ref]$a, [ref]$io,
            [IntPtr]::Zero, [uint32]0x80, [uint32]0, [uint32]2,
            [uint32]0x00200062, [IntPtr]::Zero, [uint32]0)
        return [pscustomobject]@{
            Status = [int]$status
            Information = [long]$io.Information.ToInt64()
            File = $file
        }
    } finally {
        if ($sdPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($sdPtr) }
        if ($unicodePtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($unicodePtr) }
        if ($namePtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($namePtr) }
    }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-nt-journal-proof-' + [Guid]::NewGuid().ToString('N'))
$programData = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
if ([IO.Path]::GetFullPath($root).StartsWith($programData + '\',
    [StringComparison]::OrdinalIgnoreCase)) {
    throw 'FIXTURE_PRODUCTION_ROOT_REFUSED'
}
$directory = $null
$journal = $null
try {
    [void][IO.Directory]::CreateDirectory($root)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = 'O:' + $sid + 'G:' + $sid + 'D:P(A;;FA;;;' + $sid + ')'
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $bytes = New-Object byte[] ($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($bytes, 0)
    Assert ([LdwJournalResearch.Native]::ObjectAttributesBytes() -eq 48) 'OBJECT_ATTR_ABI'
    Assert ([LdwJournalResearch.Native]::UnicodeStringBytes() -eq 16) 'UNICODE_ABI'
    Assert ([LdwJournalResearch.Native]::IoStatusBlockBytes() -eq 16) 'STATUS_ABI'
    $directory = [LdwJournalResearch.Native]::OpenDirectory(
        $root, [uint32]3221225472, [uint32]3, [IntPtr]::Zero,
        [uint32]3, [uint32]0x02200000, [IntPtr]::Zero)
    Assert (-not $directory.IsInvalid) 'DIRECTORY_HANDLE'
    $negative = $false
    try { Invoke-FixtureCreate $directory '..\escape' $bytes | Out-Null }
    catch { $negative = $_.Exception.Message -ceq 'FIXTURE_NONCANONICAL_LEAF_REFUSED' }
    Assert $negative 'TRAVERSAL_REFUSED'
    $result = Invoke-FixtureCreate $directory 'proof-once.journal' $bytes
    $journal = $result.File
    Assert ($result.Status -eq 0) 'NT_CREATE_STATUS'
    Assert ($result.Information -eq 2) 'FILE_CREATED'
    Assert (-not $journal.IsInvalid) 'VALID_JOURNAL_HANDLE'
    $stream = [IO.FileStream]::new($journal, [IO.FileAccess]::ReadWrite)
    try {
        $record = [Text.Encoding]::ASCII.GetBytes('PREPARED')
        $stream.Write($record, 0, $record.Length)
        $stream.Flush($true)
        $stream.Position = 0
        $buf = New-Object byte[] ($record.Length)
        $size = $stream.Read($buf, 0, $buf.Length)
        Assert ($size -eq $record.Length) 'READBACK_LENGTH'
        Assert ([Text.Encoding]::ASCII.GetString($buf) -ceq 'PREPARED') 'READBACK_BYTES'

        # Verify the ACTUAL created object on its STILL-OPEN exclusive handle.
        # Never reopen by pathname: the fixture must not prove a different file.
        $liveDescriptorBytes = [LdwJournalResearch.Native]::ReadFixtureSecurityByHandle($journal)
        $liveDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $liveDescriptorBytes, 0)
        Assert ($liveDescriptor.Owner.Value -ceq $sid) 'SAME_HANDLE_OWNER'
        Assert ($liveDescriptor.Group.Value -ceq $sid) 'SAME_HANDLE_GROUP'
        Assert ((($liveDescriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)) 'SAME_HANDLE_PROTECTED_DACL'
        Assert ($null -ne $liveDescriptor.DiscretionaryAcl) 'SAME_HANDLE_PRESENT_DACL'
        Assert ($liveDescriptor.DiscretionaryAcl.Count -eq 1) 'SAME_HANDLE_EXACT_ACE_COUNT'
        $ace = $liveDescriptor.DiscretionaryAcl[0]
        Assert ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed) 'SAME_HANDLE_ALLOW_ACE'
        Assert ($ace.AceFlags -eq [Security.AccessControl.AceFlags]::None) 'SAME_HANDLE_NO_INHERITED_ACE'
        Assert ($ace.SecurityIdentifier.Value -ceq $sid) 'SAME_HANDLE_ACE_IDENTITY'
        Assert ($ace.AccessMask -eq 2032127) 'SAME_HANDLE_EXACT_FULL_CONTROL_MASK'
    } finally { $stream.Dispose(); $journal = $null }
    $again = Invoke-FixtureCreate $directory 'proof-once.journal' $bytes
    $noUsableHandle = ($null -eq $again.File -or $again.File.IsInvalid)
    if ($null -ne $again.File) { $again.File.Dispose() }
    Assert ($again.Status -eq [LdwJournalResearch.Native]::ObjectNameCollisionStatus()) 'EXACT_OBJECT_NAME_COLLISION'
    Assert $noUsableHandle 'COLLISION_HAS_NO_USABLE_HANDLE'
    Write-Output ('REDRIX_NT_HANDLE_JOURNAL_TEMP_ONLY=PASS assertions=' + $script:assertions)
} finally {
    if ($null -ne $journal) { $journal.Dispose() }
    if ($null -ne $directory) { $directory.Dispose() }
    # Only our new, globally unique TEMP test directory may be deleted.
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
