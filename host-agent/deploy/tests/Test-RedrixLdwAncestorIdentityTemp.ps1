#Requires -Version 5.1
<#
.SYNOPSIS
A0 #186: synthetic, non-privileged Windows directory HANDLE identity and
rename-race refusal proof. NEVER operates on ProgramData or a protected LDW host.
.NOTES
TEMP test only. Not a parent-ACL migration, owner-admin launcher, or JIT issuer.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'ANCESTOR_IDENTITY_NATIVE_WINPS51_X64_REQUIRED'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LdwA0AncestorIdentityFixture {
    [StructLayout(LayoutKind.Sequential)]
    public struct FileIdInfo {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] FileId;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct AttributeTagInfo {
        public uint FileAttributes;
        public uint ReparseTag;
    }
    public static class Native {
        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateDirectoryHandle(
            string path, uint desiredAccess, uint shareMode,
            IntPtr security, uint disposition, uint flags, IntPtr templateFile);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        private static extern bool FileIdByHandle(
            SafeFileHandle handle, int infoClass, out FileIdInfo info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        private static extern bool AttributesByHandle(
            SafeFileHandle handle, int infoClass, out AttributeTagInfo info, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint FinalNameByHandle(
            SafeFileHandle handle, StringBuilder buffer, uint capacity, uint flags);

        private static SafeFileHandle OpenWithAccess(string path, uint desiredAccess) {
            // OPEN_EXISTING; BACKUP_SEMANTICS|OPEN_REPARSE_POINT;
            // share READ|WRITE (never FILE_SHARE_DELETE).
            SafeFileHandle h = CreateDirectoryHandle(path, desiredAccess, 0x3u,
                IntPtr.Zero, 3u, 0x02200000u, IntPtr.Zero);
            if (h == null || h.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                if (h != null) h.Dispose();
                throw new Win32Exception(error, "TEMP_DIRECTORY_OPEN_FAILED");
            }
            return h;
        }

        public static SafeFileHandle OpenNoDeleteShare(string path) {
            // GENERIC_READ requests data/traverse + READ_CONTROL, not
            // FILE_READ_ATTRIBUTES-only. Attribute-only requests are excluded
            // from ordinary CreateFile share restrictions (Microsoft docs).
            return OpenWithAccess(path, 0x80000000u);
        }

        public static SafeFileHandle OpenAttributeOnlyControl(string path) {
            // Deliberately weak control used ONLY on a disposable TEMP sibling.
            return OpenWithAccess(path, 0x80u);
        }

        public static string Identity(SafeFileHandle h) {
            if (h == null || h.IsInvalid || h.IsClosed)
                throw new InvalidOperationException("TEMP_HANDLE_INVALID");
            FileIdInfo info;
            if (!FileIdByHandle(h, 18, out info, 24u) || info.FileId == null ||
                info.FileId.Length != 16) {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "TEMP_FILE_ID_UNAVAILABLE");
            }
            return info.VolumeSerialNumber.ToString("X16") + "/" +
                BitConverter.ToString(info.FileId);
        }

        public static bool IsReparsePoint(SafeFileHandle h) {
            AttributeTagInfo info;
            if (!AttributesByHandle(h, 9, out info, 8u))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "TEMP_ATTRIBUTE_TAG_UNAVAILABLE");
            return (info.FileAttributes & 0x400u) != 0u;
        }

        public static string FinalName(SafeFileHandle h) {
            StringBuilder s = new StringBuilder(4096);
            uint length = FinalNameByHandle(h, s, (uint)s.Capacity, 0u);
            if (length == 0u || length >= s.Capacity)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "TEMP_FINAL_NAME_UNAVAILABLE");
            return s.ToString();
        }
    }
}
'@ -ErrorAction Stop

$script:assertions = 0
function Assert-Fixture([bool]$condition, [string]$id) {
    $script:assertions++
    if (-not $condition) { throw ('A0_TEMP_IDENTITY_ASSERT_' + $id) }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('ldw-a0-ancestor-id-' + [Guid]::NewGuid().ToString('N'))
$root = [IO.Path]::GetFullPath($root)
$systemRoot = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
if ([string]::IsNullOrWhiteSpace($systemRoot) -or
    $root.StartsWith(($systemRoot.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'A0_TEMP_ROOT_NOT_SEPARATE_FROM_PROGRAMDATA'
}
$ancestorPath = Join-Path $root 'ancestor'
$childPath = Join-Path $ancestorPath 'exact-child'
$controlPath = Join-Path $root 'unlocked-control'
$controlMoved = Join-Path $root 'unlocked-control-moved'
$ancestorMoved = Join-Path $root 'ancestor-moved'
$childMoved = Join-Path $ancestorPath 'exact-child-moved'
$otherPath = Join-Path $root 'unrelated'
$attributeControlPath = Join-Path $root 'attribute-only-control'
$attributeMovedPath = Join-Path $root 'attribute-only-control-moved'
$ancestorProbePath = Join-Path $root 'isolated-ancestor'
$ancestorProbeMovedPath = Join-Path $root 'isolated-ancestor-moved'

$rootHandle = $null
$ancestorHandle = $null
$childHandle = $null
$secondChildHandle = $null
$otherHandle = $null
$attributeControlHandle = $null
$ancestorProbeHandle = $null
try {
    [void][IO.Directory]::CreateDirectory($childPath)
    [void][IO.Directory]::CreateDirectory($controlPath)
    [void][IO.Directory]::CreateDirectory($otherPath)
    [void][IO.Directory]::CreateDirectory($attributeControlPath)
    [void][IO.Directory]::CreateDirectory($ancestorProbePath)
    # An unlocked control must be renameable, making denial below meaningful.
    [IO.Directory]::Move($controlPath, $controlMoved)
    Assert-Fixture (Test-Path -LiteralPath $controlMoved -PathType Container) 'CONTROL_RENAME_ALLOWED'

    # Separate attribute-only control. The result is OBSERVED, not assumed:
    # Microsoft documents that attribute-only requests bypass share restrictions.
    $attributeControlHandle = [LdwA0AncestorIdentityFixture.Native]::OpenAttributeOnlyControl($attributeControlPath)
    $attributeControlId = [LdwA0AncestorIdentityFixture.Native]::Identity($attributeControlHandle)
    $attributeRenameSucceeded = $false
    try {
        [IO.Directory]::Move($attributeControlPath, $attributeMovedPath)
        $attributeRenameSucceeded = $true
    } catch [IO.IOException] { $attributeRenameSucceeded = $false }
    Assert-Fixture ($attributeControlId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($attributeControlHandle)) 'ATTR_ONLY_HANDLE_OBJECT_STILL_SAME'
    if ($attributeRenameSucceeded) {
        Assert-Fixture (Test-Path -LiteralPath $attributeMovedPath -PathType Container) 'ATTR_MOVED_EXISTS'
        Assert-Fixture (-not (Test-Path -LiteralPath $attributeControlPath)) 'ATTR_OLD_NAME_GONE'
    } else {
        Assert-Fixture (Test-Path -LiteralPath $attributeControlPath -PathType Container) 'ATTR_DENIED_NAME_PRESERVED'
    }
    Write-Output ('A0_TEMP_ATTRIBUTE_ONLY_RENAME=' + $(if ($attributeRenameSucceeded) { 'ALLOWED' } else { 'DENIED' }))
    $attributeControlHandle.Dispose()
    $attributeControlHandle = $null

    $rootHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($root)
    $ancestorHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($ancestorPath)
    $childHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($childPath)
    $secondChildHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($childPath)
    $otherHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($otherPath)
    $ancestorProbeHandle = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($ancestorProbePath)

    foreach ($h in @($rootHandle, $ancestorHandle, $childHandle,
                     $secondChildHandle, $otherHandle, $ancestorProbeHandle)) {
        Assert-Fixture (-not [LdwA0AncestorIdentityFixture.Native]::IsReparsePoint($h)) 'NO_REPARSE_HANDLE'
    }

    $rootId = [LdwA0AncestorIdentityFixture.Native]::Identity($rootHandle)
    $ancestorId = [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorHandle)
    $childId = [LdwA0AncestorIdentityFixture.Native]::Identity($childHandle)
    Assert-Fixture ($childId -ceq
        [LdwA0AncestorIdentityFixture.Native]::Identity($secondChildHandle)) 'REOPEN_SAME_ID'
    Assert-Fixture ($childId -cne
        [LdwA0AncestorIdentityFixture.Native]::Identity($otherHandle)) 'UNRELATED_ID_DIFFERS'
    Assert-Fixture ($ancestorId -cne $childId -and $rootId -cne $ancestorId) 'ANCESTOR_IDS_DISTINCT'

    # The normalized final path must identify the exact disposable object.
    $final = [LdwA0AncestorIdentityFixture.Native]::FinalName($childHandle)
    $expected = '\\?\' + [IO.Path]::GetFullPath($childPath)
    Assert-Fixture ($final -ieq $expected) 'SAME_HANDLE_FINAL_PATH'

    # Use independent child and ancestor probes, so one result cannot hide
    # the other; NEVER treat a successful rename as a security PASS.
    $childRenameDenied = $false
    try { [IO.Directory]::Move($childPath, $childMoved) }
    catch [IO.IOException] { $childRenameDenied = $true }
    $ancestorRenameDenied = $false
    try { [IO.Directory]::Move($ancestorProbePath, $ancestorProbeMovedPath) }
    catch [IO.IOException] { $ancestorRenameDenied = $true }
    $oldChildExists = Test-Path -LiteralPath $childPath -PathType Container
    $movedChildExists = Test-Path -LiteralPath $childMoved -PathType Container
    $oldAncestorExists = Test-Path -LiteralPath $ancestorProbePath -PathType Container
    $movedAncestorExists = Test-Path -LiteralPath $ancestorProbeMovedPath -PathType Container
    Assert-Fixture ($childId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($childHandle)) 'CHILD_HANDLE_SAME_OBJECT_AFTER_ATTEMPT'
    Assert-Fixture ($ancestorId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorHandle)) 'CHAIN_ANCESTOR_HANDLE_SAME_AFTER_ATTEMPT'
    Write-Output ('A0_TEMP_GENERIC_READ_CHILD_RENAME=' + $(if ($childRenameDenied) { 'DENIED' } else { 'ALLOWED' }))
    Write-Output ('A0_TEMP_GENERIC_READ_ANCESTOR_RENAME=' + $(if ($ancestorRenameDenied) { 'DENIED' } else { 'ALLOWED' }))
    Assert-Fixture $childRenameDenied 'CHILD_RENAME_REFUSED_HELD_GENERIC_READ_HANDLE'
    Assert-Fixture $ancestorRenameDenied 'ISOLATED_ANCESTOR_RENAME_REFUSED_HELD_GENERIC_READ_HANDLE'
    Assert-Fixture ($oldChildExists -and -not $movedChildExists) 'CHILD_NAME_STABLE'
    Assert-Fixture ($oldAncestorExists -and -not $movedAncestorExists) 'ISOLATED_ANCESTOR_NAME_STABLE'

    Assert-Fixture (Test-Path -LiteralPath $childPath -PathType Container) 'PATH_STILL_EXISTS'
    Assert-Fixture (-not (Test-Path -LiteralPath $ancestorMoved)) 'ANCESTOR_NOT_REPLACED'
    Assert-Fixture ($childId -ceq
        [LdwA0AncestorIdentityFixture.Native]::Identity($childHandle)) 'CHILD_ID_STABLE'
    Assert-Fixture ($ancestorId -ceq
        [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorHandle)) 'ANCESTOR_ID_STABLE'
    Assert-Fixture ($rootId -ceq
        [LdwA0AncestorIdentityFixture.Native]::Identity($rootHandle)) 'ROOT_ID_STABLE'
    Write-Output ('REDRIX_A0_ANCESTOR_IDENTITY_TEMP=PASS assertions=' + $script:assertions)
}
finally {
    foreach ($h in @($otherHandle, $secondChildHandle, $childHandle,
                     $ancestorProbeHandle, $attributeControlHandle,
                     $ancestorHandle, $rootHandle)) {
        if ($null -ne $h) { $h.Dispose() }
    }
    # The ONLY deletion is the UUID-named TEMP tree created by this fixture.
    if (Test-Path -LiteralPath $root -PathType Container) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
