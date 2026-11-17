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

        public static SafeFileHandle OpenDeleteCapableControl(string path) {
            // Fixture's PRE-EXISTING hostile handle requests DELETE access
            // while it allows all shares; later no-delete-share opens must
            // reject rather than silently treating this chain as protected.
            SafeFileHandle h = CreateDirectoryHandle(path, 0x80010000u, 0x7u,
                IntPtr.Zero, 3u, 0x02200000u, IntPtr.Zero);
            if (h == null || h.IsInvalid) {
                int error = Marshal.GetLastWin32Error();
                if (h != null) h.Dispose();
                throw new Win32Exception(error, "TEMP_DELETE_CAPABLE_OPEN_FAILED");
            }
            return h;
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

function Invoke-TempRenameProbe([string]$source, [string]$destination) {
    # Exercise only fixture-owned, fixed TEMP paths. A successful move must
    # NEVER become an accepted security result.
    try {
        [IO.Directory]::Move($source, $destination)
        return [pscustomobject]@{ Denied = $false; HResult = 'NONE'; Win32 = 0 }
    } catch [IO.IOException] {
        $number = ([long]$_.Exception.HResult -band 4294967295L)
        return [pscustomobject]@{
            Denied = $true
            HResult = ('0x{0:X8}' -f $number)
            Win32 = [int]($number -band 65535)
        }
    } catch [UnauthorizedAccessException] {
        # Directory.Move may surface ERROR_ACCESS_DENIED as this exception
        # rather than IOException. The downstream assertion still requires
        # Win32 5 or 32, and refuses every other exception or success.
        $number = ([long]$_.Exception.HResult -band 4294967295L)
        return [pscustomobject]@{
            Denied = $true
            HResult = ('0x{0:X8}' -f $number)
            Win32 = [int]($number -band 65535)
        }
    }
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
$childMoved = Join-Path $ancestorPath 'exact-child-moved'
$nestedAncestorMoved = Join-Path $root 'ancestor-with-child-moved'
$otherPath = Join-Path $root 'unrelated'
$attributeControlPath = Join-Path $root 'attribute-only-control'
$attributeMovedPath = Join-Path $root 'attribute-only-control-moved'
$ancestorProbePath = Join-Path $root 'isolated-ancestor'
$ancestorProbeMovedPath = Join-Path $root 'isolated-ancestor-moved'
$deleteControlPath = Join-Path $root 'preexisting-delete-handle'

$rootHandle = $null
$ancestorHandle = $null
$childHandle = $null
$secondChildHandle = $null
$otherHandle = $null
$attributeControlHandle = $null
$ancestorProbeHandle = $null
$deleteCapableHandle = $null
try {
    [void][IO.Directory]::CreateDirectory($childPath)
    [void][IO.Directory]::CreateDirectory($controlPath)
    [void][IO.Directory]::CreateDirectory($otherPath)
    [void][IO.Directory]::CreateDirectory($attributeControlPath)
    [void][IO.Directory]::CreateDirectory($ancestorProbePath)
    [void][IO.Directory]::CreateDirectory($deleteControlPath)
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
        # Object identity persists, but its canonical name changed. A new
        # directory at the former path must have a DIFFERENT FileIdInfo.
        $movedExpected = '\\?\' + [IO.Path]::GetFullPath($attributeMovedPath)
        Assert-Fixture (([LdwA0AncestorIdentityFixture.Native]::FinalName($attributeControlHandle)) -ieq $movedExpected) 'ATTR_WEAK_HANDLE_FINAL_NAME_CHANGED'
        [void][IO.Directory]::CreateDirectory($attributeControlPath)
        $replacementHandle = $null
        try {
            $replacementHandle = [LdwA0AncestorIdentityFixture.Native]::OpenAttributeOnlyControl($attributeControlPath)
            Assert-Fixture ([LdwA0AncestorIdentityFixture.Native]::Identity($replacementHandle) -cne $attributeControlId) 'ATTR_ORIGINAL_PATH_REPLACED_NEW_OBJECT'
            $oldExpected = '\\?\' + [IO.Path]::GetFullPath($attributeControlPath)
            Assert-Fixture (([LdwA0AncestorIdentityFixture.Native]::FinalName($replacementHandle)) -ieq $oldExpected) 'ATTR_REPLACEMENT_CANONICAL_PATH'
        }
        finally {
            if ($null -ne $replacementHandle) { $replacementHandle.Dispose() }
        }
    } else {
        Assert-Fixture (Test-Path -LiteralPath $attributeControlPath -PathType Container) 'ATTR_DENIED_NAME_PRESERVED'
    }
    Write-Output ('A0_TEMP_ATTRIBUTE_ONLY_RENAME=' + $(if ($attributeRenameSucceeded) { 'ALLOWED' } else { 'DENIED' }))
    $attributeControlHandle.Dispose()
    $attributeControlHandle = $null

    # Adversarial negative: an existing DELETE-capable open predates our
    # proposed no-delete-sharing hold. The new protected open MUST refuse.
    # This is an isolated TEMP sibling, never the actual LDW parent.
    $deleteCapableHandle = [LdwA0AncestorIdentityFixture.Native]::OpenDeleteCapableControl($deleteControlPath)
    $denyCode = -1
    try {
        $unexpected = [LdwA0AncestorIdentityFixture.Native]::OpenNoDeleteShare($deleteControlPath)
        if ($null -ne $unexpected) { $unexpected.Dispose() }
        throw 'A0_TEMP_DELETE_CAPABLE_UNEXPECTED_SECOND_HANDLE'
    }
    catch [ComponentModel.Win32Exception] {
        $denyCode = [int]$_.Exception.NativeErrorCode
    }
    Assert-Fixture ($denyCode -eq 32) 'PREEXISTING_DELETE_CAPABLE_HANDLE_MUST_REFUSE'
    Assert-Fixture (Test-Path -LiteralPath $deleteControlPath -PathType Container) 'DELETE_CAPABLE_CONTROL_PATH_UNCHANGED'
    Write-Output ('A0_TEMP_PREEXISTING_DELETE_HANDLE_REOPEN=DENIED Win32=' + $denyCode)
    $deleteCapableHandle.Dispose()
    $deleteCapableHandle = $null

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
    $isolatedAncestorId = [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorProbeHandle)
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
    $childProbe = Invoke-TempRenameProbe $childPath $childMoved
    $ancestorProbe = Invoke-TempRenameProbe $ancestorProbePath $ancestorProbeMovedPath
    # Real nested ancestor topology: parent with an OPEN descendant, both
    # held with substantive access. The isolated probe alone isn't this case.
    $nestedProbe = Invoke-TempRenameProbe $ancestorPath $nestedAncestorMoved
    $oldChildExists = Test-Path -LiteralPath $childPath -PathType Container
    $movedChildExists = Test-Path -LiteralPath $childMoved -PathType Container
    $oldAncestorExists = Test-Path -LiteralPath $ancestorProbePath -PathType Container
    $movedAncestorExists = Test-Path -LiteralPath $ancestorProbeMovedPath -PathType Container
    $nestedMovedExists = Test-Path -LiteralPath $nestedAncestorMoved -PathType Container
    Assert-Fixture ($childId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($childHandle)) 'CHILD_HANDLE_SAME_OBJECT_AFTER_ATTEMPT'
    Assert-Fixture ($ancestorId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorHandle)) 'CHAIN_ANCESTOR_HANDLE_SAME_AFTER_ATTEMPT'
    Assert-Fixture ($isolatedAncestorId -ceq [LdwA0AncestorIdentityFixture.Native]::Identity($ancestorProbeHandle)) 'ISOLATED_ANCESTOR_HANDLE_SAME_AFTER_ATTEMPT'
    Write-Output ('A0_TEMP_GENERIC_READ_CHILD_RENAME=' + $(if ($childProbe.Denied) { 'DENIED' } else { 'ALLOWED' }) + ' HRESULT=' + $childProbe.HResult)
    Write-Output ('A0_TEMP_GENERIC_READ_ANCESTOR_RENAME=' + $(if ($ancestorProbe.Denied) { 'DENIED' } else { 'ALLOWED' }) + ' HRESULT=' + $ancestorProbe.HResult)
    Write-Output ('A0_TEMP_GENERIC_READ_NESTED_ANCESTOR_RENAME=' + $(if ($nestedProbe.Denied) { 'DENIED' } else { 'ALLOWED' }) + ' HRESULT=' + $nestedProbe.HResult)
    # Strict refusal: only Windows ERROR_ACCESS_DENIED (5) or
    # ERROR_SHARING_VIOLATION (32) count as a matching negative result.
    # Other I/O faults cannot fake rename protection.
    foreach ($probe in @($childProbe, $ancestorProbe, $nestedProbe)) {
        Assert-Fixture $probe.Denied 'PROBE_DENIED_NOT_SILENT_FAILURE'
        Assert-Fixture ($probe.Win32 -in @(5,32)) 'EXPECTED_WINDOWS_RENAME_DENIAL_CODE'
    }
    Assert-Fixture ($oldChildExists -and -not $movedChildExists) 'CHILD_NAME_STABLE'
    Assert-Fixture ($oldAncestorExists -and -not $movedAncestorExists) 'ISOLATED_ANCESTOR_NAME_STABLE'
    Assert-Fixture (-not $nestedMovedExists) 'NESTED_ANCESTOR_NAME_STABLE'
    Assert-Fixture (([LdwA0AncestorIdentityFixture.Native]::FinalName($childHandle)) -ieq $expected) 'CHILD_FINAL_NAME_STABLE_AFTER_NESTED_PROBE'

    Assert-Fixture (Test-Path -LiteralPath $childPath -PathType Container) 'PATH_STILL_EXISTS'
    Assert-Fixture (Test-Path -LiteralPath $ancestorPath -PathType Container) 'ORIGINAL_CHAIN_ANCESTOR_PRESERVED'
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
                     $ancestorProbeHandle, $attributeControlHandle, $deleteCapableHandle,
                     $ancestorHandle, $rootHandle)) {
        if ($null -ne $h) { $h.Dispose() }
    }
    # The ONLY deletion is the UUID-named TEMP tree created by this fixture.
    if (Test-Path -LiteralPath $root -PathType Container) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
