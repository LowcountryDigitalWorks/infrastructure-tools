#Requires -Version 5.1
<#
.SYNOPSIS
#186/A0: native Windows SetSecurityInfo inheritance propagation experiment.
.DESCRIPTION
Strictly disposable, no-argument Windows PowerShell 5.1 x64 TEMP proof.
Never reads or changes ProgramData, LDW services, protected tasks, or issuer.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'A0_CHILD_PROPAGATION_NATIVE_WINPS51_X64_REQUIRED'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace LdwA0ChildPropagationFixture {
    public static class Native {
        [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern SafeFileHandle CreateFile(
            string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        private static extern uint SetSecurityInfo(
            SafeFileHandle handle, int objectType, uint securityInfo,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool present,
            out IntPtr dacl,
            [MarshalAs(UnmanagedType.Bool)] out bool defaulted);

        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityInfo(
            SafeFileHandle handle, int objectType, uint securityInfo,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

        [DllImport("kernel32.dll", ExactSpelling=true)]
        private static extern IntPtr LocalFree(IntPtr address);

        public static SafeFileHandle OpenFixtureParent(string path) {
            // READ_CONTROL|WRITE_DAC|FILE_READ_ATTRIBUTES only (not MAXIMUM_ALLOWED).
            // Share READ|WRITE|DELETE, so the documented automatic propagation is
            // not suppressed by exclusive access to the parent.
            SafeFileHandle h = CreateFile(path, 0x00060080u, 7u, IntPtr.Zero,
                3u, 0x02200000u, IntPtr.Zero);
            if (h == null || h.IsInvalid) {
                int code = Marshal.GetLastWin32Error();
                if (h != null) h.Dispose();
                throw new Win32Exception(code, "A0_TEMP_PARENT_OPEN_FAILED");
            }
            return h;
        }

        public static void SetFixtureParentDacl(SafeFileHandle parent, byte[] descriptor) {
            if (parent == null || parent.IsClosed || parent.IsInvalid ||
                descriptor == null || descriptor.Length < 20 || descriptor.Length > 4096)
                throw new InvalidOperationException("A0_TEMP_DESCRIPTOR_INVALID");
            IntPtr memory = IntPtr.Zero;
            try {
                memory = Marshal.AllocHGlobal(descriptor.Length);
                Marshal.Copy(descriptor, 0, memory, descriptor.Length);
                bool present, defaulted;
                IntPtr dacl;
                if (!GetSecurityDescriptorDacl(memory, out present, out dacl, out defaulted)
                    || !present || dacl == IntPtr.Zero)
                    throw new InvalidOperationException("A0_TEMP_DACL_INVALID");
                // SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4,
                // PROTECTED_DACL_SECURITY_INFORMATION=0x80000000.
                // This call changes ONLY the disposable TEMP parent DACL.
                uint code = SetSecurityInfo(parent, 1, 0x80000004u,
                    IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (code != 0u)
                    throw new Win32Exception((int)code, "A0_TEMP_SET_SECURITY_INFO_FAILED");
            }
            finally {
                if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory);
            }
        }

        public static byte[] ReadParentSecurity(SafeFileHandle parent) {
            if (parent == null || parent.IsClosed || parent.IsInvalid)
                throw new InvalidOperationException("A0_TEMP_PARENT_HANDLE_INVALID");
            IntPtr sd = IntPtr.Zero;
            uint code = GetSecurityInfo(parent, 1, 7u,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
            try {
                if (code != 0u || sd == IntPtr.Zero)
                    throw new InvalidOperationException("A0_TEMP_PARENT_READ_FAILED");
                uint length = GetSecurityDescriptorLength(sd);
                if (length < 20u || length > 4096u)
                    throw new InvalidOperationException("A0_TEMP_PARENT_SD_LENGTH_INVALID");
                byte[] buffer = new byte[(int)length];
                Marshal.Copy(sd, buffer, 0, buffer.Length);
                return buffer;
            }
            finally {
                if (sd != IntPtr.Zero && LocalFree(sd) != IntPtr.Zero)
                    throw new InvalidOperationException("A0_TEMP_LOCALFREE_FAILED");
            }
        }
    }
}
'@ -ErrorAction Stop

$script:assertions = 0
function Assert-A0([bool]$Condition, [string]$Code) {
    $script:assertions++
    if (-not $Condition) { throw ('A0_CHILD_PROPAGATION_ASSERT_' + $Code) }
}

function Get-InheritedEveryoneReadAttributes([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.GetAccessRules($true, $true,
            [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ceq 'S-1-1-0' -and $rule.IsInherited -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            (([int]$rule.FileSystemRights -band
                [int][Security.AccessControl.FileSystemRights]::ReadAttributes) -ne 0)) {
            return $true
        }
    }
    return $false
}

$root = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath())
    ('ldw-a0-acl-propagation-' + [Guid]::NewGuid().ToString('N'))))
$programData = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
if ([string]::IsNullOrWhiteSpace($programData) -or
    $root.StartsWith(($programData.TrimEnd('\') + '\'),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'A0_CHILD_PROPAGATION_NOT_DISJOINT_FROM_PROGRAMDATA'
}

$protected = Join-Path $root 'protected-child'
$protectedGrandchild = Join-Path $protected 'protected-grandchild'
$unprotected = Join-Path $root 'inheriting-child'
$unprotectedGrandchild = Join-Path $unprotected 'inheriting-grandchild'
$parent = $null
try {
    [void][IO.Directory]::CreateDirectory($root)
    Assert-A0 (([IO.File]::GetAttributes($root) -band
        [IO.FileAttributes]::ReparsePoint) -eq 0) 'ROOT_NO_REPARSE'

    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $self = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
         [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)

    # Establish a predictable initial TEMP-only parent DACL BEFORE children exist.
    # No owner/group changes or privileged token operations.
    $baseline = Get-Acl -LiteralPath $root
    $baseline.SetAccessRuleProtection($true, $false)
    $baseline.SetAccessRule($self)
    [IO.Directory]::SetAccessControl($root, $baseline)

    [void][IO.Directory]::CreateDirectory($protected)
    [void][IO.Directory]::CreateDirectory($unprotected)

    $protectedAcl = Get-Acl -LiteralPath $protected
    $protectedAcl.SetAccessRuleProtection($true, $true)
    [IO.Directory]::SetAccessControl($protected, $protectedAcl)
    [void][IO.Directory]::CreateDirectory($protectedGrandchild)
    [void][IO.Directory]::CreateDirectory($unprotectedGrandchild)

    $preProtected = (Get-Acl -LiteralPath $protected).Sddl
    $preProtectedGrandchild = (Get-Acl -LiteralPath $protectedGrandchild).Sddl
    $preUnprotected = (Get-Acl -LiteralPath $unprotected).Sddl
    $preUnprotectedGrandchild = (Get-Acl -LiteralPath $unprotectedGrandchild).Sddl

    Assert-A0 ((Get-Acl -LiteralPath $protected).AreAccessRulesProtected) 'CHILD_PROTECTED_PRE'
    Assert-A0 (-not (Get-Acl -LiteralPath $unprotected).AreAccessRulesProtected) 'CHILD_UNPROTECTED_PRE'
    Assert-A0 (-not (Get-InheritedEveryoneReadAttributes $protected)) 'PROTECTED_NO_WORLD_BEFORE'
    Assert-A0 (-not (Get-InheritedEveryoneReadAttributes $unprotected)) 'UNPROTECTED_NO_WORLD_BEFORE'

    # Only our disposable TEMP object's existing handle is used for SetSecurityInfo.
    $parent = [LdwA0ChildPropagationFixture.Native]::OpenFixtureParent($root)
    $before = [Security.AccessControl.RawSecurityDescriptor]::new(
        [LdwA0ChildPropagationFixture.Native]::ReadParentSecurity($parent), 0)
    Assert-A0 ($null -ne $before.Owner -and $null -ne $before.Group) 'PRE_PARENT_OWNER_GROUP'

    # The frozen production DACL is NOT copied. This is an unprivileged
    # surrogate with the caller's own SID and a distinct inheritable WORLD
    # ReadAttributes ACE, strictly in a newly created TEMP fixture.
    $fixtureSddl = 'D:PAI(A;OICI;FA;;;' + $sid.Value +
        ')(A;OICI;0x80;;;WD)'
    $surrogate = [Security.AccessControl.RawSecurityDescriptor]::new($fixtureSddl)
    $surrogateBytes = New-Object byte[] ($surrogate.BinaryLength)
    $surrogate.GetBinaryForm($surrogateBytes, 0)
    [LdwA0ChildPropagationFixture.Native]::SetFixtureParentDacl(
        $parent, $surrogateBytes)

    $after = [Security.AccessControl.RawSecurityDescriptor]::new(
        [LdwA0ChildPropagationFixture.Native]::ReadParentSecurity($parent), 0)
    Assert-A0 ($after.Owner.Value -ceq $before.Owner.Value) 'PARENT_OWNER_UNCHANGED'
    Assert-A0 ($after.Group.Value -ceq $before.Group.Value) 'PARENT_GROUP_UNCHANGED'
    Assert-A0 ((($after.ControlFlags -band
        [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)) 'PARENT_DACL_PROTECTED'
    Assert-A0 ($null -ne $after.DiscretionaryAcl) 'PARENT_DACL_PRESENT'

    $postProtected = (Get-Acl -LiteralPath $protected).Sddl
    $postProtectedGrandchild = (Get-Acl -LiteralPath $protectedGrandchild).Sddl
    $postUnprotected = (Get-Acl -LiteralPath $unprotected).Sddl
    $postUnprotectedGrandchild = (Get-Acl -LiteralPath $unprotectedGrandchild).Sddl

    Assert-A0 ($postProtected -ceq $preProtected) 'PROTECTED_CHILD_EXACT_SDDL_PARITY'
    Assert-A0 ($postProtectedGrandchild -ceq $preProtectedGrandchild) 'PROTECTED_DESCENDANT_EXACT_SDDL_PARITY'
    Assert-A0 ($postUnprotected -cne $preUnprotected) 'UNPROTECTED_CHILD_PROPAGATION_OBSERVED'
    Assert-A0 ($postUnprotectedGrandchild -cne $preUnprotectedGrandchild) 'UNPROTECTED_DESCENDANT_PROPAGATION_OBSERVED'
    Assert-A0 ((Get-InheritedEveryoneReadAttributes $unprotected)) 'UNPROTECTED_CHILD_INHERITED_WORLD'
    Assert-A0 ((Get-InheritedEveryoneReadAttributes $unprotectedGrandchild)) 'UNPROTECTED_GRANDCHILD_INHERITED_WORLD'
    Assert-A0 (-not (Get-InheritedEveryoneReadAttributes $protected)) 'PROTECTED_CHILD_NO_INHERITED_WORLD'
    Assert-A0 (-not (Get-InheritedEveryoneReadAttributes $protectedGrandchild)) 'PROTECTED_GRANDCHILD_NO_INHERITED_WORLD'

    Write-Output 'REDRIX_A0_CHILD_PROTECTED_SDDL=UNCHANGED'
    Write-Output 'REDRIX_A0_CHILD_UNPROTECTED_SDDL=CHANGED'
    Write-Output ('REDRIX_A0_CHILD_PROPAGATION_TEMP_ONLY=PASS assertions=' + $script:assertions)
    Write-Output 'REDRIX_A0_CHILD_PROPAGATION_LDW_PROVEN=FALSE'
    Write-Output 'REDRIX_A0_CHILD_PROPAGATION_PHYSICAL_AUTHORITY=HOLD_SECURITY'
}
finally {
    if ($null -ne $parent) { $parent.Dispose() }
    # This is the ONLY removal, the GUID-owned TEMP fixture created above.
    if (Test-Path -LiteralPath $root -PathType Container) {
        if (([IO.File]::GetAttributes($root) -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A0_CHILD_PROPAGATION_CLEANUP_ROOT_REPARSE_REFUSED'
        }
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
