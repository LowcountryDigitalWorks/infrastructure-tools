#Requires -Version 5.1
<#
.SYNOPSIS
#186 A0 source research: classify ONLY the current Windows process token.
.NOTES
No parameters, token adjustment, impersonation, elevation, file ACL access,
ProgramData access, protected host object, journal, task, JIT or VM operation.
This is a hosted Windows SOURCE-ONLY test; never a privileged action gate.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -cne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSEdition -eq 'Core' -or -not [Environment]::Is64BitProcess) {
    throw 'A0_TOKEN_NATIVE_WINPS51_X64_REQUIRED'
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LdwA0TokenReadOnlyFixture {
    [StructLayout(LayoutKind.Sequential)]
    internal struct Luid {
        public uint LowPart;
        public int HighPart;
    }

    public static class Probe {
        private const uint TokenQuery = 0x000[uint32]8;
        private const int TokenPrivileges = 3;
        private const uint Enabled = 0x0000000[uint32]2;
        private const uint Removed = 0x0000000[uint32]4;
        private const uint KnownPrivilegeFlags = 0x80000007u;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr token, int informationClass, IntPtr buffer,
            int bufferLength, out int returnedLength);

        [DllImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValue(
            string system, string name, out Luid luid);

        public static string Classify(bool present, uint attributes, bool duplicate) {
            if (duplicate) return "HOLD_AMBIGUOUS";
            if (!present) return attributes == [uint32]0 ? "ABSENT" : "HOLD_AMBIGUOUS";
            if ((attributes & ~KnownPrivilegeFlags) != [uint32]0 ||
                (attributes & Removed) != [uint32]0) return "HOLD_AMBIGUOUS";
            return (attributes & Enabled) != [uint32]0 ?
                "PRESENT_ENABLED" : "PRESENT_DISABLED";
        }

        public static bool IsSystemIdentity() {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                return identity.User != null &&
                    String.Equals(identity.User.Value, "S-1-5-18",
                        StringComparison.Ordinal);
            }
        }

        public static string Observe() {
            IntPtr token = IntPtr.Zero;
            IntPtr memory = IntPtr.Zero;
            try {
                if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token) ||
                    token == IntPtr.Zero)
                    throw new InvalidOperationException("TOKEN_READ_ONLY_UNAVAILABLE");

                Luid wanted;
                if (!LookupPrivilegeValue(null, "SeRestorePrivilege", out wanted))
                    throw new InvalidOperationException("TOKEN_READ_ONLY_UNAVAILABLE");

                int required;
                bool initial = GetTokenInformation(token, TokenPrivileges,
                    IntPtr.Zero, 0, out required);
                if (initial || Marshal.GetLastWin32Error() != 122 ||
                    required < 4 || required > 65536)
                    throw new InvalidOperationException("TOKEN_READ_ONLY_UNAVAILABLE");

                memory = Marshal.AllocHGlobal(required);
                int actual;
                if (!GetTokenInformation(token, TokenPrivileges,
                    memory, required, out actual) ||
                    actual < 4 || actual > required)
                    throw new InvalidOperationException("TOKEN_READ_ONLY_UNAVAILABLE");

                int count = Marshal.ReadInt32(memory, 0);
                if (count < 0 || count > (actual - 4) / 12)
                    throw new InvalidOperationException("TOKEN_READ_ONLY_UNAVAILABLE");

                bool found = false;
                bool duplicate = false;
                uint attributes = [uint32]0;
                for (int i = 0; i < count; i++) {
                    int offset = 4 + i * 12;
                    uint low = unchecked((uint)Marshal.ReadInt32(memory, offset));
                    int high = Marshal.ReadInt32(memory, offset + 4);
                    if (low == wanted.LowPart && high == wanted.HighPart) {
                        if (found) duplicate = true;
                        found = true;
                        attributes = unchecked((uint)Marshal.ReadInt32(memory, offset + 8));
                    }
                }
                return Classify(found, attributes, duplicate);
            }
            finally {
                if (memory != IntPtr.Zero) Marshal.FreeHGlobal(memory);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }
    }
}
'@ -ErrorAction Stop

$checks = 0
function Assert-A0([bool]$Condition, [string]$Code) {
    $script:checks++
    if (-not $Condition) { throw ('A0_TOKEN_ASSERT_' + $Code) }
}

Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($false, [uint32]0, $false)) -ceq 'ABSENT') 'ABSENT'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]0, $false)) -ceq 'PRESENT_DISABLED') 'PRESENT_DISABLED'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]1, $false)) -ceq 'PRESENT_DISABLED') 'DISABLED_BY_DEFAULT'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]2, $false)) -ceq 'PRESENT_ENABLED') 'PRESENT_ENABLED'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]2147483650, $false)) -ceq 'PRESENT_ENABLED') 'USED_FOR_ACCESS_FLAG'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]4, $false)) -ceq 'HOLD_AMBIGUOUS') 'REMOVED_REFUSED'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]8, $false)) -ceq 'HOLD_AMBIGUOUS') 'UNKNOWN_FLAG_REFUSED'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($false, [uint32]2, $false)) -ceq 'HOLD_AMBIGUOUS') 'ABSENT_WITH_FLAGS_REFUSED'
Assert-A0 (([LdwA0TokenReadOnlyFixture.Probe]::Classify($true, [uint32]2, $true)) -ceq 'HOLD_AMBIGUOUS') 'DUPLICATE_REFUSED'

$live = [LdwA0TokenReadOnlyFixture.Probe]::Observe()
Assert-A0 ($live -cin @('ABSENT','PRESENT_DISABLED','PRESENT_ENABLED','HOLD_AMBIGUOUS')) 'LIVE_CLASSIFICATION_BOUNDED'
$system = [LdwA0TokenReadOnlyFixture.Probe]::IsSystemIdentity()
Assert-A0 ($system -is [bool]) 'SYSTEM_IDENTITY_BOUNDED'
Write-Output ('REDRIX_A0_TOKEN_READ_ONLY=PASS assertions=' + $script:checks)
Write-Output ('REDRIX_A0_TOKEN_RESTORE=' + $live)
Write-Output ('REDRIX_A0_TOKEN_SYSTEM_PRINCIPAL=' + $system.ToString().ToUpperInvariant())
Write-Output 'REDRIX_A0_TOKEN_PHYSICAL_AUTHORITY=HOLD_SECURITY'
Write-Output 'REDRIX_A0_TOKEN_JOURNAL_AT_CREATE_PROVEN=FALSE'
