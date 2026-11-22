"""Reproducible *read-only* Windows Gate C host preflight (Commander #209).

One exact, non-interactive PowerShell script reads only a few bounded local OS
signals. This never changes host feature/policy, launches a VM, elevates, or
establishes the protected host and owner signer required by Gate C.
"""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

SCHEMA = "ldw.commander.gate_c.g0_host_snapshot.v1"
CLASSIFICATION = "DATA_ONLY_POLICY_SOURCE_UNVERIFIED"
# Fixed script; accepts NO parameters, variables from a model, paths, or host names.
POWERSHELL_PROBE = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Bind CimCmdlets to the Windows PowerShell system module path, never a user module.
# The caller supplies an explicit, non-inherited minimal child environment.
Import-Module -Name (Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
$domain = 'UNKNOWN'
$feature = 'UNKNOWN'
$policyKey = 'UNAVAILABLE'
$policyCount = 0
$gpoFile = 'UNAVAILABLE'
$elevation = 'UNKNOWN'
try {
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($null -ne $system -and $null -ne $system.PartOfDomain) {
        $domain = if ([bool]$system.PartOfDomain) { 'YES' } else { 'NO' }
    }
} catch { }
try {
    $f = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='Containers-DisposableClientVM'" -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $f) {
        if ($f.InstallState -eq 1) { $feature = 'ENABLED' }
        elseif ($f.InstallState -eq 2) { $feature = 'DISABLED' }
    }
} catch { }
try {
    $reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $k = $reg.OpenSubKey('SOFTWARE\Microsoft\PolicyManager\current\device\WindowsSandbox', $false)
        if ($null -eq $k) { $policyKey = 'ABSENT' }
        else {
            $policyKey = 'PRESENT'
            try {
                $fixed = @('AllowMappedFolders','AllowNetworking','AllowClipboardRedirection',
                    'AllowAudioInput','AllowVideoInput','AllowPrinterRedirection','AllowVGPU')
                $names = @($k.GetValueNames())
                $policyCount = @($fixed | Where-Object { $names -contains $_ }).Count
            } finally { $k.Close() }
        }
    } finally { $reg.Close() }
} catch { $policyKey = 'UNAVAILABLE'; $policyCount = 0 }
try {
    $path = Join-Path ([Environment]::SystemDirectory) 'GroupPolicy\Machine\Registry.pol'
    $gpoFile = if (Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop) { 'PRESENT' } else { 'ABSENT' }
} catch { $gpoFile = 'UNAVAILABLE' }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevation = if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'YES' } else { 'NO' }
} catch { }
@{
    domain_joined_hint = $domain
    windows_sandbox_feature = $feature
    policy_manager_windows_sandbox_key = $policyKey
    policy_manager_fixed_value_count = [int]$policyCount
    local_machine_gpo_pol_file = $gpoFile
    operator_token_elevated = $elevation
} | ConvertTo-Json -Compress -Depth 3
'''.strip()

RAW_KEYS = frozenset((
    "domain_joined_hint", "windows_sandbox_feature",
    "policy_manager_windows_sandbox_key", "policy_manager_fixed_value_count",
    "local_machine_gpo_pol_file", "operator_token_elevated",
))


def _pairs_unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError("DUPLICATE_JSON_FIELD")
        result[name] = value
    return result


def _valid_raw(value: Any) -> bool:
    if type(value) is not dict or set(value) != RAW_KEYS:
        return False
    allowed = {
        "domain_joined_hint": {"YES", "NO", "UNKNOWN"},
        "windows_sandbox_feature": {"ENABLED", "DISABLED", "UNKNOWN"},
        "policy_manager_windows_sandbox_key": {"PRESENT", "ABSENT", "UNAVAILABLE"},
        "local_machine_gpo_pol_file": {"PRESENT", "ABSENT", "UNAVAILABLE"},
        "operator_token_elevated": {"YES", "NO", "UNKNOWN"},
    }
    if any(type(value[key]) is not str or value[key] not in variants
           for key, variants in allowed.items()):
        return False
    count = value["policy_manager_fixed_value_count"]
    if type(count) is not int or not 0 <= count <= 7:
        return False
    if value["policy_manager_windows_sandbox_key"] != "PRESENT" and count != 0:
        return False
    return True


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "disposition": reason,
        "domain_joined_hint": "UNKNOWN",
        "windows_sandbox_feature": "UNKNOWN",
        "policy_manager_windows_sandbox_key": "UNAVAILABLE",
        "policy_manager_fixed_value_count": 0,
        "local_machine_gpo_pol_file": "UNAVAILABLE",
        "operator_token_elevated": "UNKNOWN",
        "management_source_verified": False,
        "effective_policy_proven": False,
        "guest_isolation_proven": False,
        "physical_change_executed": False,
        "admin_session_authorized": False,
    }


def _native_system_powershell() -> str | None:
    """Resolve PowerShell using Windows' system directory, never PATH/SystemRoot.

    This is still user-mode discovery, not a protected process attestation.
    """
    try:
        dll = ctypes.WinDLL("kernel32.dll", winmode=0x00000800)
        get_directory = dll.GetSystemDirectoryW
        get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        get_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(512)
        length = get_directory(buffer, len(buffer))
        if type(length) is int and 0 < length < len(buffer):
            return str(Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        pass
    return None


def _trusted_child_environment(executable: str) -> dict[str, str] | None:
    """Fixed environment from the OS-selected Windows PowerShell path.

    No inherited caller PATH, SystemRoot, windir or PSModulePath. This does
    not attest to protected system integrity or grant Gate C authority.
    """
    path = Path(executable)
    if (path.name.casefold() != "powershell.exe"
            or path.parent.name.casefold() != "v1.0"
            or path.parent.parent.name.casefold() != "windowspowershell"
            or path.parent.parent.parent.name.casefold() not in {"system32", "syswow64"}):
        return None
    system_dir = path.parent.parent.parent
    windows_dir = system_dir.parent
    if not windows_dir.is_absolute():
        return None
    return {
        "SystemRoot": str(windows_dir),
        "windir": str(windows_dir),
        "PSModulePath": str(path.parent / "Modules"),
        "PSModuleAnalysisCachePath": "NUL",
        "PATH": str(system_dir),
    }


def collect_g0_snapshot(
    *,
    platform_tag: str | None = None,
    powershell_locator: Callable[[], str | None] | None = None,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Return sanitized hints. Injection points are for offline tests only.

    No data-only JSON is a signed host attestation. The eventual protected
    operator MUST verify host enrollment, preimages and policy provenance.
    """
    platform = sys.platform if platform_tag is None else platform_tag
    if platform != "win32":
        return _blocked("HOLD_NOT_WINDOWS")
    locate = _native_system_powershell if powershell_locator is None else powershell_locator
    try:
        executable = locate()
    except (OSError, TypeError, ValueError, AttributeError):
        return _blocked("HOLD_SYSTEM_DIRECTORY_UNAVAILABLE")
    if not isinstance(executable, str) or not executable or not Path(executable).is_absolute():
        return _blocked("HOLD_SYSTEM_DIRECTORY_UNAVAILABLE")
    child_env = _trusted_child_environment(executable)
    if child_env is None:
        return _blocked("HOLD_SYSTEM_DIRECTORY_UNAVAILABLE")
    run = subprocess.run if runner is None else runner
    try:
        # This is one fixed read-only command. Never use shell=True or a
        # command supplied by the model, an issue, file, or the caller.
        # Output is size-validated AFTER capture, not bounded at pipe-read time.
        completed = run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_PROBE],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
            env=child_env,
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return _blocked("HOLD_PROBE_UNAVAILABLE")
    if type(completed.returncode) is not int or completed.returncode != 0:
        return _blocked("HOLD_PROBE_FAILED")
    raw = completed.stdout
    if not isinstance(raw, str):
        return _blocked("HOLD_INVALID_PROBE_OUTPUT")
    try:
        raw_size = len(raw.encode("utf-8"))
    except UnicodeError:
        # A malformed child stream must not escape the sanitized HOLD result.
        return _blocked("HOLD_INVALID_PROBE_OUTPUT")
    if raw_size > 2048:
        return _blocked("HOLD_INVALID_PROBE_OUTPUT")
    try:
        parsed = json.loads(raw, object_pairs_hook=_pairs_unique)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _blocked("HOLD_INVALID_PROBE_OUTPUT")
    if not _valid_raw(parsed):
        return _blocked("HOLD_INVALID_PROBE_OUTPUT")
    result = _blocked("G0_HINTS_ONLY_AUTHORITY_UNVERIFIED")
    result.update(parsed)
    return result


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(collect_g0_snapshot(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
