"""Reproducible *read-only* Windows Gate C host preflight (Commander #209).

One exact, non-interactive PowerShell script reads only a few bounded local OS
signals. This never changes host feature/policy, launches a VM, elevates, or
establishes the protected host and owner signer required by Gate C.
"""
from __future__ import annotations

import json
import os
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
    $path = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Registry.pol'
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


def collect_g0_snapshot(
    *,
    platform_tag: str | None = None,
    system_root: str | None = None,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Return sanitized hints. Injection points are for offline tests only.

    No data-only JSON is a signed host attestation. The eventual protected
    operator MUST verify host enrollment, preimages and policy provenance.
    """
    platform = sys.platform if platform_tag is None else platform_tag
    if platform != "win32":
        return _blocked("HOLD_NOT_WINDOWS")
    root = os.environ.get("SystemRoot") if system_root is None else system_root
    if not isinstance(root, str) or not root or not Path(root).is_absolute():
        return _blocked("HOLD_SYSTEM_DIRECTORY_UNAVAILABLE")
    executable = str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    run = subprocess.run if runner is None else runner
    try:
        # This is one fixed read-only command. Never use shell=True or a
        # command supplied by the model, an issue, file, or the caller.
        completed = run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_PROBE],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return _blocked("HOLD_PROBE_UNAVAILABLE")
    if type(completed.returncode) is not int or completed.returncode != 0:
        return _blocked("HOLD_PROBE_FAILED")
    raw = completed.stdout
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 2048:
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
