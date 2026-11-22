"""Read-only Windows Sandbox *device-policy* feasibility signals for Gate C.

No host mutation, Sandbox launch, elevated operation, credentials, or authority.
Even explicit machine policy values are not an independently attested guest.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable

SCHEMA = "ldw.commander.gate_c.sandbox_policy.v1"
CLASSIFICATION = "POLICY_DATA_ONLY_GUEST_NOT_ADMITTED"
POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Windows\Sandbox"
# MappedFolders GPO requires Windows 11 24H2+ (build >= 26100).
MIN_BUILD_FOR_MAPPED_FOLDERS_POLICY = 26100
# Group Policy/CSP device restrictions. Zero means explicitly not allowed.
REQUIRED_POLICIES = (
    "AllowMappedFolders",
    "AllowNetworking",
    "AllowClipboardRedirection",
    "AllowAudioInput",
    "AllowVideoInput",
    "AllowPrinterRedirection",
    "AllowVGPU",
)
DWORD = 4


def _read_policy(name: str) -> tuple[Any, Any]:
    """Read the 64-bit machine-policy view, never write it."""
    import winreg  # Imported only on Windows, after the platform/build check.

    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, 0, access) as key:
        return winreg.QueryValueEx(key, name)


def _windows_build() -> int | None:
    try:
        version = sys.getwindowsversion()
        build = version.build
        return build if type(build) is int and build > 0 else None
    except (AttributeError, OSError, ValueError, TypeError):
        return None


def _classify_entry(value: object) -> str:
    if not isinstance(value, tuple) or len(value) != 2:
        return "INVALID"
    data, kind = value
    if type(data) is not int or type(kind) is not int or kind != DWORD:
        return "INVALID"
    if data == 0:
        return "EXPLICIT_DENY"
    if data == 1:
        return "ALLOWED"
    return "INVALID"


def inspect_device_policy(
    *,
    platform_tag: str | None = None,
    os_build: object = None,
    reader: Callable[[str], object] | None = None,
) -> dict[str, object]:
    """Return bounded unauthenticated policy observations, never permission.

    Injection points exist solely for deterministic non-Windows unit tests.
    If an untrusted process supplies a fake reader/build or tampers with JSON,
    the result remains DATA ONLY and cannot authorize a launch or host action.
    """
    platform = sys.platform if platform_tag is None else platform_tag
    on_windows = platform == "win32"
    build = (_windows_build() if os_build is None else os_build) if on_windows else None
    supported = on_windows and type(build) is int and build >= MIN_BUILD_FOR_MAPPED_FOLDERS_POLICY
    states: dict[str, str] = {name: "NOT_INSPECTED" for name in REQUIRED_POLICIES}
    if supported:
        policy_reader = _read_policy if reader is None else reader
        for name in REQUIRED_POLICIES:
            try:
                states[name] = _classify_entry(policy_reader(name))
            except FileNotFoundError:
                states[name] = "NOT_CONFIGURED"
            except (PermissionError, OSError, AttributeError, ImportError, TypeError, ValueError):
                states[name] = "UNAVAILABLE"
    # Device policy is only one precondition; even all explicit denies NEVER
    # implies trusted owner approval or effective external isolation.
    all_deny = bool(supported and all(v == "EXPLICIT_DENY" for v in states.values()))
    return {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "windows_platform_observed": on_windows,
        "mapped_folder_policy_build_supported": bool(supported),
        "policy_states": states,
        "all_required_policies_explicitly_deny": all_deny,
        "runtime_policy_enforcement_verified": False,
        "post_start_mutation_denial_verified": False,
        "guest_isolation_verified": False,
        "hardware_owner_presence_verified": False,
        "admin_session_authorized": False,
    }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(inspect_device_policy(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
