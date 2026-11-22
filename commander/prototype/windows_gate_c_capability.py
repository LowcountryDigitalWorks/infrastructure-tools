"""Windows Gate C capability *hints*, never host or Administrator admission.

Read-only, stdlib-only inspection of documented Win32 APIs. A successful result
is NOT proof of owner presence, a protected issuer, a disposable guest, or an
externally enforced sandbox. No ID, path, credential or raw OS detail is emitted.
"""
from __future__ import annotations

import ctypes
import json
import sys
from typing import Any, Callable

SCHEMA = "ldw.commander.gate_c.capability.v1"
CLASSIFICATION = "DATA_ONLY_GATE_C_NOT_AUTHORIZED"
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 20
PF_VIRT_FIRMWARE_ENABLED = 21


def _system_dll(name: str) -> Any:
    """Load only the requested Windows system DLL from System32."""
    return ctypes.WinDLL(name, winmode=LOAD_LIBRARY_SEARCH_SYSTEM32)


def _api_version(loader: Callable[[str], Any]) -> int | None:
    try:
        fn = loader("webauthn.dll").WebAuthNGetApiVersionNumber
        fn.argtypes = []
        fn.restype = ctypes.c_ulong
        value = fn()
        # bool is an int subclass but is not a valid DWORD API version.
        if type(value) is int and 0 < value < 65536:
            return value
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        pass
    return None


def _processor_hints(loader: Callable[[str], Any]) -> tuple[bool | None, bool | None]:
    try:
        fn = loader("kernel32.dll").IsProcessorFeaturePresent
        fn.argtypes = [ctypes.c_ulong]
        fn.restype = ctypes.c_int
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        return None, None

    def hint(index: int) -> bool | None:
        try:
            value = fn(index)
        except (OSError, TypeError, ValueError, OverflowError):
            return None
        if type(value) is not int or value not in (0, 1):
            return None
        return bool(value)

    return hint(PF_VIRT_FIRMWARE_ENABLED), hint(PF_SECOND_LEVEL_ADDRESS_TRANSLATION)


def collect_capability_hints(
    *,
    platform_tag: str | None = None,
    dll_loader: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Return non-authorizing facts. Injected inputs are for deterministic tests.

    In particular, never accept these fields as a signed OS/owner assertion:
    a same-user process can fake the loader, platform or this JSON document.
    """
    platform_tag = sys.platform if platform_tag is None else platform_tag
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "windows_api_inspected": False,
        "webauthn_api_version": None,
        "firmware_virtualization_hint": None,
        "slat_hint": None,
        "owner_presence_verified": False,
        "protected_issuer_verified": False,
        "external_guest_isolation_verified": False,
        "admin_session_authorized": False,
    }
    if platform_tag != "win32":
        return result
    loader = _system_dll if dll_loader is None else dll_loader
    result["windows_api_inspected"] = True
    result["webauthn_api_version"] = _api_version(loader)
    virt, slat = _processor_hints(loader)
    result["firmware_virtualization_hint"] = virt
    result["slat_hint"] = slat
    return result


def main() -> None:
    # No argument may select an identity, host, authority or probe target.
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(collect_capability_hints(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
