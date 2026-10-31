#!/usr/bin/env python3
"""Read-only pre-install REDRIX Gate A3 preflight.

This helper closes the Gate A packet gap between the accepted #115 baseline and the
receipt-based post-install readback. It performs no install, recovery, rollback,
network, provider, SSH, Tailscale, JIT, QEMU, or credential mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import pwd
import re
import sys
from types import ModuleType

INSTALLER_BLOB = "036aae98e58f454dd761bbbcc591a6c52e12006d"
INSTALLER_PATH = Path(__file__).resolve().with_name("dragonfly_canary_redrix_install.py")
_VERIFIED_INSTALLER_GLOBAL = "__LDW_VERIFIED_INSTALLER_BYTES__"
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_USER = "eddie"
PRODUCTION_UID = 1000


class PreflightError(RuntimeError):
    pass


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _exec_verified_module(data: bytes, module_name: str) -> ModuleType:
    code = compile(data, f"<{module_name}>", "exec", dont_inherit=True)
    module = ModuleType(module_name)
    module.__file__ = f"<{module_name}>"
    exec(code, module.__dict__)
    return module


def _is_in_memory_host() -> bool:
    return str(__file__).startswith("<")


def _installer_bytes_from_host(path: Path = INSTALLER_PATH) -> bytes:
    injected = globals().get(_VERIFIED_INSTALLER_GLOBAL)
    if isinstance(injected, bytes):
        return injected
    if _is_in_memory_host():
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_UNAVAILABLE")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_UNAVAILABLE") from exc


def _load_installer(path: Path = INSTALLER_PATH) -> ModuleType:
    data = _installer_bytes_from_host(path)
    if _git_blob(data) != INSTALLER_BLOB:
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_IDENTITY_MISMATCH")
    return _exec_verified_module(data, "ldw_redrix_gate_a3_installer")


def _gate_a3_transport_error_codes() -> dict[str, str]:
    return {
        "invalid_hash_code": "REDRIX_PREFLIGHT_EXPECTED_TRANSPORT_KEY_SHA256_INVALID",
        "invalid_key_code": "REDRIX_PREFLIGHT_TRANSPORT_KEY_IDENTITY_INVALID",
        "alternate_present_code": "REDRIX_PREFLIGHT_AUTHORIZED_KEYS_ALTERNATE_PRESENT",
        "keys_invalid_code": "REDRIX_PREFLIGHT_AUTHORIZED_KEYS_INVALID",
        "keys_not_unique_code": "REDRIX_PREFLIGHT_AUTHORIZED_KEYS_NOT_UNIQUE",
    }


def preflight_fixture(
    home: Path,
    uid: int,
    installer: ModuleType,
    expected_key_sha256: str,
) -> dict:
    result = installer.assert_gate_a3_pre_install_state(
        home,
        uid,
        installer.FORCED_COMMAND,
        expected_key_sha256,
        error_cls=PreflightError,
        require_accepted_115=True,
        require_no_transaction=True,
        require_no_receipt=True,
        transport_error_codes=_gate_a3_transport_error_codes(),
    )
    return {
        "baseline": result["baseline"],
        "authorizedKeysInvariant": True,
        "transportKeyIdentity": "expected",
        "transactionPending": False,
        "receiptPresent": False,
        "packageOwnedResidue": False,
        "installerBlob": INSTALLER_BLOB,
    }


def _assert_production_identity() -> None:
    try:
        account = pwd.getpwnam(PRODUCTION_USER)
    except KeyError as exc:
        raise PreflightError("REDRIX_OWNER_IDENTITY_INVALID") from exc
    if (
        account.pw_uid != PRODUCTION_UID
        or os.geteuid() != PRODUCTION_UID
        or Path(account.pw_dir) != PRODUCTION_HOME
        or Path.home() != PRODUCTION_HOME
    ):
        raise PreflightError("REDRIX_OWNER_IDENTITY_INVALID")


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only REDRIX Gate A3 preflight")
    parser.add_argument("--expected-transport-key-sha256", required=True)
    args = parser.parse_args()
    try:
        if sys.platform != "linux":
            raise PreflightError("REDRIX_LINUX_REQUIRED")
        _assert_production_identity()
        installer = _load_installer()
        result = preflight_fixture(
            PRODUCTION_HOME,
            PRODUCTION_UID,
            installer,
            args.expected_transport_key_sha256,
        )
        print("REDRIX_CANARY_PREFLIGHT=PASS")
        print("BASELINE=" + result["baseline"])
        print("AUTHORIZED_KEYS_INVARIANT=PASS")
        print("TRANSPORT_KEY_IDENTITY=expected")
        print("TRANSACTION_PENDING=no")
        print("RECEIPT_PRESENT=no")
        print("PACKAGE_OWNED_RESIDUE=no")
        print("INSTALLER_BLOB=" + result["installerBlob"])
        return 0
    except Exception as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "REDRIX_CANARY_PREFLIGHT_FAILED"
        print("REDRIX_CANARY_PREFLIGHT=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
