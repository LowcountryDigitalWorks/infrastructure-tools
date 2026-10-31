#!/usr/bin/env python3
"""Read-only pre-install REDRIX Gate A3 preflight.

This helper closes the Gate A packet gap between the accepted #115 baseline and the
receipt-based post-install readback. It performs no install, recovery, rollback,
network, provider, SSH, Tailscale, JIT, QEMU, or credential mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from types import ModuleType

INSTALLER_BLOB = "889cff6d25aff80963c21070e994406414b272a4"
INSTALLER_PATH = Path(__file__).resolve().with_name("dragonfly_canary_redrix_install.py")
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_USER = "eddie"
PRODUCTION_UID = 1000
AUTHORIZED_KEYS2_REL = Path(".ssh/authorized_keys2")


class PreflightError(RuntimeError):
    pass


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _load_installer(path: Path = INSTALLER_PATH) -> ModuleType:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_UNAVAILABLE") from exc
    if _git_blob(data) != INSTALLER_BLOB:
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_IDENTITY_MISMATCH")
    spec = importlib.util.spec_from_file_location("ldw_redrix_gate_a3_installer", path)
    if spec is None or spec.loader is None:
        raise PreflightError("REDRIX_PREFLIGHT_INSTALLER_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_exact_ssh_directory(home: Path, uid: int, installer: ModuleType) -> None:
    ssh = home / ".ssh"
    installer._assert_path_chain(home, ssh / ".sentinel", uid)
    try:
        info = ssh.lstat()
    except FileNotFoundError as exc:
        raise PreflightError("REDRIX_PREFLIGHT_SSH_DIR_INVALID") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PreflightError("REDRIX_PREFLIGHT_SSH_DIR_INVALID")


def _assert_transport_key_identity(
    home: Path,
    uid: int,
    installer: ModuleType,
    expected_key_sha256: str,
) -> None:
    if re.fullmatch(r"[a-f0-9]{64}", expected_key_sha256) is None:
        raise PreflightError("REDRIX_PREFLIGHT_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")

    _assert_exact_ssh_directory(home, uid, installer)
    alternate = home / AUTHORIZED_KEYS2_REL
    installer._assert_path_chain(home, alternate, uid)
    if alternate.exists() or alternate.is_symlink():
        raise PreflightError("REDRIX_PREFLIGHT_AUTHORIZED_KEYS_ALTERNATE_PRESENT")

    path = home / installer.AUTHORIZED_KEYS_REL
    installer._assert_path_chain(home, path, uid)
    data = installer._assert_owned_regular(path, uid, 0o600)
    if len(data) > 1024 * 1024 or b"\x00" in data:
        raise PreflightError("REDRIX_PREFLIGHT_AUTHORIZED_KEYS_INVALID")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreflightError("REDRIX_PREFLIGHT_AUTHORIZED_KEYS_INVALID") from exc

    active = [
        raw.strip()
        for raw in text.splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    ]
    if len(active) != 1:
        raise PreflightError("REDRIX_PREFLIGHT_AUTHORIZED_KEYS_NOT_UNIQUE")

    command = re.escape(installer.FORCED_COMMAND)
    match = re.fullmatch(
        rf'restrict,command="{command}" (ssh-ed25519) ([A-Za-z0-9+/]+={{0,3}})(?: [^\r\n]*)?',
        active[0],
    )
    if match is None:
        raise PreflightError("REDRIX_PREFLIGHT_TRANSPORT_KEY_IDENTITY_INVALID")
    key_type, key_data = match.groups()
    key_hash = hashlib.sha256(f"{key_type} {key_data}".encode("ascii")).hexdigest()
    if key_hash != expected_key_sha256:
        raise PreflightError("REDRIX_PREFLIGHT_TRANSPORT_KEY_IDENTITY_INVALID")


def preflight_fixture(
    home: Path,
    uid: int,
    installer: ModuleType,
    expected_key_sha256: str,
) -> dict:
    home = installer._assert_home(home, uid)

    transaction = home / installer.TRANSACTION_REL
    installer._assert_path_chain(home, transaction, uid)
    if transaction.exists() or transaction.is_symlink():
        raise PreflightError("REDRIX_TRANSACTION_RECOVERY_REQUIRED")

    receipt = home / installer.RECEIPT_REL
    installer._assert_path_chain(home, receipt, uid)
    if receipt.exists() or receipt.is_symlink():
        raise PreflightError("REDRIX_PREFLIGHT_RECEIPT_PRESENT")

    baseline, preexisting = installer._recognize_baseline(home, uid)
    if baseline != "accepted-115":
        raise PreflightError("REDRIX_PREFLIGHT_BASELINE_NOT_ACCEPTED_115")

    rollback_targets = {rel.as_posix() for _, _, rel, _ in installer.ROLLBACK}
    expected_preexisting = {
        rel.as_posix(): rel.as_posix() in rollback_targets
        for _, _, rel, _ in installer.CURRENT
    }
    if preexisting != expected_preexisting:
        raise PreflightError("REDRIX_PREFLIGHT_RESIDUE_PRESENT")

    # Preserve the accepted installer restriction check, then independently pin
    # the exact #115 public-key identity so A3 cannot silently accept a swapped key.
    installer._authorized_keys_digest(home, uid, installer.FORCED_COMMAND)
    _assert_transport_key_identity(home, uid, installer, expected_key_sha256)
    return {
        "baseline": baseline,
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
