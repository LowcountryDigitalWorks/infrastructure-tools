#!/usr/bin/env python3
"""Shared REDRIX Gate A3 security invariants for preflight and install."""
from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path
from types import ModuleType

AUTHORIZED_KEYS2_REL = Path(".ssh/authorized_keys2")


def exec_verified_module(data: bytes, module_name: str) -> ModuleType:
    code = compile(data, f"<{module_name}>", "exec", dont_inherit=True)
    module = ModuleType(module_name)
    module.__file__ = f"<{module_name}>"
    exec(code, module.__dict__)
    return module


def _assert_exact_ssh_directory(home: Path, uid: int, installer: ModuleType, error_cls: type[Exception]) -> None:
    ssh = home / ".ssh"
    installer._assert_path_chain(home, ssh / ".sentinel", uid)
    try:
        info = ssh.lstat()
    except FileNotFoundError as exc:
        raise error_cls("REDRIX_SSH_DIR_INVALID") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise error_cls("REDRIX_SSH_DIR_INVALID")


def assert_transport_key_identity(
    home: Path,
    uid: int,
    installer: ModuleType,
    forced_command: str,
    expected_key_sha256: str,
    *,
    error_cls: type[Exception],
    invalid_hash_code: str,
    invalid_key_code: str,
    alternate_present_code: str,
    keys_invalid_code: str,
    keys_not_unique_code: str,
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_key_sha256) is None:
        raise error_cls(invalid_hash_code)

    _assert_exact_ssh_directory(home, uid, installer, error_cls)
    alternate = home / AUTHORIZED_KEYS2_REL
    installer._assert_path_chain(home, alternate, uid)
    if alternate.exists() or alternate.is_symlink():
        raise error_cls(alternate_present_code)

    path = home / installer.AUTHORIZED_KEYS_REL
    installer._assert_path_chain(home, path, uid)
    data = installer._assert_owned_regular(path, uid, 0o600)
    if len(data) > 1024 * 1024 or b"\x00" in data:
        raise error_cls(keys_invalid_code)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls(keys_invalid_code) from exc

    active = [
        raw.strip()
        for raw in text.splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    ]
    if len(active) != 1:
        raise error_cls(keys_not_unique_code)

    command = re.escape(forced_command)
    match = re.fullmatch(
        rf'restrict,command="{command}" (ssh-ed25519) ([A-Za-z0-9+/]+={{0,3}})(?: [^\r\n]*)?',
        active[0],
    )
    if match is None:
        raise error_cls(invalid_key_code)
    key_type, key_data = match.groups()
    key_hash = hashlib.sha256(f"{key_type} {key_data}".encode("ascii")).hexdigest()
    if key_hash != expected_key_sha256:
        raise error_cls(invalid_key_code)


def assert_gate_a3_pre_install_state(
    home: Path,
    uid: int,
    installer: ModuleType,
    forced_command: str,
    expected_transport_key_sha256: str,
    *,
    error_cls: type[Exception],
    require_accepted_115: bool,
    require_no_transaction: bool,
    require_no_receipt: bool,
    transport_error_codes: dict[str, str],
) -> dict[str, object]:
    home = installer._assert_home(home, uid)

    transaction = home / installer.TRANSACTION_REL
    installer._assert_path_chain(home, transaction, uid)
    if require_no_transaction and (transaction.exists() or transaction.is_symlink()):
        raise error_cls("REDRIX_TRANSACTION_RECOVERY_REQUIRED")

    receipt = home / installer.RECEIPT_REL
    installer._assert_path_chain(home, receipt, uid)
    if require_no_receipt and (receipt.exists() or receipt.is_symlink()):
        raise error_cls("REDRIX_PREFLIGHT_RECEIPT_PRESENT")

    baseline, preexisting = installer._recognize_baseline(home, uid)
    if require_accepted_115 and baseline != "accepted-115":
        raise error_cls("REDRIX_PREFLIGHT_BASELINE_NOT_ACCEPTED_115")

    rollback_targets = {rel.as_posix() for _, _, rel, _ in installer.ROLLBACK}
    expected_preexisting = {
        rel.as_posix(): rel.as_posix() in rollback_targets
        for _, _, rel, _ in installer.CURRENT
    }
    if preexisting != expected_preexisting:
        raise error_cls("REDRIX_PREFLIGHT_RESIDUE_PRESENT")

    installer._authorized_keys_digest(home, uid, forced_command)
    assert_transport_key_identity(
        home,
        uid,
        installer,
        forced_command,
        expected_transport_key_sha256,
        error_cls=error_cls,
        **transport_error_codes,
    )
    return {
        "baseline": baseline,
        "preexisting": preexisting,
        "authorizedKeysSha256": hashlib.sha256(
            (home / installer.AUTHORIZED_KEYS_REL).read_bytes()
        ).hexdigest(),
    }
