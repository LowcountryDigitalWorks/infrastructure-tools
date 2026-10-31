#!/usr/bin/env python3
"""Fail-closed REDRIX install/readback/recovery/rollback for accepted canary source.

Production paths and identity are fixed. Tests import the core functions with
isolated fixture homes; no production root override is exposed by the CLI.
The helper never edits authorized_keys, sshd, Tailscale, credentials, or provider state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import sys
import tarfile
import tempfile
from typing import Any

SOURCE_COMMIT = "78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca"
SOURCE_TREE = "5f54ee5b76f49250db1358f058745cb30b6587ef"
ROLLBACK_COMMIT = "4fed47d8d81833b2978f4ea03ffd0f5b86126008"
ROLLBACK_TREE = "076069fe4437cea2538a9333b45ee47025bc9f2d"
PACKAGE = "ldw-dragonfly-canary-source-v1"
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_USER = "eddie"
PRODUCTION_UID = 1000
TRANSACTION_REL = Path(".local/state/ldw/dragonfly-canary-publication/install-transaction.json")
RECEIPT_REL = Path(".local/state/ldw/dragonfly-canary-publication/install-receipt.json")
AUTHORIZED_KEYS_REL = Path(".ssh/authorized_keys")
AUTHORIZED_KEYS2_REL = Path(".ssh/authorized_keys2")
RECEIVER_REL = Path(".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py")
FORCED_COMMAND = "/home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"

CURRENT = (
    ("dragonfly-jit/ssh_forced_receiver.py", "88b527fa4b9b7060216c661d58edf2e97034dafa", RECEIVER_REL, 0o700),
    ("dragonfly-jit/handoff_contract.py", "cedf75fb360f05893afea119782f646da8a2e28b", Path(".local/lib/ldw-dragonfly-jit/handoff_contract.py"), 0o600),
    ("dragonfly-jit/canary_executor.py", "c8c51040b99b0f2f8fd6b10156395244505d61cc", Path(".local/lib/ldw-dragonfly-jit/canary_executor.py"), 0o600),
    ("dragonfly-jit/dragonfly_jit.py", "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a", Path(".local/lib/ldw-dragonfly-jit/dragonfly_jit.py"), 0o600),
    ("dragonfly-jit/canary-guest/bootstrap.sh", "0fa167cba3f30652caac3bf822a616f31183d62a", Path(".local/lib/ldw-dragonfly-jit/canary-guest/bootstrap.sh"), 0o700),
    ("ci-runner/guest/run-one.sh", "a17ee1fa2ae307ce142572eb7dff9b2bbcfb56ee", Path(".local/lib/ci-runner/guest/run-one.sh"), 0o755),
    ("ci-runner/guest/ci7-runner.service", "b5a7cdad0d7ec457b3aacee59167454a5078022e", Path(".local/lib/ci-runner/guest/ci7-runner.service"), 0o644),
)
ROLLBACK = (
    ("dragonfly-jit/ssh_forced_receiver.py", "bb7401de594623aa3f879150a92b20f0f6bbf607", RECEIVER_REL, 0o700),
    ("dragonfly-jit/handoff_contract.py", "2f7892275bacd9f56abaa0cdf204f46f79c046c0", Path(".local/lib/ldw-dragonfly-jit/handoff_contract.py"), 0o600),
)
PREEXISTING_KEYS = {rel.as_posix() for _, _, rel, _ in CURRENT}


def _assert_exact_ssh_directory(home: Path, uid: int, error_cls: type[Exception]) -> None:
    ssh = home / ".ssh"
    _assert_path_chain(home, ssh / ".sentinel", uid)
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
    forced_command: str,
    expected_key_sha256: str | None,
    *,
    error_cls: type[Exception],
    invalid_hash_code: str,
    invalid_key_code: str,
    alternate_present_code: str,
    keys_invalid_code: str,
    keys_not_unique_code: str,
) -> str:
    _assert_exact_ssh_directory(home, uid, error_cls)
    alternate = home / AUTHORIZED_KEYS2_REL
    _assert_path_chain(home, alternate, uid)
    if alternate.exists() or alternate.is_symlink():
        raise error_cls(alternate_present_code)

    path = home / AUTHORIZED_KEYS_REL
    _assert_path_chain(home, path, uid)
    data = _assert_owned_regular(path, uid, 0o600)
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
    if expected_key_sha256 is not None:
        if re.fullmatch(r"[0-9a-f]{64}", expected_key_sha256) is None:
            raise error_cls(invalid_hash_code)
        if key_hash != expected_key_sha256:
            raise error_cls(invalid_key_code)
    return _sha256(data)


def assert_gate_a3_pre_install_state(
    home: Path,
    uid: int,
    forced_command: str,
    expected_transport_key_sha256: str,
    *,
    error_cls: type[Exception],
    require_accepted_115: bool,
    require_no_transaction: bool,
    require_no_receipt: bool,
    transport_error_codes: dict[str, str],
) -> dict[str, object]:
    home = _assert_home(home, uid)

    transaction = home / TRANSACTION_REL
    _assert_path_chain(home, transaction, uid)
    if require_no_transaction and (transaction.exists() or transaction.is_symlink()):
        raise error_cls("REDRIX_TRANSACTION_RECOVERY_REQUIRED")

    receipt = home / RECEIPT_REL
    _assert_path_chain(home, receipt, uid)
    if require_no_receipt and (receipt.exists() or receipt.is_symlink()):
        raise error_cls("REDRIX_PREFLIGHT_RECEIPT_PRESENT")

    baseline, preexisting = _recognize_baseline(home, uid)
    if require_accepted_115 and baseline != "accepted-115":
        raise error_cls("REDRIX_PREFLIGHT_BASELINE_NOT_ACCEPTED_115")

    if require_accepted_115:
        rollback_targets = {rel.as_posix() for _, _, rel, _ in ROLLBACK}
        expected_preexisting = {
            rel.as_posix(): rel.as_posix() in rollback_targets
            for _, _, rel, _ in CURRENT
        }
        if preexisting != expected_preexisting:
            raise error_cls("REDRIX_PREFLIGHT_RESIDUE_PRESENT")
    else:
        if baseline != "accepted-133":
            raise error_cls("REDRIX_RECEIPT_STATE_INVALID")
        _verify_current_files(home, uid)

    authorized_keys_sha256 = assert_transport_key_identity(
        home,
        uid,
        forced_command,
        expected_transport_key_sha256,
        error_cls=error_cls,
        **transport_error_codes,
    )
    return {
        "baseline": baseline,
        "preexisting": preexisting,
        "authorizedKeysSha256": authorized_keys_sha256,
    }


class InstallError(RuntimeError):
    pass


def _authorized_keys_invariant_digest(
    home: Path,
    uid: int,
    forced_command: str,
    *,
    error_cls: type[Exception] = InstallError,
) -> str:
    return assert_transport_key_identity(
        home,
        uid,
        forced_command,
        None,
        error_cls=error_cls,
        invalid_hash_code="REDRIX_TRANSPORT_KEY_SHA256_INVALID",
        invalid_key_code="REDRIX_TRANSPORT_KEY_INVALID",
        alternate_present_code="REDRIX_AUTHORIZED_KEYS2_PRESENT",
        keys_invalid_code="REDRIX_AUTHORIZED_KEYS_INVALID",
        keys_not_unique_code="REDRIX_FORCED_KEY_NOT_UNIQUE",
    )


def assert_authorized_keys_marker_matches(
    home: Path,
    uid: int,
    forced_command: str,
    expected_raw_digest: str,
    *,
    expected_transport_key_sha256: str | None = None,
    error_cls: type[Exception] = InstallError,
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_raw_digest) is None:
        raise error_cls("REDRIX_AUTHORIZED_KEYS_CHANGED")
    if expected_transport_key_sha256 is not None:
        digest = assert_transport_key_identity(
            home,
            uid,
            forced_command,
            expected_transport_key_sha256,
            error_cls=error_cls,
            invalid_hash_code="REDRIX_TRANSPORT_KEY_SHA256_INVALID",
            invalid_key_code="REDRIX_TRANSPORT_KEY_INVALID",
            alternate_present_code="REDRIX_AUTHORIZED_KEYS2_PRESENT",
            keys_invalid_code="REDRIX_AUTHORIZED_KEYS_INVALID",
            keys_not_unique_code="REDRIX_FORCED_KEY_NOT_UNIQUE",
        )
    else:
        digest = _authorized_keys_invariant_digest(home, uid, forced_command, error_cls=error_cls)
    if digest != expected_raw_digest:
        raise error_cls("REDRIX_AUTHORIZED_KEYS_CHANGED")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.parent / ("." + path.name + ".tmp-" + os.urandom(8).hex())
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(temp, mode)
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _assert_owned_regular(path: Path, uid: int, mode: int | None = None) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError("REDRIX_REQUIRED_FILE_MISSING") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        raise InstallError("REDRIX_FILE_OWNERSHIP_INVALID")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise InstallError("REDRIX_FILE_MODE_INVALID")
    return path.read_bytes()


def _assert_home(home: Path, uid: int) -> Path:
    candidate = home.absolute()
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise InstallError("REDRIX_HOME_INVALID") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise InstallError("REDRIX_HOME_INVALID")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate:
        raise InstallError("REDRIX_HOME_INVALID")
    return resolved


def _assert_path_chain(home: Path, target: Path, uid: int) -> None:
    home = _assert_home(home, uid)
    candidate = target.absolute()
    try:
        relative = candidate.relative_to(home)
    except ValueError as exc:
        raise InstallError("REDRIX_TARGET_OUTSIDE_HOME") from exc
    cursor = home
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            info = cursor.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise InstallError("REDRIX_TARGET_PARENT_INVALID")


def _expected_map(specs) -> dict[Path, tuple[str, int]]:
    return {rel: (blob, mode) for _, blob, rel, mode in specs}


def _validate_preexisting(value: object) -> dict[str, bool]:
    if not isinstance(value, dict) or set(value) != PREEXISTING_KEYS or not all(type(item) is bool for item in value.values()):
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    return dict(value)


def _recognize_baseline(home: Path, uid: int) -> tuple[str, dict[str, bool]]:
    current = _expected_map(CURRENT)
    rollback = _expected_map(ROLLBACK)
    transport_states: list[str] = []
    preexisting: dict[str, bool] = {}
    for _, _, rel, expected_mode in CURRENT:
        path = home / rel
        _assert_path_chain(home, path, uid)
        if not path.exists() and not path.is_symlink():
            preexisting[rel.as_posix()] = False
            if rel in rollback:
                transport_states.append("absent")
            continue
        mode = rollback[rel][1] if rel in rollback else current[rel][1]
        data = _assert_owned_regular(path, uid, mode)
        preexisting[rel.as_posix()] = True
        blob = _git_blob(data)
        if rel in rollback:
            if blob == rollback[rel][0]:
                transport_states.append("rollback")
            elif blob == current[rel][0]:
                transport_states.append("current")
            else:
                raise InstallError("REDRIX_BASELINE_UNRECOGNIZED")
        elif blob != current[rel][0]:
            raise InstallError("REDRIX_BASELINE_UNRECOGNIZED")
    if transport_states.count("rollback") == len(ROLLBACK):
        return "accepted-115", preexisting
    if transport_states.count("current") == len(ROLLBACK):
        return "accepted-133", preexisting
    raise InstallError("REDRIX_BASELINE_MIXED_OR_INCOMPLETE")


def _verify_checksum(archive: Path, checksum: Path) -> str:
    lines = checksum.read_text(encoding="ascii").splitlines()
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", lines[0]) if len(lines) == 1 else None
    if match is None or match.group(2) != archive.name:
        raise InstallError("REDRIX_PACKAGE_CHECKSUM_INVALID")
    digest = _sha256(archive.read_bytes())
    if digest != match.group(1):
        raise InstallError("REDRIX_PACKAGE_CHECKSUM_MISMATCH")
    return digest


def _extract_verified_package(archive: Path, checksum: Path, work: Path) -> tuple[Path, dict[str, Any], str]:
    archive_digest = _verify_checksum(archive, checksum)
    expected = {"payload/" + path: (path, blob, target, mode, "current", SOURCE_COMMIT) for path, blob, target, mode in CURRENT}
    expected.update({"rollback/" + path: (path, blob, target, mode, "rollback", ROLLBACK_COMMIT) for path, blob, target, mode in ROLLBACK})
    modes: dict[str, int] = {}
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise InstallError("REDRIX_PACKAGE_EMPTY")
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != PACKAGE:
                raise InstallError("REDRIX_PACKAGE_PATH_INVALID")
            if not (member.isdir() or member.isfile()) or member.issym() or member.islnk():
                raise InstallError("REDRIX_PACKAGE_MEMBER_INVALID")
            if member.isfile():
                modes[PurePosixPath(*pure.parts[1:]).as_posix()] = member.mode & 0o777
        tf.extractall(work, filter="data")
    root = work / PACKAGE
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_keys = {
        "schemaVersion", "artifact", "sourceCommit", "sourceTree", "rollbackCommit", "rollbackTree",
        "sourceDateEpoch", "owner", "containsCredential", "containsBootstrap", "containsPrivateKey",
        "authorizedKeysMutationAuthorized", "entries",
    }
    if set(manifest) != manifest_keys:
        raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
    required = {
        "schemaVersion": 1,
        "artifact": PACKAGE,
        "sourceCommit": SOURCE_COMMIT,
        "sourceTree": SOURCE_TREE,
        "rollbackCommit": ROLLBACK_COMMIT,
        "rollbackTree": ROLLBACK_TREE,
        "owner": {"user": PRODUCTION_USER, "uid": PRODUCTION_UID},
        "containsCredential": False,
        "containsBootstrap": False,
        "containsPrivateKey": False,
        "authorizedKeysMutationAuthorized": False,
    }
    for key, value in required.items():
        if manifest.get(key) != value:
            raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
    epoch = manifest.get("sourceDateEpoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
    records = manifest.get("entries")
    if not isinstance(records, list) or len(records) != len(expected):
        raise InstallError("REDRIX_PACKAGE_INVENTORY_INVALID")
    by_path = {record.get("packagePath"): record for record in records if isinstance(record, dict)}
    if set(by_path) != set(expected):
        raise InstallError("REDRIX_PACKAGE_INVENTORY_INVALID")
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual_files != set(expected) | {"manifest.json"}:
        raise InstallError("REDRIX_PACKAGE_INVENTORY_INVALID")
    record_keys = {
        "role", "packagePath", "sourceCommit", "sourcePath", "gitBlob", "sourceSha256",
        "materialization", "sha256", "size", "mode", "targetPath",
    }
    for package_path, (source_path, blob, target, mode, role, source_commit) in expected.items():
        record = by_path[package_path]
        path = root.joinpath(*PurePosixPath(package_path).parts)
        data = path.read_bytes()
        if set(record) != record_keys:
            raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
        if (
            record.get("role") != role
            or record.get("packagePath") != package_path
            or record.get("sourceCommit") != source_commit
            or record.get("sourcePath") != source_path
            or record.get("gitBlob") != blob
            or record.get("materialization") != "raw"
            or record.get("targetPath") != "~/" + target.as_posix()
            or record.get("mode") != f"{mode:04o}"
        ):
            raise InstallError("REDRIX_PACKAGE_MANIFEST_INVALID")
        if (
            _git_blob(data) != blob
            or record.get("sha256") != _sha256(data)
            or record.get("sourceSha256") != _sha256(data)
            or record.get("size") != len(data)
        ):
            raise InstallError("REDRIX_PACKAGE_CONTENT_INVALID")
        if modes.get(package_path) != mode:
            raise InstallError("REDRIX_PACKAGE_MODE_INVALID")
    if modes.get("manifest.json") != 0o600:
        raise InstallError("REDRIX_PACKAGE_MODE_INVALID")
    return root, manifest, archive_digest


def _write_transaction(path: Path, record: dict[str, Any]) -> None:
    _atomic_write(path, _canonical(record), 0o600)


def _validate_transaction(record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    expected = {"schema", "operation", "sourceCommit", "packageSha256", "authorizedKeysSha256", "baseline", "preexisting"}
    if set(record) != expected or record.get("schema") != 2 or record.get("operation") not in {"install", "rollback"}:
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    if record.get("sourceCommit") != SOURCE_COMMIT or record.get("baseline") not in {"accepted-115", "accepted-133"}:
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    if not isinstance(record.get("packageSha256"), str) or re.fullmatch(r"[a-f0-9]{64}", record["packageSha256"]) is None:
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    if not isinstance(record.get("authorizedKeysSha256"), str) or re.fullmatch(r"[a-f0-9]{64}", record["authorizedKeysSha256"]) is None:
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    record = dict(record)
    record["preexisting"] = _validate_preexisting(record.get("preexisting"))
    return record


def _validate_receipt_data(record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InstallError("REDRIX_RECEIPT_INVALID")
    expected = {"schema", "sourceCommit", "sourceTree", "packageSha256", "authorizedKeysSha256", "rollbackBaseline", "preexisting"}
    if set(record) != expected or record.get("schema") != 2 or record.get("sourceCommit") != SOURCE_COMMIT or record.get("sourceTree") != SOURCE_TREE:
        raise InstallError("REDRIX_RECEIPT_INVALID")
    if record.get("rollbackBaseline") not in {"accepted-115", "accepted-133"}:
        raise InstallError("REDRIX_RECEIPT_INVALID")
    for key in ("packageSha256", "authorizedKeysSha256"):
        if not isinstance(record.get(key), str) or re.fullmatch(r"[a-f0-9]{64}", record[key]) is None:
            raise InstallError("REDRIX_RECEIPT_INVALID")
    record = dict(record)
    record["preexisting"] = _validate_preexisting(record.get("preexisting"))
    return record


def _read_receipt(home: Path, uid: int) -> dict[str, Any]:
    receipt = home / RECEIPT_REL
    _assert_path_chain(home, receipt, uid)
    data = _assert_owned_regular(receipt, uid, 0o600)
    try:
        return _validate_receipt_data(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("REDRIX_RECEIPT_INVALID") from exc


def _remove_matching_receipt(home: Path, uid: int, package_sha: str, auth_sha: str) -> None:
    receipt = home / RECEIPT_REL
    if not receipt.exists() and not receipt.is_symlink():
        return
    record = _read_receipt(home, uid)
    if record["packageSha256"] != package_sha or record["authorizedKeysSha256"] != auth_sha:
        raise InstallError("REDRIX_RECEIPT_STATE_INVALID")
    receipt.unlink()
    _fsync_dir(receipt.parent)


def _install_one(home: Path, source: Path, target: Path, mode: int, uid: int) -> None:
    _assert_path_chain(home, target, uid)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_path_chain(home, target, uid)
    _atomic_write(target, source.read_bytes(), mode)
    info = target.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
        raise InstallError("REDRIX_INSTALL_READBACK_INVALID")


def _restore(home: Path, package_root: Path, record: dict[str, Any], uid: int) -> None:
    rollback = {rel: (path, blob, mode) for path, blob, rel, mode in ROLLBACK}
    current = {rel: (path, blob, mode) for path, blob, rel, mode in CURRENT}
    baseline = record["baseline"]
    preexisting = record["preexisting"]
    for rel, (_, _, _) in current.items():
        target = home / rel
        _assert_path_chain(home, target, uid)
        if rel in rollback and baseline == "accepted-115":
            rollback_source, rollback_blob, rollback_mode = rollback[rel]
            _install_one(home, package_root / "rollback" / rollback_source, target, rollback_mode, uid)
            if _git_blob(target.read_bytes()) != rollback_blob:
                raise InstallError("REDRIX_ROLLBACK_READBACK_INVALID")
        elif preexisting.get(rel.as_posix()) is False:
            if target.exists() or target.is_symlink():
                if target.is_symlink() or not target.is_file() or _git_blob(target.read_bytes()) != current[rel][1]:
                    raise InstallError("REDRIX_ROLLBACK_TARGET_UNRECOGNIZED")
                target.unlink()
                _fsync_dir(target.parent)
        else:
            if not target.exists() or target.is_symlink() or _git_blob(target.read_bytes()) != current[rel][1]:
                raise InstallError("REDRIX_ROLLBACK_TARGET_UNRECOGNIZED")


def _verify_current_files(home: Path, uid: int) -> None:
    for _, blob, rel, mode in CURRENT:
        path = home / rel
        _assert_path_chain(home, path, uid)
        data = _assert_owned_regular(path, uid, mode)
        if _git_blob(data) != blob:
            raise InstallError("REDRIX_INSTALL_READBACK_INVALID")


def _gate_a3_transport_error_codes() -> dict[str, str]:
    return {
        "invalid_hash_code": "REDRIX_EXPECTED_TRANSPORT_KEY_SHA256_INVALID",
        "invalid_key_code": "REDRIX_TRANSPORT_KEY_IDENTITY_INVALID",
        "alternate_present_code": "REDRIX_AUTHORIZED_KEYS_ALTERNATE_PRESENT",
        "keys_invalid_code": "REDRIX_AUTHORIZED_KEYS_INVALID",
        "keys_not_unique_code": "REDRIX_AUTHORIZED_KEYS_NOT_UNIQUE",
    }


def _revalidate_gate_a3_before_transaction(
    home: Path,
    uid: int,
    forced_command: str,
    expected_transport_key_sha256: str,
    *,
    require_accepted_115: bool,
    require_no_receipt: bool,
) -> dict[str, object]:
    return assert_gate_a3_pre_install_state(
        home,
        uid,
        forced_command,
        expected_transport_key_sha256,
        error_cls=InstallError,
        require_accepted_115=require_accepted_115,
        require_no_transaction=True,
        require_no_receipt=require_no_receipt,
        transport_error_codes=_gate_a3_transport_error_codes(),
    )


def install_fixture(
    archive: Path,
    checksum: Path,
    home: Path,
    uid: int,
    forced_command: str,
    expected_transport_key_sha256: str,
    fault_after: int | None = None,
    fault_after_receipt: bool = False,
) -> dict[str, Any]:
    home = _assert_home(home, uid)
    transaction = home / TRANSACTION_REL
    receipt = home / RECEIPT_REL
    _assert_path_chain(home, transaction, uid)
    if transaction.exists() or transaction.is_symlink():
        raise InstallError("REDRIX_TRANSACTION_RECOVERY_REQUIRED")
    baseline, preexisting = _recognize_baseline(home, uid)
    if baseline == "accepted-115" and (receipt.exists() or receipt.is_symlink()):
        raise InstallError("REDRIX_RECEIPT_STATE_INVALID")
    transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_path_chain(home, transaction, uid)
    with tempfile.TemporaryDirectory(dir=transaction.parent, prefix="stage-") as td:
        package_root, _, archive_digest = _extract_verified_package(archive, checksum, Path(td))
        if baseline == "accepted-133" and (receipt.exists() or receipt.is_symlink()):
            existing = _read_receipt(home, uid)
            gate_state = _revalidate_gate_a3_before_transaction(
                home,
                uid,
                forced_command,
                expected_transport_key_sha256,
                require_accepted_115=False,
                require_no_receipt=False,
            )
            auth_before = str(gate_state["authorizedKeysSha256"])
            if existing["packageSha256"] != archive_digest or existing["authorizedKeysSha256"] != auth_before:
                raise InstallError("REDRIX_RECEIPT_STATE_INVALID")
            return existing
        gate_state = _revalidate_gate_a3_before_transaction(
            home,
            uid,
            forced_command,
            expected_transport_key_sha256,
            require_accepted_115=(baseline == "accepted-115"),
            require_no_receipt=True,
        )
        auth_before = str(gate_state["authorizedKeysSha256"])
        baseline = str(gate_state["baseline"])
        preexisting = dict(gate_state["preexisting"])
        record = _validate_transaction({
            "schema": 2,
            "operation": "install",
            "sourceCommit": SOURCE_COMMIT,
            "packageSha256": archive_digest,
            "authorizedKeysSha256": auth_before,
            "baseline": baseline,
            "preexisting": preexisting,
        })
        _write_transaction(transaction, record)
        try:
            count = 0
            for source_path, blob, rel, mode in CURRENT:
                source = package_root / "payload" / source_path
                target = home / rel
                _install_one(home, source, target, mode, uid)
                if _git_blob(target.read_bytes()) != blob:
                    raise InstallError("REDRIX_INSTALL_READBACK_INVALID")
                count += 1
                if fault_after is not None and count == fault_after:
                    raise InstallError("REDRIX_SYNTHETIC_INSTALL_FAULT")
            auth_after = assert_transport_key_identity(
                home,
                uid,
                forced_command,
                expected_transport_key_sha256,
                error_cls=InstallError,
                invalid_hash_code="REDRIX_TRANSPORT_KEY_SHA256_INVALID",
                invalid_key_code="REDRIX_TRANSPORT_KEY_INVALID",
                alternate_present_code="REDRIX_AUTHORIZED_KEYS2_PRESENT",
                keys_invalid_code="REDRIX_AUTHORIZED_KEYS_INVALID",
                keys_not_unique_code="REDRIX_FORCED_KEY_NOT_UNIQUE",
            )
            if auth_after != auth_before:
                raise InstallError("REDRIX_AUTHORIZED_KEYS_CHANGED")
            _assert_path_chain(home, receipt, uid)
            receipt_record = _validate_receipt_data({
                "schema": 2,
                "sourceCommit": SOURCE_COMMIT,
                "sourceTree": SOURCE_TREE,
                "packageSha256": archive_digest,
                "authorizedKeysSha256": auth_before,
                "rollbackBaseline": baseline,
                "preexisting": preexisting,
            })
            _atomic_write(receipt, _canonical(receipt_record), 0o600)
            if fault_after_receipt:
                raise InstallError("REDRIX_SYNTHETIC_POST_RECEIPT_FAULT")
            transaction.unlink()
            _fsync_dir(transaction.parent)
            return receipt_record
        except Exception as original:
            try:
                _restore(home, package_root, record, uid)
                assert_authorized_keys_marker_matches(
                    home,
                    uid,
                    forced_command,
                    auth_before,
                    expected_transport_key_sha256=expected_transport_key_sha256,
                )
                if baseline == "accepted-115":
                    _remove_matching_receipt(home, uid, archive_digest, auth_before)
                transaction.unlink()
                _fsync_dir(transaction.parent)
            except Exception as rollback_error:
                raise InstallError("REDRIX_TRANSACTION_HOLD") from rollback_error
            raise original


def recover_fixture(archive: Path, checksum: Path, home: Path, uid: int, forced_command: str) -> None:
    home = _assert_home(home, uid)
    transaction = home / TRANSACTION_REL
    _assert_path_chain(home, transaction, uid)
    if not transaction.is_file() or transaction.is_symlink():
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID")
    marker_data = _assert_owned_regular(transaction, uid, 0o600)
    try:
        record = _validate_transaction(json.loads(marker_data.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("REDRIX_TRANSACTION_MARKER_INVALID") from exc
    assert_authorized_keys_marker_matches(home, uid, forced_command, record["authorizedKeysSha256"])
    with tempfile.TemporaryDirectory(dir=transaction.parent, prefix="recover-") as td:
        package_root, _, archive_digest = _extract_verified_package(archive, checksum, Path(td))
        if archive_digest != record["packageSha256"]:
            raise InstallError("REDRIX_RECOVERY_PACKAGE_MISMATCH")
        _restore(home, package_root, record, uid)
        assert_authorized_keys_marker_matches(home, uid, forced_command, record["authorizedKeysSha256"])
        if record["baseline"] == "accepted-115":
            _remove_matching_receipt(home, uid, archive_digest, record["authorizedKeysSha256"])
    transaction.unlink()
    _fsync_dir(transaction.parent)


def rollback_fixture(archive: Path, checksum: Path, home: Path, uid: int, forced_command: str, fault_after: int | None = None) -> None:
    home = _assert_home(home, uid)
    transaction = home / TRANSACTION_REL
    _assert_path_chain(home, transaction, uid)
    if transaction.exists() or transaction.is_symlink():
        raise InstallError("REDRIX_TRANSACTION_RECOVERY_REQUIRED")
    receipt = _read_receipt(home, uid)
    if receipt["rollbackBaseline"] != "accepted-115":
        raise InstallError("REDRIX_ROLLBACK_BASELINE_REFUSED")
    assert_authorized_keys_marker_matches(home, uid, forced_command, receipt["authorizedKeysSha256"])
    auth = receipt["authorizedKeysSha256"]
    _verify_current_files(home, uid)
    transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_path_chain(home, transaction, uid)
    with tempfile.TemporaryDirectory(dir=transaction.parent, prefix="rollback-") as td:
        package_root, _, archive_digest = _extract_verified_package(archive, checksum, Path(td))
        if archive_digest != receipt["packageSha256"]:
            raise InstallError("REDRIX_ROLLBACK_PACKAGE_MISMATCH")
        record = _validate_transaction({
            "schema": 2,
            "operation": "rollback",
            "sourceCommit": SOURCE_COMMIT,
            "packageSha256": archive_digest,
            "authorizedKeysSha256": auth,
            "baseline": "accepted-115",
            "preexisting": receipt["preexisting"],
        })
        _write_transaction(transaction, record)
        if fault_after == 0:
            raise InstallError("REDRIX_SYNTHETIC_ROLLBACK_FAULT")
        _restore(home, package_root, record, uid)
        if fault_after == 1:
            raise InstallError("REDRIX_SYNTHETIC_ROLLBACK_FAULT")
        assert_authorized_keys_marker_matches(home, uid, forced_command, auth)
        _remove_matching_receipt(home, uid, archive_digest, auth)
        transaction.unlink()
        _fsync_dir(transaction.parent)


def readback_fixture(home: Path, uid: int, forced_command: str) -> dict[str, Any]:
    home = _assert_home(home, uid)
    transaction = home / TRANSACTION_REL
    _assert_path_chain(home, transaction, uid)
    if transaction.exists() or transaction.is_symlink():
        raise InstallError("REDRIX_TRANSACTION_RECOVERY_REQUIRED")
    receipt_data = _read_receipt(home, uid)
    assert_authorized_keys_marker_matches(home, uid, forced_command, receipt_data["authorizedKeysSha256"])
    _verify_current_files(home, uid)
    return {
        "sourceCommit": SOURCE_COMMIT,
        "sourceTree": SOURCE_TREE,
        "authorizedKeysInvariant": True,
        "transactionPending": False,
        "rollbackBaseline": receipt_data["rollbackBaseline"],
        "files": len(CURRENT),
    }


def _assert_production_identity() -> None:
    try:
        account = pwd.getpwnam(PRODUCTION_USER)
    except KeyError as exc:
        raise InstallError("REDRIX_OWNER_IDENTITY_INVALID") from exc
    if account.pw_uid != PRODUCTION_UID or os.geteuid() != PRODUCTION_UID or Path(account.pw_dir) != PRODUCTION_HOME:
        raise InstallError("REDRIX_OWNER_IDENTITY_INVALID")
    _assert_home(PRODUCTION_HOME, PRODUCTION_UID)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    install_parser = sub.add_parser("install")
    install_parser.add_argument("archive", type=Path)
    install_parser.add_argument("checksum", type=Path)
    install_parser.add_argument("--expected-transport-key-sha256", required=True)
    for name in ("recover", "rollback"):
        child = sub.add_parser(name)
        child.add_argument("archive", type=Path)
        child.add_argument("checksum", type=Path)
    sub.add_parser("readback")
    args = parser.parse_args()
    try:
        _assert_production_identity()
        if args.command == "install":
            result = install_fixture(
                args.archive,
                args.checksum,
                PRODUCTION_HOME,
                PRODUCTION_UID,
                FORCED_COMMAND,
                args.expected_transport_key_sha256,
            )
            print("REDRIX_CANARY_INSTALL=PASS")
            print("SOURCE_COMMIT=" + result["sourceCommit"])
        elif args.command == "recover":
            recover_fixture(args.archive, args.checksum, PRODUCTION_HOME, PRODUCTION_UID, FORCED_COMMAND)
            print("REDRIX_CANARY_RECOVERY=PASS")
        elif args.command == "rollback":
            rollback_fixture(args.archive, args.checksum, PRODUCTION_HOME, PRODUCTION_UID, FORCED_COMMAND)
            print("REDRIX_CANARY_ROLLBACK=PASS")
        else:
            result = readback_fixture(PRODUCTION_HOME, PRODUCTION_UID, FORCED_COMMAND)
            print("REDRIX_CANARY_READBACK=PASS")
            print("SOURCE_COMMIT=" + result["sourceCommit"])
            print("AUTHORIZED_KEYS_INVARIANT=PASS")
        return 0
    except (InstallError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "REDRIX_CANARY_INSTALL_FAILED"
        print("REDRIX_CANARY_INSTALL=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
