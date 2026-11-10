#!/usr/bin/env python3
"""Closed normal-user V2 forced-receiver adjunct install plan (dry-run default).

Source-only, fail-closed. Does not edit authorized_keys, sshd, Tailscale, credentials,
or network policy. PHYSICAL_INSTALL_ENABLED remains false until a separate reviewed commit.
"""
from __future__ import annotations

import argparse
import hashlib
try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - non-POSIX dev hosts
    fcntl = None  # type: ignore[assignment]
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any

CONTRACT_PATH = Path(__file__).with_name("redrix_normal_user_v2_receiver_install.json")
MARKER = "REDRIX_NORMAL_USER_V2_RECEIVER_INSTALL_P0"
PHYSICAL_INSTALL_ENABLED = False
PRODUCTION_USER = "eddie"
PRODUCTION_UID = 1000
INSTALL_LIB_REL = Path(".local/lib/ldw-dragonfly-jit")
STATE_REL = Path(".local/state/ldw-dragonfly-jit/v2-receiver-install")
RECEIVER_REL = INSTALL_LIB_REL / "ssh_forced_receiver.py"
INBOUND_REL = INSTALL_LIB_REL / "inbound_transfer_v2.py"
STAGING_REL = INSTALL_LIB_REL / ".v2-receiver-staging"
KERNEL_LOCK_REL = STATE_REL / "invoke.kernel.lock"
TRANSACTION_REL = STATE_REL / "install-transaction.json"
RECEIPT_REL = STATE_REL / "install-receipt.json"
ROLLBACK_ARCHIVE_REL = STATE_REL / "rollback-receiver-v1.bin"
FORCED_COMMAND = "/usr/bin/python3 /home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"
INBOUND_PACKAGE = "payload/inbound_transfer_v2.py"
RECEIVER_PACKAGE = "payload/ssh_forced_receiver.py"
_MAX_PACKAGE_BYTES = 256 * 1024
_BLOB_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION_PHASES = frozenset(
    {"PREPARED", "INBOUND_STAGED", "INBOUND_COMMITTED", "RECEIVER_COMMITTED", "CLEANUP", "FAILED"}
)


class InstallError(RuntimeError):
    pass


_HOME_MOUNT = Path("/home")


def _assert_lock_inode_identity(path: Path, fd: int) -> tuple[int, int]:
    """Fail closed if the public path does not name the same inode as the held fd."""
    path_stat = path.lstat()
    fd_stat = os.fstat(fd)
    identity = (fd_stat.st_dev, fd_stat.st_ino)
    if (path_stat.st_dev, path_stat.st_ino) != identity:
        raise InstallError("LOCK_PATH_INVALID")
    return identity


def _assert_kernel_lock_trust_root(home: Path, uid: int) -> Path:
    """Require install home under root-owned /home (e.g. /home/eddie). Same-UID tamper of /home
    itself is out of contract; without this anchor return BLOCKED_LOCK_TRUST_ROOT fail-closed."""
    resolved = _assert_home(home, uid)
    if sys.platform == "win32" or fcntl is None:
        raise InstallError("KERNEL_LOCK_UNAVAILABLE")
    try:
        mount_info = _HOME_MOUNT.lstat()
    except OSError as exc:
        raise InstallError("BLOCKED_LOCK_TRUST_ROOT") from exc
    if (
        not stat.S_ISDIR(mount_info.st_mode)
        or stat.S_ISLNK(mount_info.st_mode)
        or mount_info.st_uid != 0
    ):
        raise InstallError("BLOCKED_LOCK_TRUST_ROOT")
    try:
        resolved.relative_to(_HOME_MOUNT.resolve(strict=True))
    except ValueError as exc:
        raise InstallError("BLOCKED_LOCK_TRUST_ROOT") from exc
    return resolved


class _KernelLock:
    """One-controller exclusivity via flock on the resolved trusted home directory inode.
    invoke.kernel.lock is a durable nonce record only (replaceable without bypassing flock)."""

    def __init__(self) -> None:
        self._fd: int | None = None
        self._anchor: Path | None = None
        self._identity: tuple[int, int] | None = None

    def reverify_lock_anchor(self, *, home: Path, uid: int) -> None:
        if self._fd is None or self._anchor is None:
            raise InstallError("KERNEL_LOCK_UNAVAILABLE")
        anchor = _assert_kernel_lock_trust_root(home, uid)
        if anchor != self._anchor:
            raise InstallError("LOCK_PATH_INVALID")
        identity = _assert_lock_inode_identity(anchor, self._fd)
        if self._identity is not None and identity != self._identity:
            raise InstallError("LOCK_PATH_INVALID")

    def acquire(self, *, home: Path, path: Path, uid: int, operation_id: str) -> None:
        if sys.platform == "win32" or fcntl is None:
            raise InstallError("KERNEL_LOCK_UNAVAILABLE")
        anchor = _assert_kernel_lock_trust_root(home, uid)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _assert_path_chain(home, path, uid)
        if path.is_symlink():
            raise InstallError("LOCK_PATH_INVALID")
        o_directory = getattr(os, "O_DIRECTORY", 0)
        fd = os.open(anchor, os.O_RDONLY | o_directory)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            identity = _assert_lock_inode_identity(anchor, fd)
        except (BlockingIOError, OSError) as exc:
            os.close(fd)
            raise InstallError("CONCURRENT_INVOKE_REFUSED") from exc
        except InstallError:
            os.close(fd)
            raise
        record = _canonical(
            {
                "marker": MARKER,
                "operationId": operation_id,
                "pid": os.getpid(),
                "lockAnchor": anchor.as_posix(),
            }
        )
        _atomic_write(path, record, 0o600)
        _assert_lock_inode_identity(anchor, fd)
        self._fd = fd
        self._anchor = anchor
        self._identity = identity

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None
            self._anchor = None
            self._identity = None


def load_contract() -> dict[str, Any]:
    data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if data.get("marker") != MARKER:
        raise InstallError("CONTRACT_MARKER_INVALID")
    return data


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(record: object) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _fsync_dir(path: Path) -> None:
    if sys.platform == "win32":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _assert_path_chain(home: Path, target: Path, uid: int) -> None:
    home = _assert_home(home, uid)
    try:
        relative = target.absolute().relative_to(home)
    except ValueError as exc:
        raise InstallError("TARGET_OUTSIDE_HOME") from exc
    cursor = home
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if not cursor.exists() and not cursor.is_symlink():
            continue
        info = cursor.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or not _uid_matches(info, uid)
            or (sys.platform != "win32" and stat.S_IMODE(info.st_mode) & 0o022)
        ):
            raise InstallError("TARGET_PARENT_INVALID")


def _assert_home(home: Path, uid: int) -> Path:
    candidate = home.absolute()
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise InstallError("HOME_INVALID") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not _uid_matches(info, uid)
        or (sys.platform != "win32" and stat.S_IMODE(info.st_mode) & 0o022)
    ):
        raise InstallError("HOME_INVALID")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate:
        raise InstallError("HOME_INVALID")
    return resolved


def _uid_matches(info: os.stat_result, uid: int) -> bool:
    if sys.platform == "win32":
        return True
    return info.st_uid == uid


def _assert_owned_regular(path: Path, uid: int, mode: int | None = None) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError("REQUIRED_FILE_MISSING") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or not _uid_matches(info, uid):
        raise InstallError("FILE_OWNERSHIP_INVALID")
    if mode is not None and sys.platform != "win32" and stat.S_IMODE(info.st_mode) != mode:
        raise InstallError("FILE_MODE_INVALID")
    return path.read_bytes()


def _assert_no_symlink_target(path: Path) -> None:
    if path.is_symlink():
        raise InstallError("SYMLINK_PATH_REFUSED")
    cursor = path
    for parent in path.parents:
        if parent == parent.anchor:
            break
        if parent.is_symlink():
            raise InstallError("SYMLINK_PATH_REFUSED")
        cursor = parent


def _atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    *,
    inject_parent_fsync_fault: bool = False,
) -> None:
    _assert_no_symlink_target(path.parent)
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
        if inject_parent_fsync_fault:
            raise InstallError("SIMULATED_RECEIPT_PARENT_FSYNC_FAULT")
        _fsync_dir(path.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _install_receipt_record_matches(path: Path, uid: int, expected: dict[str, Any]) -> bool:
    if not path.exists() or path.is_symlink():
        return False
    try:
        raw = _assert_owned_regular(path, uid, 0o600)
        parsed = json.loads(raw.decode("utf-8"))
    except (InstallError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and parsed == expected


def _validate_manifest(manifest: object, contract: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    expected_keys = {
        "schemaVersion",
        "artifact",
        "sourceCommit",
        "owner",
        "authorizedKeysMutationAuthorized",
        "payloadEntries",
        "rollbackEntries",
    }
    if set(manifest) != expected_keys:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    if manifest.get("schemaVersion") != 1:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    if manifest.get("artifact") != contract["package_identity"]:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    if manifest.get("sourceCommit") != contract["source_commit"]:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    owner = manifest.get("owner")
    if owner != {"user": PRODUCTION_USER, "uid": PRODUCTION_UID}:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    if manifest.get("authorizedKeysMutationAuthorized") is not False:
        raise InstallError("PACKAGE_MANIFEST_INVALID")
    return manifest


def _entries_by_path(entries: list[dict[str, Any]], *, label: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise InstallError(f"{label}_INVALID")
        package_path = entry.get("packagePath")
        if not isinstance(package_path, str):
            raise InstallError(f"{label}_INVALID")
        pure = PurePosixPath(package_path)
        if pure.is_absolute() or ".." in pure.parts:
            raise InstallError("PACKAGE_PATH_INVALID")
        if package_path in out:
            raise InstallError("PACKAGE_PATH_DUPLICATE")
        out[package_path] = entry
    return out


def _verify_package_inventory(
    package_root: Path,
    manifest: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, bytes]:
    payload_map = _entries_by_path(manifest["payloadEntries"], label="PAYLOAD_ENTRY")
    rollback_map = _entries_by_path(manifest["rollbackEntries"], label="ROLLBACK_ENTRY")
    contract_payload = {
        entry["package_path"]: entry for entry in contract["payload_entries"]
    }
    contract_rollback = {
        entry["package_path"]: entry for entry in contract["rollback_entries"]
    }
    if set(payload_map) != set(contract_payload) or set(rollback_map) != set(contract_rollback):
        raise InstallError("PACKAGE_INVENTORY_DRIFT")

    inventory: dict[str, bytes] = {}
    for package_path, spec in {**payload_map, **rollback_map}.items():
        for key in (
            "packagePath",
            "sourcePath",
            "gitBlob",
            "materialization",
            "sha256",
            "size",
            "mode",
        ):
            if key not in spec:
                raise InstallError("PACKAGE_ENTRY_INVALID")
        if spec["materialization"] != "raw":
            raise InstallError("PACKAGE_ENTRY_INVALID")
        if not _BLOB_RE.fullmatch(str(spec["gitBlob"])):
            raise InstallError("PACKAGE_ENTRY_INVALID")
        if not _SHA256_RE.fullmatch(str(spec["sha256"])):
            raise InstallError("PACKAGE_ENTRY_INVALID")
        role_spec = contract_payload.get(package_path) or contract_rollback[package_path]
        if (
            spec["packagePath"] != package_path
            or spec["sourcePath"] != role_spec["source_path"]
            or spec["gitBlob"] != role_spec["git_blob"]
            or spec["mode"] != role_spec["mode"]
        ):
            raise InstallError("PACKAGE_PIN_MISMATCH")
        data_path = package_root.joinpath(*PurePosixPath(package_path).parts)
        if not data_path.is_file() or data_path.is_symlink():
            raise InstallError("PACKAGE_FILE_MISSING")
        if data_path.stat().st_size > _MAX_PACKAGE_BYTES:
            raise InstallError("PACKAGE_FILE_TOO_LARGE")
        data = data_path.read_bytes()
        if b"\r\n" in data:
            normalized = data.replace(b"\r\n", b"\n")
            if _git_blob(normalized) == spec["gitBlob"]:
                raise InstallError("PACKAGE_CRLF_MATERIALIZATION_REFUSED")
        if _git_blob(data) != spec["gitBlob"] or _sha256(data) != spec["sha256"] or len(data) != spec["size"]:
            raise InstallError("PACKAGE_CONTENT_INVALID")
        inventory[package_path] = data
    return inventory


def _receiver_inbound_coherent(receiver_bytes: bytes, inbound_blob: str) -> bool:
    needle = f'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "{inbound_blob}"'
    return needle.encode("ascii") in receiver_bytes


def _read_json_object(path: Path, uid: int) -> dict[str, Any]:
    raw = _assert_owned_regular(path, uid, 0o600)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("STATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise InstallError("STATE_JSON_INVALID")
    return value


def _validate_transaction(record: object) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InstallError("TRANSACTION_INVALID")
    expected = {
        "marker",
        "schema",
        "operationId",
        "sourceCommit",
        "phase",
        "rollbackReceiverGitBlob",
        "inboundGitBlob",
        "receiverGitBlob",
    }
    if set(record) != expected or record.get("marker") != MARKER or record.get("schema") != 1:
        raise InstallError("TRANSACTION_INVALID")
    phase = record.get("phase")
    if phase not in _TRANSACTION_PHASES:
        raise InstallError("TRANSACTION_INVALID")
    if not re.fullmatch(r"[0-9a-f]{32}", str(record.get("operationId"))):
        raise InstallError("TRANSACTION_INVALID")
    return record


def _reconcile_durable_state(home: Path, uid: int, contract: dict[str, Any]) -> None:
    home = _assert_home(home, uid)
    transaction_path = home / TRANSACTION_REL
    receipt_path = home / RECEIPT_REL
    _assert_path_chain(home, transaction_path, uid)
    _assert_path_chain(home, receipt_path, uid)

    if receipt_path.exists() or receipt_path.is_symlink():
        raise InstallError("RECEIPT_ALREADY_PRESENT")

    if transaction_path.exists() or transaction_path.is_symlink():
        record = _validate_transaction(_read_json_object(transaction_path, uid))
        if record["phase"] != "CLEANUP":
            raise InstallError("INSTALL_RECOVERY_REQUIRED")

    inbound = home / INBOUND_REL
    receiver = home / RECEIVER_REL
    v1_blob = contract["required_installed_receiver_git_blob"]
    v2_inbound = contract["payload_entries"][1]["git_blob"]
    v2_receiver = contract["payload_entries"][0]["git_blob"]

    inbound_present = inbound.exists() or inbound.is_symlink()
    if inbound_present:
        inbound_data = _assert_owned_regular(inbound, uid)
        inbound_blob = _git_blob(inbound_data)
    else:
        inbound_blob = None

    receiver_data = _assert_owned_regular(receiver, uid, 0o700)
    receiver_blob = _git_blob(receiver_data)

    if inbound_blob == v2_inbound and receiver_blob == v1_blob:
        raise InstallError("INSTALL_STATE_AMBIGUOUS")
    if inbound_blob == v2_inbound and receiver_blob != v2_receiver:
        raise InstallError("INSTALL_STATE_AMBIGUOUS")
    if inbound_blob not in (None, v2_inbound) or receiver_blob not in (v1_blob, v2_receiver):
        raise InstallError("INSTALL_STATE_UNRECOGNIZED")


def _prepare_exclusive_staging(home: Path, uid: int) -> Path:
    stage_root = home / STAGING_REL
    _assert_path_chain(home, stage_root, uid)
    _assert_no_symlink_target(stage_root.parent)
    if stage_root.exists() or stage_root.is_symlink():
        raise InstallError("STAGING_PATH_PRESENT")
    try:
        stage_root.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise InstallError("STAGING_PATH_PRESENT") from exc
    info = stage_root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not _uid_matches(info, uid)
        or (sys.platform != "win32" and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        raise InstallError("STAGING_PATH_INVALID")
    return stage_root


def _entry_for_package(contract: dict[str, Any], package_path: str) -> dict[str, Any]:
    for entry in contract["payload_entries"]:
        if entry["package_path"] == package_path:
            return entry
    raise InstallError("PACKAGE_PATH_UNKNOWN")


def _write_transaction(path: Path, record: dict[str, Any]) -> None:
    _atomic_write(path, _canonical(record), 0o600)


def _rollback_partial_inbound(home: Path, uid: int, contract: dict[str, Any]) -> None:
    inbound = home / INBOUND_REL
    if not inbound.exists() and not inbound.is_symlink():
        return
    data = _assert_owned_regular(inbound, uid)
    if _git_blob(data) == contract["payload_entries"][1]["git_blob"]:
        inbound.unlink()
        _fsync_dir(inbound.parent)


def _restore_v1_receiver(home: Path, uid: int, contract: dict[str, Any]) -> None:
    archive = home / ROLLBACK_ARCHIVE_REL
    target = home / RECEIVER_REL
    if not archive.exists():
        return
    data = _assert_owned_regular(archive, uid, 0o600)
    if _git_blob(data) != contract["required_installed_receiver_git_blob"]:
        return
    _atomic_write(target, data, 0o700)


def preflight_installed_state(home: Path, uid: int, contract: dict[str, Any]) -> dict[str, Any]:
    home = _assert_home(home, uid)
    _reconcile_durable_state(home, uid, contract)
    install_root = home / INSTALL_LIB_REL
    _assert_path_chain(home, install_root, uid)
    if not install_root.exists():
        raise InstallError("INSTALL_ROOT_MISSING")
    info = install_root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or not _uid_matches(info, uid)
        or (sys.platform != "win32" and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        raise InstallError("INSTALL_ROOT_INVALID")

    stage = home / STAGING_REL
    if stage.exists() or stage.is_symlink():
        raise InstallError("STAGING_PATH_PRESENT")

    receiver = home / RECEIVER_REL
    receiver_blob = _assert_owned_regular(receiver, uid, 0o700)
    observed = _git_blob(receiver_blob)
    required = contract["required_installed_receiver_git_blob"]
    if observed != required:
        raise InstallError("INSTALLED_RECEIVER_BLOB_MISMATCH")

    inbound = home / INBOUND_REL
    _assert_path_chain(home, inbound, uid)
    if inbound.exists() or inbound.is_symlink():
        raise InstallError("INBOUND_ALREADY_PRESENT")

    return {
        "installedReceiverGitBlob": observed,
        "inboundPresent": False,
        "forcedCommand": FORCED_COMMAND,
    }


def build_install_plan(
    *,
    home: Path,
    uid: int,
    package_root: Path,
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contract = contract or load_contract()
    home = _assert_home(home, uid)
    manifest_path = package_root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise InstallError("PACKAGE_MANIFEST_MISSING")
    manifest = _validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")), contract)
    inventory = _verify_package_inventory(package_root, manifest, contract)
    installed = preflight_installed_state(home, uid, contract)
    receiver_bytes = inventory[RECEIVER_PACKAGE]
    inbound_blob = contract["payload_entries"][1]["git_blob"]
    coherent = _receiver_inbound_coherent(receiver_bytes, inbound_blob)
    return {
        "marker": MARKER,
        "mode": "DRY_RUN_PLAN",
        "physicalInstallEnabled": PHYSICAL_INSTALL_ENABLED,
        "sourceCommit": contract["source_commit"],
        "packageArtifact": contract["package_identity"],
        "preflight": installed,
        "payloadGitBlobs": {
            entry["package_path"]: entry["git_blob"] for entry in contract["payload_entries"]
        },
        "receiverInboundPinCoherent": coherent,
        "eligibleForPhysicalInstall": bool(PHYSICAL_INSTALL_ENABLED and coherent),
        "authorizedKeysMutationAuthorized": False,
    }


def install_fixture(
    *,
    home: Path,
    uid: int,
    package_root: Path,
    operation_id: str,
    fault_after: str | None = None,
) -> dict[str, Any]:
    if not PHYSICAL_INSTALL_ENABLED:
        raise InstallError("PHYSICAL_INSTALL_DISABLED")
    if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise InstallError("OPERATION_ID_INVALID")

    contract = load_contract()
    home = _assert_home(home, uid)
    kernel_lock_path = home / KERNEL_LOCK_REL
    transaction_path = home / TRANSACTION_REL
    receipt_path = home / RECEIPT_REL
    rollback_archive = home / ROLLBACK_ARCHIVE_REL

    lock = _KernelLock()
    stage_root: Path | None = None
    receipt_written = False
    receipt_payload: dict[str, Any] | None = None

    def _reverify_kernel_lock() -> None:
        lock.reverify_lock_anchor(home=home, uid=uid)

    try:
        lock.acquire(home=home, path=kernel_lock_path, uid=uid, operation_id=operation_id)
        _reverify_kernel_lock()
        plan = build_install_plan(home=home, uid=uid, package_root=package_root, contract=contract)
        if not plan["receiverInboundPinCoherent"]:
            raise InstallError("RECEIVER_INBOUND_PIN_INCOHERENT")

        manifest = _validate_manifest(
            json.loads((package_root / "manifest.json").read_text(encoding="utf-8")),
            contract,
        )
        inventory = _verify_package_inventory(package_root, manifest, contract)
        inbound_entry = _entry_for_package(contract, INBOUND_PACKAGE)
        receiver_entry = _entry_for_package(contract, RECEIVER_PACKAGE)
        inbound_bytes = inventory[INBOUND_PACKAGE]
        receiver_bytes = inventory[RECEIVER_PACKAGE]
        prior_receiver = _assert_owned_regular(home / RECEIVER_REL, uid, 0o700)

        transaction = {
            "marker": MARKER,
            "schema": 1,
            "operationId": operation_id,
            "sourceCommit": contract["source_commit"],
            "phase": "PREPARED",
            "rollbackReceiverGitBlob": contract["required_installed_receiver_git_blob"],
            "inboundGitBlob": inbound_entry["git_blob"],
            "receiverGitBlob": receiver_entry["git_blob"],
        }
        _reverify_kernel_lock()
        _write_transaction(transaction_path, transaction)
        _atomic_write(rollback_archive, prior_receiver, 0o600)

        stage_root = _prepare_exclusive_staging(home, uid)
        staged_inbound = stage_root / "inbound_transfer_v2.py"
        staged_receiver = stage_root / "ssh_forced_receiver.py"
        _atomic_write(staged_inbound, inbound_bytes, int(inbound_entry["mode"], 8))
        transaction["phase"] = "INBOUND_STAGED"
        _write_transaction(transaction_path, transaction)
        if fault_after == "abrupt_exit":
            os._exit(133)
        staged_inbound_read = _assert_owned_regular(staged_inbound, uid)
        if (
            staged_inbound_read != inbound_bytes
            or _git_blob(staged_inbound_read) != inbound_entry["git_blob"]
        ):
            raise InstallError("STAGED_INBOUND_INVALID")
        _atomic_write(staged_receiver, receiver_bytes, int(receiver_entry["mode"], 8))
        staged_receiver_read = _assert_owned_regular(staged_receiver, uid)
        if (
            staged_receiver_read != receiver_bytes
            or _git_blob(staged_receiver_read) != receiver_entry["git_blob"]
        ):
            raise InstallError("STAGED_RECEIVER_INVALID")

        inbound_target = home / Path(inbound_entry["target_relpath"])
        _assert_path_chain(home, inbound_target, uid)
        _reverify_kernel_lock()
        _atomic_write(inbound_target, inbound_bytes, int(inbound_entry["mode"], 8))
        inbound_readback = _assert_owned_regular(inbound_target, uid, int(inbound_entry["mode"], 8))
        if inbound_readback != inbound_bytes or _git_blob(inbound_readback) != inbound_entry["git_blob"]:
            raise InstallError("INSTALL_READBACK_INVALID")
        transaction["phase"] = "INBOUND_COMMITTED"
        _write_transaction(transaction_path, transaction)
        if fault_after == INBOUND_PACKAGE:
            raise InstallError("SIMULATED_INTERRUPT")

        receiver_target = home / Path(receiver_entry["target_relpath"])
        _assert_path_chain(home, receiver_target, uid)
        _reverify_kernel_lock()
        _atomic_write(receiver_target, receiver_bytes, int(receiver_entry["mode"], 8))
        receiver_readback = _assert_owned_regular(receiver_target, uid, int(receiver_entry["mode"], 8))
        if receiver_readback != receiver_bytes or _git_blob(receiver_readback) != receiver_entry["git_blob"]:
            raise InstallError("INSTALL_READBACK_INVALID")
        transaction["phase"] = "RECEIVER_COMMITTED"
        _write_transaction(transaction_path, transaction)
        if fault_after == RECEIVER_PACKAGE:
            raise InstallError("SIMULATED_INTERRUPT")

        receipt_payload = {
            "marker": MARKER,
            "schema": 1,
            "operationId": operation_id,
            "sourceCommit": contract["source_commit"],
            "packageArtifact": contract["package_identity"],
            "installedReceiverGitBlob": receiver_entry["git_blob"],
            "installedInboundGitBlob": inbound_entry["git_blob"],
            "priorReceiverGitBlob": contract["required_installed_receiver_git_blob"],
            "rollbackArchiveRel": ROLLBACK_ARCHIVE_REL.as_posix(),
            "forcedCommand": FORCED_COMMAND,
            "authorizedKeysSha256": None,
        }
        _reverify_kernel_lock()
        receipt_parent_fsync_fault = fault_after == "receipt_parent_fsync"
        try:
            _atomic_write(
                receipt_path,
                _canonical(receipt_payload),
                0o600,
                inject_parent_fsync_fault=receipt_parent_fsync_fault,
            )
        except InstallError:
            if _install_receipt_record_matches(receipt_path, uid, receipt_payload):
                raise InstallError("INSTALL_POST_RECEIPT_HOLD")
            raise
        receipt_written = True
        if fault_after == "receipt":
            raise InstallError("SIMULATED_INTERRUPT")
        transaction["phase"] = "CLEANUP"
        _write_transaction(transaction_path, transaction)
        if stage_root is not None and stage_root.exists():
            for child in stage_root.iterdir():
                child.unlink()
            stage_root.rmdir()
        transaction_path.unlink(missing_ok=True)
        _fsync_dir(transaction_path.parent)
        return receipt_payload
    except Exception as original:
        receipt_on_disk = (
            receipt_payload is not None
            and _install_receipt_record_matches(receipt_path, uid, receipt_payload)
        )
        if receipt_written or receipt_on_disk:
            if transaction_path.exists() or transaction_path.is_symlink():
                try:
                    record = _validate_transaction(_read_json_object(transaction_path, uid))
                    record["phase"] = "FAILED"
                    _write_transaction(transaction_path, record)
                except InstallError:
                    pass
            if stage_root is not None and stage_root.exists():
                for child in stage_root.iterdir():
                    child.unlink()
                stage_root.rmdir()
            raise InstallError("INSTALL_POST_RECEIPT_HOLD") from original
        if transaction_path.exists() or transaction_path.is_symlink():
            try:
                record = _validate_transaction(_read_json_object(transaction_path, uid))
                record["phase"] = "FAILED"
                _write_transaction(transaction_path, record)
            except InstallError:
                pass
        phase = None
        if transaction_path.exists():
            try:
                phase = _validate_transaction(_read_json_object(transaction_path, uid))["phase"]
            except InstallError:
                phase = "FAILED"
        if phase in {"INBOUND_COMMITTED", "FAILED"}:
            _rollback_partial_inbound(home, uid, contract)
        if phase in {"INBOUND_COMMITTED", "RECEIVER_COMMITTED", "FAILED"}:
            _restore_v1_receiver(home, uid, contract)
        raise
    finally:
        lock.release()


def evaluate_admission() -> dict[str, Any]:
    contract = load_contract()
    problems: list[str] = []
    if PHYSICAL_INSTALL_ENABLED:
        problems.append("PHYSICAL_INSTALL_MUST_REMAIN_FALSE_IN_THIS_RELEASE")
    if contract["runtime_enablement"]["physical_install_source_enabled"]:
        problems.append("CONTRACT_RUNTIME_FLAG_INVALID")
    return {
        "marker": MARKER,
        "eligibility": "READY_FOR_HW_VM_INDEPENDENT_REVIEW" if not problems else "HOLD",
        "problems": problems,
        "physical_install_source_enabled": PHYSICAL_INSTALL_ENABLED,
        "source_commit": contract["source_commit"],
        "jit_admission_authorized": False,
        "authorized_keys_mutation_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="REDRIX normal-user V2 receiver install (plan-only default)")
    parser.add_argument("command", choices=["plan", "admission"])
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--uid", type=int, default=os.getuid() if hasattr(os, "getuid") else PRODUCTION_UID)
    parser.add_argument("--package-root", type=Path)
    args = parser.parse_args(argv)

    if args.command == "admission":
        sys.stdout.write(json.dumps(evaluate_admission(), sort_keys=True) + "\n")
        return 0

    if args.package_root is None:
        sys.stderr.write("ERROR:PACKAGE_ROOT_REQUIRED\n")
        return 2
    try:
        plan = build_install_plan(
            home=Path(args.home),
            uid=args.uid,
            package_root=args.package_root.expanduser().absolute(),
        )
    except InstallError as exc:
        sys.stderr.write(f"ERROR:{exc}\n")
        return 2
    sys.stdout.write(json.dumps(plan, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
