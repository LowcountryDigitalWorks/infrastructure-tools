#!/usr/bin/env python3
"""Closed normal-user V2 forced-receiver adjunct install plan (dry-run default).

Source-only, fail-closed. Does not edit authorized_keys, sshd, Tailscale, credentials,
or network policy. PHYSICAL_INSTALL_ENABLED remains false until a separate reviewed commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import time
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
LOCK_REL = STATE_REL / "invoke.lock"
TRANSACTION_REL = STATE_REL / "install-transaction.json"
RECEIPT_REL = STATE_REL / "install-receipt.json"
ROLLBACK_ARCHIVE_REL = STATE_REL / "rollback-receiver-v1.bin"
FORCED_COMMAND = "/usr/bin/python3 /home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"
_MAX_PACKAGE_BYTES = 256 * 1024
_BLOB_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class InstallError(RuntimeError):
    pass


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


def _acquire_lock(home: Path, lock_path: Path, uid: int, *, stale_after_sec: int = 900) -> None:
    home = _assert_home(home, uid)
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_path_chain(home, lock_path, uid)
    now = int(time.time())
    if lock_path.exists() or lock_path.is_symlink():
        record = _read_json_object(lock_path, uid)
        started = record.get("startedUnix")
        if not isinstance(started, int) or now - started < stale_after_sec:
            raise InstallError("CONCURRENT_INVOKE_REFUSED")
        lock_path.unlink()
    payload = {
        "marker": MARKER,
        "startedUnix": now,
        "pid": os.getpid(),
    }
    _atomic_write(lock_path, _canonical(payload), 0o600)


def _release_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass


def preflight_installed_state(home: Path, uid: int, contract: dict[str, Any]) -> dict[str, Any]:
    home = _assert_home(home, uid)
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

    for rel_path in (LOCK_REL, TRANSACTION_REL):
        path = home / rel_path
        if path.exists() or path.is_symlink():
            raise InstallError("PRIOR_INSTALL_ARTIFACT_PRESENT")

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
    receiver_bytes = inventory["payload/ssh_forced_receiver.py"]
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
        "eligibleForPhysicalInstall": bool(
            PHYSICAL_INSTALL_ENABLED and coherent
        ),
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
    """Test-only install path; still refuses unless PHYSICAL_INSTALL_ENABLED in tests."""
    if not PHYSICAL_INSTALL_ENABLED:
        raise InstallError("PHYSICAL_INSTALL_DISABLED")
    if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise InstallError("OPERATION_ID_INVALID")

    contract = load_contract()
    plan = build_install_plan(home=home, uid=uid, package_root=package_root, contract=contract)
    if not plan["receiverInboundPinCoherent"]:
        raise InstallError("RECEIVER_INBOUND_PIN_INCOHERENT")

    home = _assert_home(home, uid)
    lock_path = home / LOCK_REL
    transaction_path = home / TRANSACTION_REL
    receipt_path = home / RECEIPT_REL
    rollback_archive = home / ROLLBACK_ARCHIVE_REL

    if receipt_path.exists() or receipt_path.is_symlink():
        receipt = _read_json_object(receipt_path, uid)
        if receipt.get("operationId") == operation_id:
            raise InstallError("REPLAY_REFUSED")
        raise InstallError("RECEIPT_ALREADY_PRESENT")

    _acquire_lock(home, lock_path, uid)
    staged_paths: list[Path] = []
    try:
        manifest = _validate_manifest(
            json.loads((package_root / "manifest.json").read_text(encoding="utf-8")),
            contract,
        )
        inventory = _verify_package_inventory(package_root, manifest, contract)
        prior_receiver = _assert_owned_regular(home / RECEIVER_REL, uid, 0o700)

        transaction = {
            "marker": MARKER,
            "schema": 1,
            "operationId": operation_id,
            "sourceCommit": contract["source_commit"],
            "phase": "staged",
            "rollbackReceiverGitBlob": contract["required_installed_receiver_git_blob"],
        }
        _atomic_write(transaction_path, _canonical(transaction), 0o600)
        _atomic_write(rollback_archive, prior_receiver, 0o600)

        install_root = home / INSTALL_LIB_REL
        stage_root = install_root / ".v2-receiver-staging"
        stage_root.mkdir(mode=0o700, exist_ok=True)
        for entry in contract["payload_entries"]:
            source = package_root.joinpath(*PurePosixPath(entry["package_path"]).parts)
            mode = int(entry["mode"], 8)
            staged = stage_root / Path(entry["package_path"]).name
            _atomic_write(staged, inventory[entry["package_path"]], mode)
            staged_paths.append(staged)
            if fault_after == entry["package_path"]:
                raise InstallError("SIMULATED_INTERRUPT")

        for entry in contract["payload_entries"]:
            target = home / Path(entry["target_relpath"])
            staged = stage_root / Path(entry["package_path"]).name
            mode = int(entry["mode"], 8)
            _assert_path_chain(home, target, uid)
            expected = inventory[entry["package_path"]]
            _atomic_write(target, expected, mode)
            readback = _assert_owned_regular(target, uid, mode)
            if readback != expected or _git_blob(readback) != entry["git_blob"]:
                raise InstallError("INSTALL_READBACK_INVALID")

        transaction["phase"] = "committed"
        _atomic_write(transaction_path, _canonical(transaction), 0o600)
        if fault_after == "receipt":
            raise InstallError("SIMULATED_INTERRUPT")

        receipt = {
            "marker": MARKER,
            "schema": 1,
            "operationId": operation_id,
            "sourceCommit": contract["source_commit"],
            "packageArtifact": contract["package_identity"],
            "installedReceiverGitBlob": contract["payload_entries"][0]["git_blob"],
            "installedInboundGitBlob": contract["payload_entries"][1]["git_blob"],
            "priorReceiverGitBlob": contract["required_installed_receiver_git_blob"],
            "rollbackArchiveRel": ROLLBACK_ARCHIVE_REL.as_posix(),
            "forcedCommand": FORCED_COMMAND,
            "authorizedKeysSha256": None,
        }
        _atomic_write(receipt_path, _canonical(receipt), 0o600)
        transaction_path.unlink()
        return receipt
    except Exception:
        for staged in staged_paths:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
        for target_rel, blob, mode in (
            (RECEIVER_REL, contract["required_installed_receiver_git_blob"], 0o700),
        ):
            target = home / target_rel
            if rollback_archive.exists():
                data = _assert_owned_regular(rollback_archive, uid, 0o600)
                if _git_blob(data) == blob:
                    _atomic_write(target, data, mode)
        if transaction_path.exists():
            transaction_path.unlink()
        raise
    finally:
        _release_lock(lock_path)


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
