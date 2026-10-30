#!/usr/bin/env python3
"""Read-only REDRIX Gate A0 evidence for DRAGONFLY-JIT-CANARY-RUNTIME-001.

This helper deliberately has no provider API, SSH, runner registration, QEMU launch,
install, recovery, rollback, or mutation path. It composes the accepted local JIT
state and transport-baseline contracts into sanitized point-in-time evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from types import ModuleType

MARKER = "DRAGONFLY_GATE_A0_V1"
ACCEPTED_LOCAL_ALIASES = {"redrix", "penguin"}
QEMU_NAMES = {"qemu-kvm", "kvm"}


class A0Error(RuntimeError):
    pass


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise A0Error("A0_SOURCE_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        raise A0Error("A0_GIT_PROVENANCE_UNAVAILABLE")
    return proc.stdout.strip()


def _assert_repo(repo: Path, expected_head: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", expected_head) is None:
        raise A0Error("A0_CONTROLLER_HEAD_INVALID")
    remote = _git(repo, "remote", "get-url", "origin")
    if re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(?:\.git)?",
        remote,
    ) is None:
        raise A0Error("A0_REPOSITORY_REFUSED")
    if _git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise A0Error("A0_SOURCE_WORKTREE_DIRTY")
    head = _git(repo, "rev-parse", "HEAD")
    if head != expected_head:
        raise A0Error("A0_CONTROLLER_HEAD_MISMATCH")
    return head


def _assert_owned_directory(path: Path, uid: int, *, label: str) -> Path:
    candidate = path.expanduser().absolute()
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise A0Error(label + "_MISSING") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise A0Error(label + "_INVALID")
    if candidate.resolve(strict=True) != candidate:
        raise A0Error(label + "_INVALID")
    return candidate


def _lock_available_readonly(path: Path) -> tuple[bool, bool]:
    present = path.exists() or path.is_symlink()
    if not present:
        return True, False
    if path.is_symlink() or not path.is_file():
        raise A0Error("A0_LOCK_PATH_INVALID")
    with path.open("rb") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False, True
        try:
            return True, True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _looks_like_qemu(token: str) -> bool:
    token = token.strip("'\";()[]{}:,=")
    if not token:
        return False
    name = Path(token).name
    return name in QEMU_NAMES or name.startswith("qemu-system-")


def _qemu_process_ids_from_ps(text: str) -> list[int]:
    matches: list[int] = []
    for raw in text.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        comm = parts[1]
        args = parts[2] if len(parts) > 2 else ""
        tokens = [comm]
        if args:
            tokens.extend(args.replace("\"", " ").replace("'", " ").split())
        if any(_looks_like_qemu(token) for token in tokens):
            matches.append(pid)
    return sorted(set(matches))


def _qemu_process_ids(process_output: str | None = None) -> list[int]:
    if process_output is not None:
        return _qemu_process_ids_from_ps(process_output)
    proc = subprocess.run(
        ["ps", "-eo", "pid=,comm=,args="],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        raise A0Error("A0_PROCESS_ENUMERATION_FAILED")
    return _qemu_process_ids_from_ps(proc.stdout)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _runtime_snapshot(*, controller, runs_root: Path, process_output: str | None) -> dict:
    status_path = controller.state_path
    if status_path.is_symlink():
        raise A0Error("A0_STATUS_PATH_INVALID")
    status_present = status_path.exists()
    current = controller.read_state()
    if current.get("state") != "STOPPED":
        raise A0Error("A0_JIT_STATE_NOT_STOPPED")
    if current.get("run_id") is not None:
        raise A0Error("A0_JIT_RUN_ID_PRESENT")
    if current.get("qemu_pid") is not None:
        raise A0Error("A0_JIT_QEMU_PID_PRESENT")

    run_entries = list(runs_root.iterdir())
    for entry in run_entries:
        if entry.is_symlink() or not entry.is_dir():
            raise A0Error("A0_RUN_ROOT_CONTAMINATED")
    if run_entries:
        raise A0Error("A0_RUN_RESIDUE_PRESENT")

    guest_lock_available, guest_lock_present = _lock_available_readonly(controller.guest_lock_path)
    if not guest_lock_available:
        raise A0Error("A0_GUEST_LOCK_BUSY")
    state_lock_available, state_lock_present = _lock_available_readonly(controller.state_lock_path)
    if not state_lock_available:
        raise A0Error("A0_STATE_LOCK_BUSY")

    processes = _qemu_process_ids(process_output)
    if processes:
        raise A0Error("A0_QEMU_PROCESS_PRESENT")

    return {
        "jitState": "STOPPED",
        "jitStateSource": "file-backed" if status_present else "implicit-default",
        "statusFilePresent": status_present,
        "runIdPresent": False,
        "qemuPidPresent": False,
        "runResidueCount": 0,
        "qemuProcessCount": 0,
        "guestLockAvailable": True,
        "guestLockFilePresent": guest_lock_present,
        "stateLockAvailable": True,
        "stateLockFilePresent": state_lock_present,
    }


def collect_a0(
    *,
    repo: Path,
    expected_head: str,
    home: Path,
    uid: int,
    state_root: Path,
    data_root: Path,
    hostname: str,
    expected_local_alias: str,
    process_output: str | None = None,
) -> dict:
    repo = repo.expanduser().absolute()
    head = _assert_repo(repo, expected_head)

    expected_alias = expected_local_alias.lower()
    if expected_alias not in ACCEPTED_LOCAL_ALIASES:
        raise A0Error("A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID")
    local_alias = hostname.split(".", 1)[0].lower()
    if local_alias != expected_alias:
        raise A0Error("A0_LOCAL_HOST_IDENTITY_MISMATCH")

    jit = _load_module("ldw_gate_a0_jit", repo / "dragonfly-jit" / "dragonfly_jit.py")
    installer = _load_module(
        "ldw_gate_a0_installer", repo / "tools" / "dragonfly_canary_redrix_install.py"
    )

    home = _assert_owned_directory(home, uid, label="A0_HOME")
    state_root = _assert_owned_directory(state_root, uid, label="A0_STATE_ROOT")
    runs_root = _assert_owned_directory(state_root / "runs", uid, label="A0_RUNS_ROOT")
    controller = jit.Controller(data_root=data_root, state_root=state_root)

    runtime_before = _runtime_snapshot(
        controller=controller,
        runs_root=runs_root,
        process_output=process_output,
    )

    transaction = home / installer.TRANSACTION_REL
    if transaction.exists() or transaction.is_symlink():
        raise A0Error("A0_INSTALL_TRANSACTION_PRESENT")

    receipt = home / installer.RECEIPT_REL
    if receipt.exists() or receipt.is_symlink():
        raise A0Error("A0_INSTALL_RECEIPT_PRESENT")

    try:
        baseline, _preexisting = installer._recognize_baseline(home, uid)
        installer._authorized_keys_digest(home, uid, installer.FORCED_COMMAND)
    except Exception as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code):
            raise A0Error(code) from exc
        raise A0Error("A0_TRANSPORT_BASELINE_UNVERIFIED") from exc
    if baseline != "accepted-115":
        raise A0Error("A0_TRANSPORT_BASELINE_NOT_ACCEPTED_115")

    runtime_after = _runtime_snapshot(
        controller=controller,
        runs_root=runs_root,
        process_output=process_output,
    )
    if runtime_after != runtime_before:
        raise A0Error("A0_RUNTIME_SNAPSHOT_CHANGED")

    stable_snapshot = {
        "schema": 1,
        "marker": MARKER,
        "controllerHead": head,
        "localHostAlias": local_alias,
        **runtime_after,
        "stabilityPasses": 2,
        "transportBaseline": "accepted-115",
        "authorizedKeysInvariant": True,
        "installTransactionPending": False,
        "installReceiptPresent": False,
    }
    snapshot_digest = hashlib.sha256(_canonical(stable_snapshot)).hexdigest()
    generated_at = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        **stable_snapshot,
        "generatedAt": generated_at,
        "snapshotSha256": snapshot_digest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only REDRIX Gate A0 evidence")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-controller-head", required=True)
    parser.add_argument(
        "--expected-local-alias",
        required=True,
        choices=sorted(ACCEPTED_LOCAL_ALIASES),
    )
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux":
            raise A0Error("A0_LINUX_REQUIRED")
        if os.geteuid() != 1000 or Path.home() != Path("/home/eddie"):
            raise A0Error("A0_OWNER_IDENTITY_INVALID")
        evidence = collect_a0(
            repo=args.repo_root,
            expected_head=args.expected_controller_head,
            home=Path("/home/eddie"),
            uid=1000,
            state_root=Path("/home/eddie/.local/state/ldw-dragonfly-jit"),
            data_root=Path("/home/eddie/.local/share/ldw-jit"),
            hostname=socket.gethostname(),
            expected_local_alias=args.expected_local_alias,
        )
        print("DRAGONFLY_GATE_A0=PASS")
        print("EVIDENCE_JSON=" + json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    except (A0Error, OSError, ValueError, json.JSONDecodeError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "A0_READBACK_FAILED"
        print("DRAGONFLY_GATE_A0=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
