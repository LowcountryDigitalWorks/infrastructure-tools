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


def _lock_available_readonly(path: Path) -> bool:
    if not path.exists() and not path.is_symlink():
        return True
    if path.is_symlink() or not path.is_file():
        raise A0Error("A0_LOCK_PATH_INVALID")
    with path.open("rb") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        try:
            return True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _qemu_process_ids() -> list[int]:
    proc = subprocess.run(
        ["ps", "-eo", "pid=,comm=,args="],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        raise A0Error("A0_PROCESS_ENUMERATION_FAILED")
    matches: list[int] = []
    for raw in proc.stdout.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        comm = parts[1]
        args = parts[2] if len(parts) > 2 else ""
        first = args.split(None, 1)[0] if args else ""
        executable = Path(first).name if first else ""
        if comm.startswith("qemu-system") or executable == "qemu-system-x86_64":
            matches.append(pid)
    return sorted(set(matches))


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def collect_a0(
    *,
    repo: Path,
    expected_head: str,
    home: Path,
    uid: int,
    state_root: Path,
    data_root: Path,
    hostname: str,
    qemu_pids: list[int] | None = None,
) -> dict:
    repo = repo.expanduser().absolute()
    head = _assert_repo(repo, expected_head)

    local_alias = hostname.split(".", 1)[0].lower()
    if local_alias not in ACCEPTED_LOCAL_ALIASES:
        raise A0Error("A0_LOCAL_HOST_IDENTITY_REFUSED")

    jit = _load_module("ldw_gate_a0_jit", repo / "dragonfly-jit" / "dragonfly_jit.py")
    installer = _load_module(
        "ldw_gate_a0_installer", repo / "tools" / "dragonfly_canary_redrix_install.py"
    )

    home = _assert_owned_directory(home, uid, label="A0_HOME")
    state_root = _assert_owned_directory(state_root, uid, label="A0_STATE_ROOT")
    runs_root = _assert_owned_directory(state_root / "runs", uid, label="A0_RUNS_ROOT")

    controller = jit.Controller(data_root=data_root, state_root=state_root)
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

    if not _lock_available_readonly(controller.guest_lock_path):
        raise A0Error("A0_GUEST_LOCK_BUSY")
    if not _lock_available_readonly(controller.state_lock_path):
        raise A0Error("A0_STATE_LOCK_BUSY")

    processes = _qemu_process_ids() if qemu_pids is None else sorted(qemu_pids)
    if processes:
        raise A0Error("A0_QEMU_PROCESS_PRESENT")

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

    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    evidence = {
        "schema": 1,
        "marker": MARKER,
        "generatedAt": generated_at,
        "controllerHead": head,
        "localHostIdentity": "accepted-redrix-alias",
        "jitState": "STOPPED",
        "runIdPresent": False,
        "qemuPidPresent": False,
        "runResidueCount": 0,
        "qemuProcessCount": 0,
        "guestLockAvailable": True,
        "stateLockAvailable": True,
        "transportBaseline": "accepted-115",
        "authorizedKeysInvariant": True,
        "installTransactionPending": False,
        "installReceiptPresent": False,
    }
    digest = hashlib.sha256(_canonical(evidence)).hexdigest()
    evidence["evidenceSha256"] = digest
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only REDRIX Gate A0 evidence")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-controller-head", required=True)
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
