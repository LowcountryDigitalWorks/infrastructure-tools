#!/usr/bin/env python3
"""Forced-command receiver for the reviewed Dragonfly JIT handoff contract."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys

REMOTE_SENTINEL = "/nonexistent/ldw-dragonfly-jit-handoff-v1"
OWNER_USER = "eddie"
HANDOFF_MODULE_NAME = "ldw_dragonfly_handoff_contract"
HANDOFF_FILENAME = "handoff_contract.py"
EXPECTED_HANDOFF_GIT_BLOB = "cedf75fb360f05893afea119782f646da8a2e28b"
CANARY_EXECUTOR_MODULE_NAME = "ldw_dragonfly_canary_executor"
CANARY_EXECUTOR_FILENAME = "canary_executor.py"
EXPECTED_CANARY_EXECUTOR_GIT_BLOB = "c8c51040b99b0f2f8fd6b10156395244505d61cc"
CANARY_PROFILE_ID = "dragonfly-github-canary-v1"
MAX_HANDOFF_BYTES = 256 * 1024
MAX_EXECUTOR_BYTES = 256 * 1024
MAX_RECEIVER_BYTES = 64 * 1024


class ReceiverError(RuntimeError):
    pass


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _assert_path_not_symlinked(path: Path) -> Path:
    path = path.absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    return path


def _assert_owned_regular_source(path: Path, *, max_bytes: int) -> bytes:
    path = _assert_path_not_symlinked(path)
    try:
        st = path.stat()
    except OSError as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > max_bytes:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc


def _assert_pinned_source(path: Path, *, expected_blob: str, max_bytes: int) -> bytes:
    data = _assert_owned_regular_source(path, max_bytes=max_bytes)
    if _git_blob_sha1(data) != expected_blob:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    return data


def _assert_regular_private_source(path: Path) -> bytes:
    return _assert_pinned_source(path, expected_blob=EXPECTED_HANDOFF_GIT_BLOB, max_bytes=MAX_HANDOFF_BYTES)


def _load_module(*, module_name: str, source_path: Path, expected_blob: str, max_bytes: int):
    _assert_pinned_source(source_path, expected_blob=expected_blob, max_bytes=max_bytes)
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    if spec is None or spec.loader is None:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc
    return module


def _load_handoff_contract():
    receiver_path = Path(__file__).absolute()
    _assert_owned_regular_source(receiver_path, max_bytes=MAX_RECEIVER_BYTES)
    return _load_module(
        module_name=HANDOFF_MODULE_NAME,
        source_path=receiver_path.parent / HANDOFF_FILENAME,
        expected_blob=EXPECTED_HANDOFF_GIT_BLOB,
        max_bytes=MAX_HANDOFF_BYTES,
    )


def _load_canary_executor():
    receiver_path = Path(__file__).absolute()
    _assert_owned_regular_source(receiver_path, max_bytes=MAX_RECEIVER_BYTES)
    return _load_module(
        module_name=CANARY_EXECUTOR_MODULE_NAME,
        source_path=receiver_path.parent / CANARY_EXECUTOR_FILENAME,
        expected_blob=EXPECTED_CANARY_EXECUTOR_GIT_BLOB,
        max_bytes=MAX_EXECUTOR_BYTES,
    )


def _owner_state_root() -> Path:
    if not sys.platform.startswith("linux") or not hasattr(os, "geteuid"):
        raise ReceiverError("RECEIVER_PLATFORM_INVALID")
    uid = os.geteuid()
    if uid == 0:
        raise ReceiverError("RECEIVER_IDENTITY_INVALID")
    try:
        owner = pwd.getpwuid(uid)
    except KeyError as exc:
        raise ReceiverError("RECEIVER_IDENTITY_INVALID") from exc
    if owner.pw_name != OWNER_USER or not owner.pw_dir.startswith("/"):
        raise ReceiverError("RECEIVER_IDENTITY_INVALID")
    return Path(owner.pw_dir) / ".local/state/ldw-dragonfly-jit"


def run_receiver(*, stdin, stdout, stderr, environ: dict[str, str], state_root: Path | None = None) -> int:
    try:
        if environ.get("SSH_ORIGINAL_COMMAND") != REMOTE_SENTINEL:
            raise ReceiverError("ORIGINAL_COMMAND_INVALID")
        root = state_root if state_root is not None else _owner_state_root()
        handoff = _load_handoff_contract()
        payload = handoff.read_capsule(stdin)
        summary = handoff.validate_capsule(payload)
        handoff.claim_dispatch(summary, state_root=root)
        result = dict(summary)
        result["claimed"] = True
        if summary.get("profile_id") == CANARY_PROFILE_ID:
            executor = _load_canary_executor()
            execution = executor.execute_canary(payload, summary, state_root=root)
            if not isinstance(execution, dict):
                raise ReceiverError("CANARY_EXECUTOR_RESULT_INVALID")
            result["execution"] = execution
        stdout.write((json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        return 0
    except ReceiverError as exc:
        stderr.write(f"ERROR:{exc}\n".encode("utf-8"))
        return 2
    except Exception as exc:
        handoff_error = getattr(locals().get("handoff", None), "HandoffError", None)
        executor_error = getattr(locals().get("executor", None), "CanaryExecutorError", None)
        if handoff_error is not None and isinstance(exc, handoff_error):
            stderr.write(f"ERROR:{exc}\n".encode("utf-8"))
            return 2
        if executor_error is not None and isinstance(exc, executor_error):
            stderr.write(f"ERROR:{exc}\n".encode("utf-8"))
            return 2
        stderr.write(b"ERROR:RECEIVER_FAILED\n")
        return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        sys.stderr.write("ERROR:RECEIVER_ARGUMENTS_INVALID\n")
        return 2
    return run_receiver(
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr.buffer,
        environ=dict(os.environ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
