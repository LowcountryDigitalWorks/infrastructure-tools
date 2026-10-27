#!/usr/bin/env python3
"""Forced-command receiver for the reviewed Dragonfly JIT handoff contract.

This source opens no listener. It is intended only as the fixed command behind a
separately reviewed, dedicated OpenSSH key restriction after #115's live REDRIX
capability/security gate. The receiver accepts one fixed SSH original-command
sentinel, reads one bounded V6 capsule from stdin, claims it using the already
accepted handoff contract, and emits only the sanitized claim summary.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys

REMOTE_SENTINEL = "ldw-dragonfly-jit-handoff-v1"
OWNER_USER = "eddie"
HANDOFF_MODULE_NAME = "ldw_dragonfly_handoff_contract"
HANDOFF_FILENAME = "handoff_contract.py"
EXPECTED_HANDOFF_GIT_BLOB = "2f7892275bacd9f56abaa0cdf204f46f79c046c0"
MAX_HANDOFF_BYTES = 256 * 1024


class ReceiverError(RuntimeError):
    pass


def _git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _assert_regular_private_source(path: Path) -> bytes:
    path = path.absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    try:
        st = path.stat()
    except OSError as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > MAX_HANDOFF_BYTES:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc
    if _git_blob_sha1(data) != EXPECTED_HANDOFF_GIT_BLOB:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    return data


def _load_handoff_contract():
    source_path = Path(__file__).resolve().parent / HANDOFF_FILENAME
    _assert_regular_private_source(source_path)
    spec = importlib.util.spec_from_file_location(HANDOFF_MODULE_NAME, source_path)
    if spec is None or spec.loader is None:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ReceiverError("HANDOFF_SOURCE_UNTRUSTED") from exc
    return module


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
        stdout.write((json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        return 0
    except ReceiverError as exc:
        stderr.write(f"ERROR:{exc}\n".encode("utf-8"))
        return 2
    except Exception as exc:
        handoff_error = getattr(locals().get("handoff", None), "HandoffError", None)
        if handoff_error is not None and isinstance(exc, handoff_error):
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
