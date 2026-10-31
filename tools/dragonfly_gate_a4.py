#!/usr/bin/env python3
"""Read-only REDRIX Gate A4 acceptance evidence for issue #139.

A4 composes the accepted post-install canary receipt/readback with the already
accepted local JIT, QEMU, authorized-key, OpenSSH, and Tailscale posture checks.
It exposes no install/recovery/rollback, provider, runner, SSH-client, service
mutation, or VM-launch path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
from types import ModuleType

INSTALLER_BLOB = "889cff6d25aff80963c21070e994406414b272a4"
A0_BLOB = "fc9784a52d5f0d20b02c5d95ad4adc2e86ae04e9"
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_UID = 1000
ACCEPTED_LOCAL_ALIASES = {"redrix", "penguin"}


class A4Error(RuntimeError):
    pass


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _load_pinned(name: str, path: Path, expected_blob: str) -> ModuleType:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise A4Error("A4_SOURCE_UNAVAILABLE") from exc
    if _git_blob(data) != expected_blob:
        raise A4Error("A4_SOURCE_IDENTITY_MISMATCH")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise A4Error("A4_SOURCE_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _collect_once(
    *,
    home: Path,
    uid: int,
    installer: ModuleType,
    a0: ModuleType,
    runner,
    expected_local_alias: str,
    expected_host_fingerprint: str,
    expected_transport_key_sha256: str,
    proc_root: Path,
) -> dict:
    alias = socket.gethostname().split(".", 1)[0].lower()
    if expected_local_alias not in ACCEPTED_LOCAL_ALIASES:
        raise A4Error("A4_EXPECTED_LOCAL_HOST_IDENTITY_INVALID")
    if alias != expected_local_alias:
        raise A4Error("A4_LOCAL_HOST_IDENTITY_MISMATCH")

    installed = installer.readback_fixture(home, uid, installer.FORCED_COMMAND)
    if installed.get("sourceCommit") != installer.SOURCE_COMMIT:
        raise A4Error("A4_INSTALLED_SOURCE_COMMIT_MISMATCH")
    if installed.get("sourceTree") != installer.SOURCE_TREE:
        raise A4Error("A4_INSTALLED_SOURCE_TREE_MISMATCH")
    if installed.get("authorizedKeysInvariant") is not True:
        raise A4Error("A4_AUTHORIZED_KEYS_INVARIANT_FAILED")
    if installed.get("transactionPending") is not False:
        raise A4Error("A4_INSTALL_TRANSACTION_PENDING")
    if installed.get("rollbackBaseline") != "accepted-115":
        raise A4Error("A4_ROLLBACK_BASELINE_NOT_RETAINED")
    if installed.get("files") != len(installer.CURRENT):
        raise A4Error("A4_INSTALLED_FILE_COUNT_MISMATCH")

    try:
        jit = a0._validate_jit_state(home, uid)
        qemu = a0._qemu_snapshot(runner, proc_root, uid)
        key = a0._transport_authorized_key(home, uid, expected_transport_key_sha256)
        network = a0._network_snapshot(runner, expected_host_fingerprint)
    except Exception as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code):
            raise A4Error(code.replace("A0_", "A4_", 1) if code.startswith("A0_") else code) from exc
        raise A4Error("A4_POSTURE_READBACK_FAILED") from exc

    return {
        "schema": 1,
        "marker": "DRAGONFLY_GATE_A4_V1",
        "localHostAlias": alias,
        "installedSourceCommit": installed["sourceCommit"],
        "installedSourceTree": installed["sourceTree"],
        "installedFiles": installed["files"],
        "rollbackBaseline": installed["rollbackBaseline"],
        "rollbackRetained": True,
        "installTransactionPending": False,
        "installReceiptValidated": True,
        **jit,
        **qemu,
        **key,
        **network,
    }


def collect_a4(
    *,
    home: Path,
    uid: int,
    installer: ModuleType,
    a0: ModuleType,
    runner,
    expected_local_alias: str,
    expected_host_fingerprint: str,
    expected_transport_key_sha256: str,
    proc_root: Path,
) -> dict:
    first = _collect_once(
        home=home,
        uid=uid,
        installer=installer,
        a0=a0,
        runner=runner,
        expected_local_alias=expected_local_alias,
        expected_host_fingerprint=expected_host_fingerprint,
        expected_transport_key_sha256=expected_transport_key_sha256,
        proc_root=proc_root,
    )
    second = _collect_once(
        home=home,
        uid=uid,
        installer=installer,
        a0=a0,
        runner=runner,
        expected_local_alias=expected_local_alias,
        expected_host_fingerprint=expected_host_fingerprint,
        expected_transport_key_sha256=expected_transport_key_sha256,
        proc_root=proc_root,
    )
    if first != second:
        raise A4Error("A4_SNAPSHOT_CHANGED_DURING_READBACK")
    digest = hashlib.sha256(_canonical(second)).hexdigest()
    generated_at = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        **second,
        "stabilityPasses": 2,
        "snapshotSha256": digest,
        "generatedAt": generated_at,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only REDRIX Gate A4 acceptance evidence")
    parser.add_argument("--expected-local-alias", required=True, choices=sorted(ACCEPTED_LOCAL_ALIASES))
    parser.add_argument("--expected-host-fingerprint", required=True)
    parser.add_argument("--expected-transport-key-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux":
            raise A4Error("A4_LINUX_REQUIRED")
        if os.geteuid() != PRODUCTION_UID or Path.home() != PRODUCTION_HOME:
            raise A4Error("A4_OWNER_IDENTITY_INVALID")
        tools = Path(__file__).resolve().parent
        installer = _load_pinned(
            "ldw_gate_a4_installer",
            tools / "dragonfly_canary_redrix_install.py",
            INSTALLER_BLOB,
        )
        a0 = _load_pinned(
            "ldw_gate_a4_a0",
            tools / "dragonfly_gate_a0.py",
            A0_BLOB,
        )
        evidence = collect_a4(
            home=PRODUCTION_HOME,
            uid=PRODUCTION_UID,
            installer=installer,
            a0=a0,
            runner=a0._default_runner,
            expected_local_alias=args.expected_local_alias,
            expected_host_fingerprint=args.expected_host_fingerprint,
            expected_transport_key_sha256=args.expected_transport_key_sha256,
            proc_root=a0.PROC_ROOT,
        )
        print("DRAGONFLY_GATE_A4=PASS")
        print("EVIDENCE_JSON=" + json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    except (A4Error, OSError, ValueError, json.JSONDecodeError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "A4_READBACK_FAILED"
        print("DRAGONFLY_GATE_A4=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
