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
import json
import os
from pathlib import Path
import re
import socket
import sys
from types import ModuleType

ACCEPTED_MAIN_COMMIT = "f736bbd36da4e99bb10c6e33b0dfba3bd7074f0b"
INSTALLER_BLOB = "ed8337a74a85ddfe4f1afff8fe02789fd533f51f"
A0_BLOB = "fc9784a52d5f0d20b02c5d95ad4adc2e86ae04e9"
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_UID = 1000
ACCEPTED_LOCAL_ALIASES = {"redrix", "penguin"}
PACKAGE_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class A4Error(RuntimeError):
    pass


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _load_pinned(name: str, path: Path, expected_blob: str) -> ModuleType:
    """Execute one verified byte string. The pathname is not opened again."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise A4Error("A4_SOURCE_UNAVAILABLE") from exc
    if _git_blob(data) != expected_blob:
        raise A4Error("A4_SOURCE_IDENTITY_MISMATCH")
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = None
    module.__loader__ = None
    module.__spec__ = None
    try:
        code = compile(data, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as exc:
        raise A4Error("A4_SOURCE_IMPORT_FAILED") from exc
    return module


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _accepted_115_preexisting_map(installer: ModuleType) -> dict[str, bool]:
    rollback_targets = {rel.as_posix() for _, _, rel, _ in installer.ROLLBACK}
    return {
        rel.as_posix(): rel.as_posix() in rollback_targets
        for _, _, rel, _ in installer.CURRENT
    }


def _assert_receipt_validated(
    receipt: dict,
    *,
    installer: ModuleType,
    expected_package_sha256: str,
) -> dict:
    if receipt.get("packageSha256") != expected_package_sha256:
        raise A4Error("A4_RECEIPT_PACKAGE_IDENTITY_MISMATCH")
    if receipt.get("sourceCommit") != installer.SOURCE_COMMIT:
        raise A4Error("A4_RECEIPT_SOURCE_COMMIT_MISMATCH")
    if receipt.get("sourceTree") != installer.SOURCE_TREE:
        raise A4Error("A4_RECEIPT_SOURCE_TREE_MISMATCH")
    if receipt.get("rollbackBaseline") != "accepted-115":
        raise A4Error("A4_ROLLBACK_BASELINE_NOT_RETAINED")
    if receipt.get("preexisting") != _accepted_115_preexisting_map(installer):
        raise A4Error("A4_RECEIPT_PREEXISTING_MISMATCH")
    bound = dict(receipt)
    bound["preexisting"] = dict(receipt["preexisting"])
    return bound


def _validate_install_receipt(
    *,
    home: Path,
    uid: int,
    installer: ModuleType,
    expected_package_sha256: str,
) -> dict:
    if PACKAGE_SHA256_RE.fullmatch(expected_package_sha256) is None:
        raise A4Error("A4_EXPECTED_PACKAGE_SHA256_INVALID")
    read_receipt = getattr(installer, "_read_receipt", None)
    if read_receipt is None:
        raise A4Error("A4_RECEIPT_READBACK_INVALID")
    try:
        receipt = read_receipt(home, uid)
    except Exception as exc:
        raise A4Error("A4_RECEIPT_READBACK_INVALID") from exc
    return _assert_receipt_validated(
        receipt,
        installer=installer,
        expected_package_sha256=expected_package_sha256,
    )


def _read_validated_receipt_after_readback(
    *,
    home: Path,
    uid: int,
    installer: ModuleType,
    expected_package_sha256: str,
    receipt_before: dict,
) -> dict:
    read_receipt = getattr(installer, "_read_receipt", None)
    if read_receipt is None:
        raise A4Error("A4_RECEIPT_READBACK_INVALID")
    try:
        receipt = dict(read_receipt(home, uid))
    except Exception as exc:
        raise A4Error("A4_RECEIPT_READBACK_INVALID") from exc
    receipt["preexisting"] = dict(receipt["preexisting"])
    if receipt_before != receipt:
        raise A4Error("A4_RECEIPT_CHANGED_DURING_READBACK")
    return _assert_receipt_validated(
        receipt,
        installer=installer,
        expected_package_sha256=expected_package_sha256,
    )


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
    expected_package_sha256: str,
    proc_root: Path,
) -> dict:
    alias = socket.gethostname().split(".", 1)[0].lower()
    if expected_local_alias not in ACCEPTED_LOCAL_ALIASES:
        raise A4Error("A4_EXPECTED_LOCAL_HOST_IDENTITY_INVALID")
    if alias != expected_local_alias:
        raise A4Error("A4_LOCAL_HOST_IDENTITY_MISMATCH")

    receipt_before = _validate_install_receipt(
        home=home,
        uid=uid,
        installer=installer,
        expected_package_sha256=expected_package_sha256,
    )
    installed = installer.readback_fixture(home, uid, installer.FORCED_COMMAND)
    _read_validated_receipt_after_readback(
        home=home,
        uid=uid,
        installer=installer,
        expected_package_sha256=expected_package_sha256,
        receipt_before=receipt_before,
    )
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
        "packageIdentity": "expected",
        "rollbackReceiptValidated": True,
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
    expected_package_sha256: str,
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
        expected_package_sha256=expected_package_sha256,
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
        expected_package_sha256=expected_package_sha256,
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
    parser.add_argument("--expected-package-sha256", required=True)
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
            expected_package_sha256=args.expected_package_sha256,
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
