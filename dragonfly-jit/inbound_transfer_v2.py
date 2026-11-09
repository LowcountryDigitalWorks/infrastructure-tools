#!/usr/bin/env python3
"""Closed inbound profile for the pinned Dragonfly adjunct V2 release transfer."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

TRANSFER_MARKER = "DRAGONFLY-V2-PACKAGE-TRANSFER-001"
TRANSFER_SCHEMA = 1
ARTIFACT_ID = "ldw-dragonfly-canary-adjunct-v2"
CANARY_COMMIT = "78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca"
CANARY_TREE = "5f54ee5b76f49250db1358f058745cb30b6587ef"
ENTRY_COMMIT = "e53e016383441fde6ba22cb57821b3d26bdf4824"
ENTRY_TREE = "18e910ba4ed5113a1a4b5065bcc8f08a5e0084cb"
RELEASE_IDENTITY = f"{CANARY_COMMIT}-{ENTRY_COMMIT}"
DISPATCH_COMMIT = "ce2bf253556a69dfb43de7bb8e8a4927c41c9e15"
DISPATCH_TREE = "57ceb47f2a0a40d3b176cde0818a0ad8c5891dca"
DISPATCH_BLOB = "c862dd503b98060ec984206e63ef9efa5f957e8f"
DISPATCH_RAW_SHA256 = "76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675"
DISPATCH_WINDOWS_SHA256 = "0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72"
PINNED_FILE_PATHS = (
    "ci-dispatch/DragonflyCanary.psm1",
    "ci-dispatch/DragonflyCanaryRuntime.psm1",
    "ci-dispatch/Invoke-DragonflyCanaryProduction.ps1",
    "ci-dispatch/Dispatch.psm1",
)
MAX_TRANSFER_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
MANIFEST_FILENAME = "manifest.json"


class TransferError(RuntimeError):
    pass


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(stream, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = stream.read(min(65536, limit - total))
        if not block:
            break
        total += len(block)
        if total > limit:
            raise TransferError("TRANSFER_PAYLOAD_TOO_LARGE")
        chunks.append(block)
    if not chunks:
        raise TransferError("TRANSFER_PAYLOAD_EMPTY")
    return b"".join(chunks)


def _assert_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode
    if not stat.S_ISDIR(mode):
        raise TransferError("TRANSFER_STAGING_INVALID")
    if hasattr(os, "geteuid"):
        if path.stat().st_uid != os.geteuid():
            raise TransferError("TRANSFER_STAGING_INVALID")
        if mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_IRWXG | stat.S_IRWXO):
            raise TransferError("TRANSFER_STAGING_INVALID")


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def validate_transfer_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict):
        raise TransferError("TRANSFER_MANIFEST_INVALID")
    required = {
        "schema": 2,
        "artifact": ARTIFACT_ID,
        "releaseIdentity": RELEASE_IDENTITY,
        "canaryCommit": CANARY_COMMIT,
        "canaryTree": CANARY_TREE,
        "entryCommit": ENTRY_COMMIT,
        "entryTree": ENTRY_TREE,
        "containsCredential": False,
        "containsBootstrap": False,
        "containsPrivateEndpoint": False,
    }
    for key, value in required.items():
        if manifest.get(key) != value:
            raise TransferError("TRANSFER_MANIFEST_PIN_MISMATCH")
    authority = manifest.get("dispatchAuthority")
    if not isinstance(authority, dict):
        raise TransferError("TRANSFER_MANIFEST_INVALID")
    authority_checks = {
        "commit": DISPATCH_COMMIT,
        "tree": DISPATCH_TREE,
        "blob": DISPATCH_BLOB,
        "rawSha256": DISPATCH_RAW_SHA256,
        "windowsSha256": DISPATCH_WINDOWS_SHA256,
        "materialization": "crlf",
    }
    for key, value in authority_checks.items():
        if authority.get(key) != value:
            raise TransferError("TRANSFER_MANIFEST_PIN_MISMATCH")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != len(PINNED_FILE_PATHS):
        raise TransferError("TRANSFER_MANIFEST_FILES_INVALID")
    paths = []
    for entry in files:
        if not isinstance(entry, dict):
            raise TransferError("TRANSFER_MANIFEST_FILES_INVALID")
        path = entry.get("path")
        sha = entry.get("sha256")
        if not isinstance(path, str) or path not in PINNED_FILE_PATHS:
            raise TransferError("TRANSFER_MANIFEST_FILES_INVALID")
        if not isinstance(sha, str) or len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
            raise TransferError("TRANSFER_MANIFEST_FILES_INVALID")
        paths.append(path)
    if sorted(paths) != sorted(PINNED_FILE_PATHS):
        raise TransferError("TRANSFER_MANIFEST_FILES_INVALID")
    return manifest


def validate_transfer_envelope(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise TransferError("TRANSFER_ENVELOPE_INVALID")
    if payload.get("schema") != TRANSFER_SCHEMA or payload.get("marker") != TRANSFER_MARKER:
        raise TransferError("TRANSFER_ENVELOPE_MARKER_INVALID")
    if payload.get("release_identity") != RELEASE_IDENTITY:
        raise TransferError("TRANSFER_RELEASE_IDENTITY_INVALID")
    manifest_sha256 = payload.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64:
        raise TransferError("TRANSFER_MANIFEST_SHA_INVALID")
    manifest = validate_transfer_manifest(payload.get("manifest"))
    files = payload.get("files")
    if not isinstance(files, dict) or set(files) != set(PINNED_FILE_PATHS):
        raise TransferError("TRANSFER_FILE_SET_INVALID")
    decoded: dict[str, bytes] = {}
    for path in PINNED_FILE_PATHS:
        entry = files[path]
        if not isinstance(entry, dict):
            raise TransferError("TRANSFER_FILE_ENTRY_INVALID")
        expected_sha = next(item["sha256"] for item in manifest["files"] if item["path"] == path)
        if entry.get("sha256") != expected_sha:
            raise TransferError("TRANSFER_FILE_SHA_MISMATCH")
        content = entry.get("content")
        if not isinstance(content, str):
            raise TransferError("TRANSFER_FILE_CONTENT_INVALID")
        try:
            data = base64.b64decode(content, validate=True)
        except Exception as exc:
            raise TransferError("TRANSFER_FILE_CONTENT_INVALID") from exc
        if len(data) > MAX_FILE_BYTES:
            raise TransferError("TRANSFER_FILE_TOO_LARGE")
        if _sha256_hex(data) != expected_sha:
            raise TransferError("TRANSFER_FILE_DIGEST_MISMATCH")
        decoded[path] = data
    manifest_blob = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if _sha256_hex(manifest_blob) != manifest_sha256:
        raise TransferError("TRANSFER_MANIFEST_SHA_MISMATCH")
    decoded[MANIFEST_FILENAME] = manifest_blob
    return {
        "manifest_sha256": manifest_sha256,
        "files": decoded,
        "manifest": manifest,
    }


def _claim_manifest_once(state_root: Path, manifest_sha256: str) -> None:
    state_root.mkdir(parents=True, exist_ok=True)
    _assert_private_dir(state_root)
    claim_path = state_root / "v2-transfer-claims.json"
    claims: dict[str, str] = {}
    if claim_path.exists():
        try:
            claims = json.loads(claim_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise TransferError("TRANSFER_CLAIM_STATE_INVALID") from exc
        if not isinstance(claims, dict):
            raise TransferError("TRANSFER_CLAIM_STATE_INVALID")
    if manifest_sha256 in claims.values():
        raise TransferError("TRANSFER_REPLAY_REFUSED")
    claims[RELEASE_IDENTITY] = manifest_sha256
    _write_private_file(claim_path, json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def install_transfer_bundle(
    envelope: dict,
    *,
    install_root: Path,
    state_root: Path,
) -> dict:
    release_root = install_root / "releases" / RELEASE_IDENTITY
    if release_root.exists():
        raise TransferError("TRANSFER_RELEASE_ALREADY_PRESENT")
    _claim_manifest_once(state_root, envelope["manifest_sha256"])
    install_root.mkdir(parents=True, exist_ok=True)
    _assert_private_dir(install_root)
    staging = Path(tempfile.mkdtemp(prefix="ldw-v2-transfer-", dir=install_root))
    try:
        _assert_private_dir(staging)
        for rel_path, data in envelope["files"].items():
            target = staging / rel_path
            _write_private_file(target, data)
        release_root.parent.mkdir(parents=True, exist_ok=True)
        _assert_private_dir(release_root.parent)
        os.replace(staging, release_root)
        staging = None
    finally:
        if staging is not None and staging.exists():
            for child in sorted(staging.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
            staging.rmdir()
    receiver_manifest = (release_root / MANIFEST_FILENAME).read_bytes()
    receiver_sha = _sha256_hex(receiver_manifest)
    if receiver_sha != envelope["manifest_sha256"]:
        raise TransferError("TRANSFER_READBACK_MISMATCH")
    file_evidence = []
    for rel_path in PINNED_FILE_PATHS:
        data = (release_root / rel_path).read_bytes()
        file_evidence.append({"path": rel_path, "sha256": _sha256_hex(data)})
    return {
        "outcome": "TRANSFER_INSTALLED",
        "release_identity": RELEASE_IDENTITY,
        "manifest_sha256_sender": envelope["manifest_sha256"],
        "manifest_sha256_receiver": receiver_sha,
        "files": file_evidence,
    }


def run_inbound_transfer(
    *,
    stdin,
    stdout,
    stderr,
    install_root: Path,
    state_root: Path,
) -> int:
    try:
        raw = _read_bounded(stdin, MAX_TRANSFER_BYTES)
        payload = json.loads(raw.decode("utf-8"))
        envelope = validate_transfer_envelope(payload)
        evidence = install_transfer_bundle(envelope, install_root=install_root, state_root=state_root)
        stdout.write((json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        return 0
    except TransferError as exc:
        stderr.write(f"ERROR:{exc}\n".encode("utf-8"))
        return 2
    except json.JSONDecodeError:
        stderr.write(b"ERROR:TRANSFER_JSON_INVALID\n")
        return 2
    except Exception:
        stderr.write(b"ERROR:TRANSFER_FAILED\n")
        return 2
