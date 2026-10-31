#!/usr/bin/env python3
"""Gate A1 bounded transport public identity derivation (source-only).

Derives the REDRIX Gate A3 transport-key SHA-256 from the protected LDW01
transport private key using a fixed Windows OpenSSH ``ssh-keygen.exe`` path and a
single bound read of the private key (no PATH lookup, no digest-only record minting).
Emits only digests and provenance records — never private key material.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

RECORD_SCHEMA = "GATE_A1_TRANSPORT_IDENTITY_V1"
PROVENANCE = "gate-a1-ldw01-transport-private-key-unchanged-contract"
PROVENANCE_LINE = f"PROVENANCE={PROVENANCE}"
DIGEST_LINE_PREFIX = "TRANSPORT_PUBLIC_IDENTITY_SHA256="

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
    _GetFileAttributesW = _kernel32.GetFileAttributesW
    _GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _GetFileAttributesW.restype = wintypes.DWORD

    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


class TransportIdentityError(ValueError):
    pass


def transport_public_identity_sha256(key_type: str, key_data: str) -> str:
    if key_type != "ssh-ed25519":
        raise TransportIdentityError("GATE_A1_TRANSPORT_KEY_TYPE_INVALID")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", key_data) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_KEY_DATA_INVALID")
    return hashlib.sha256(f"{key_type} {key_data}".encode("ascii")).hexdigest()


def digest_from_ssh_keygen_y(stdout: str) -> str:
    line = stdout.strip().splitlines()[0] if stdout.strip() else ""
    match = re.fullmatch(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,3})(?: [^\r\n]*)?", line)
    if match is None:
        raise TransportIdentityError("GATE_A1_SSH_KEYGEN_Y_OUTPUT_INVALID")
    key_type, key_data = "ssh-ed25519", match.group(1)
    return transport_public_identity_sha256(key_type, key_data)


def build_record(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_SHA256_INVALID")
    return "\n".join(
        (
            RECORD_SCHEMA,
            PROVENANCE_LINE,
            DIGEST_LINE_PREFIX + digest,
            "",
        )
    )


def parse_record(text: str) -> str:
    lines = text.splitlines()
    if len(lines) != 3:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_INVALID")
    if lines[0] != RECORD_SCHEMA:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_SCHEMA_INVALID")
    if lines[1] != PROVENANCE_LINE:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_PROVENANCE_INVALID")
    if not lines[2].startswith(DIGEST_LINE_PREFIX):
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_INVALID")
    digest = lines[2][len(DIGEST_LINE_PREFIX) :]
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_SHA256_INVALID")
    return digest


def _assert_windows_normal_file(path: Path) -> None:
    if sys.platform != "win32":
        return
    attrs = _GetFileAttributesW(str(path))
    if attrs == _INVALID_FILE_ATTRIBUTES:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_INVALID")
    if attrs & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_REPARSE")


def _validate_protected_private_key_path(private_key_path: Path) -> Path:
    if sys.platform != "win32":
        raise TransportIdentityError("GATE_A1_WINDOWS_REQUIRED")
    try:
        resolved = private_key_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_INVALID") from exc
    if not resolved.is_file():
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_INVALID")
    _assert_windows_normal_file(resolved)
    return resolved


def resolve_trusted_ssh_keygen_path() -> Path:
    if sys.platform != "win32":
        raise TransportIdentityError("GATE_A1_WINDOWS_REQUIRED")
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidate = Path(windir) / "System32" / "OpenSSH" / "ssh-keygen.exe"
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise TransportIdentityError("GATE_A1_SSH_KEYGEN_TRUSTED_PATH_MISSING") from exc
    if not resolved.is_file():
        raise TransportIdentityError("GATE_A1_SSH_KEYGEN_TRUSTED_PATH_MISSING")
    _assert_windows_normal_file(resolved)
    return resolved


def _open_private_key_for_bound_read(key_path: Path) -> int:
    handle = _CreateFileW(
        str(key_path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle is None or int(handle) == -1:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_BIND_FAILED")
    return int(handle)


def derive_bound_transport_public_identity(private_key_path: Path) -> str:
    """Derive transport public identity from the protected private key (Windows only)."""
    key_path = _validate_protected_private_key_path(private_key_path)
    ssh_keygen = resolve_trusted_ssh_keygen_path()
    handle = _open_private_key_for_bound_read(key_path)
    try:
        proc = subprocess.run(
            [str(ssh_keygen), "-y", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        _CloseHandle(handle)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_DERIVATION_FAILED")
    return digest_from_ssh_keygen_y(proc.stdout)


def write_bound_record(private_key_path: Path, output: Path) -> None:
    digest = derive_bound_transport_public_identity(private_key_path)
    output.write_text(build_record(digest), encoding="utf-8")


def verify_bound_record(private_key_path: Path, record_path: Path) -> str:
    bound = derive_bound_transport_public_identity(private_key_path)
    record_digest = parse_record(record_path.read_text(encoding="utf-8"))
    if record_digest != bound:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_MISMATCH")
    return bound


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate A1 transport public identity helper")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "derive-from-ssh-keygen-y",
        help="Test-only: read ssh-keygen -y line on stdin; print digest only",
    )
    derive_bound = sub.add_parser("derive-bound")
    derive_bound.add_argument("--private-key", type=Path, required=True)
    write_bound = sub.add_parser("write-bound-record")
    write_bound.add_argument("--private-key", type=Path, required=True)
    write_bound.add_argument("--output", type=Path, required=True)
    verify_bound = sub.add_parser("verify-bound-record")
    verify_bound.add_argument("--private-key", type=Path, required=True)
    verify_bound.add_argument("record", type=Path)
    verify = sub.add_parser("verify-record")
    verify.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "derive-from-ssh-keygen-y":
            digest = digest_from_ssh_keygen_y(sys.stdin.read())
            print(digest)
            return 0
        if args.command == "derive-bound":
            print(derive_bound_transport_public_identity(args.private_key))
            return 0
        if args.command == "write-bound-record":
            write_bound_record(args.private_key, args.output)
            return 0
        if args.command == "verify-bound-record":
            digest = verify_bound_record(args.private_key, args.record)
            print("GATE_A1_TRANSPORT_IDENTITY_VERIFY=PASS")
            print(DIGEST_LINE_PREFIX + digest)
            print("TRANSPORT_KEY_PROVENANCE=" + PROVENANCE)
            return 0
        digest = parse_record(args.record.read_text(encoding="utf-8"))
        print("GATE_A1_TRANSPORT_IDENTITY_VERIFY=PASS")
        print(DIGEST_LINE_PREFIX + digest)
        print("TRANSPORT_KEY_PROVENANCE=" + PROVENANCE)
        return 0
    except TransportIdentityError as exc:
        print("GATE_A1_TRANSPORT_IDENTITY=HOLD", file=sys.stderr)
        print("CLASSIFICATION=" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
