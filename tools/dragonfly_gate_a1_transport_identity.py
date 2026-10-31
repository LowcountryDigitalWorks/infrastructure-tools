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
import tempfile
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
    _kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    _kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    _kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL

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


_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_MAX_PRIVATE_KEY_BYTES = 1024 * 1024


def ssh_keygen_path_from_system_directory(system_directory: Path) -> Path:
    """Join the trusted OpenSSH binary under the Windows system directory. PATH is not used."""
    return system_directory / "OpenSSH" / "ssh-keygen.exe"


def _require_windows_64() -> None:
    if sys.platform != "win32":
        raise TransportIdentityError("GATE_A1_WINDOWS_REQUIRED")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise TransportIdentityError("GATE_A1_WINDOWS_64BIT_REQUIRED")


def _system_directory() -> Path:
    _require_windows_64()
    buffer = ctypes.create_unicode_buffer(32768)
    length = _kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise TransportIdentityError("GATE_A1_SSH_KEYGEN_TRUSTED_PATH_MISSING")
    return Path(buffer.value)


def _handle_is_reparse(handle: int) -> bool:
    class _FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _ByHandle(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _FileTime),
            ("ftLastAccessTime", _FileTime),
            ("ftLastWriteTime", _FileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    info = _ByHandle()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_BIND_FAILED")
    return bool(info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _open_nofollow(path: Path, *, directory: bool) -> int:
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = _CreateFileW(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    if handle is None or int(handle) == -1 or int(handle) == int(ctypes.c_void_p(-1).value):
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_BIND_FAILED")
    opened = int(handle)
    if _handle_is_reparse(opened):
        _CloseHandle(opened)
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_REPARSE")
    return opened


def _read_handle(handle: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        buffer = ctypes.create_string_buffer(65536)
        read = wintypes.DWORD(0)
        ok = _kernel32.ReadFile(handle, buffer, 65536, ctypes.byref(read), None)
        if not ok:
            raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_BIND_FAILED")
        if read.value == 0:
            break
        total += int(read.value)
        if total > _MAX_PRIVATE_KEY_BYTES:
            raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_INVALID")
        chunks.append(buffer.raw[: int(read.value)])
    return b"".join(chunks)


def _assert_parent_chain(private_key_path: Path) -> None:
    current = private_key_path.parent
    while True:
        handle = _open_nofollow(current, directory=True)
        _CloseHandle(handle)
        parent = current.parent
        if parent == current:
            break
        current = parent


def read_accepted_private_key_bytes(private_key_path: Path) -> bytes:
    """Read one exact buffer from a no-follow handle. The handle is closed before return."""
    _require_windows_64()
    _assert_parent_chain(private_key_path)
    handle = _open_nofollow(private_key_path, directory=False)
    try:
        return _read_handle(handle)
    finally:
        _CloseHandle(handle)


def resolve_trusted_ssh_keygen_path() -> Path:
    system = _system_directory()
    candidate = ssh_keygen_path_from_system_directory(system)
    handle = _open_nofollow(candidate, directory=False)
    _CloseHandle(handle)
    return candidate


def derive_public_identity_from_accepted_bytes(
    key_bytes: bytes,
    *,
    ssh_keygen: Path,
    temp_dir: Path,
    baseline_sha256: str | None = None,
) -> str:
    """Run ssh-keygen only against an exclusive temp copy of the accepted bytes."""
    if len(key_bytes) > _MAX_PRIVATE_KEY_BYTES:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_INVALID")
    actual = hashlib.sha256(key_bytes).hexdigest()
    if baseline_sha256 is not None and (
        re.fullmatch(r"[0-9a-f]{64}", baseline_sha256) is None or actual != baseline_sha256
    ):
        raise TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED")
    if temp_dir.is_symlink():
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_REPARSE")
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="ldw-gate-a1-key-", dir=temp_dir)
    try:
        os.write(fd, key_bytes)
        os.close(fd)
        fd = -1
        os.chmod(name, 0o600)
        proc = subprocess.run(
            [str(ssh_keygen), "-y", "-P", "", "-f", name],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_DERIVATION_FAILED")
        try:
            text = proc.stdout.decode("ascii")
        except UnicodeDecodeError as exc:
            raise TransportIdentityError("GATE_A1_SSH_KEYGEN_Y_OUTPUT_INVALID") from exc
        return digest_from_ssh_keygen_y(text)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(name)
        except OSError:
            pass


def derive_bound_transport_public_identity(
    private_key_path: Path,
    *,
    baseline_sha256: str | None = None,
    ssh_keygen: Path | None = None,
    accepted_bytes: bytes | None = None,
    temp_dir: Path | None = None,
) -> str:
    """Production path reads one no-follow snapshot, then derives from that copy."""
    if accepted_bytes is None:
        if sys.platform != "win32":
            raise TransportIdentityError("GATE_A1_WINDOWS_REQUIRED")
        key_bytes = read_accepted_private_key_bytes(private_key_path)
        keygen = ssh_keygen or resolve_trusted_ssh_keygen_path()
    else:
        key_bytes = accepted_bytes
        if ssh_keygen is None:
            raise TransportIdentityError("GATE_A1_SSH_KEYGEN_TRUSTED_PATH_MISSING")
        keygen = ssh_keygen
    directory = temp_dir or Path(tempfile.mkdtemp(prefix="ldw-gate-a1-"))
    created_temp = temp_dir is None
    try:
        return derive_public_identity_from_accepted_bytes(
            key_bytes,
            ssh_keygen=keygen,
            temp_dir=directory,
            baseline_sha256=baseline_sha256,
        )
    finally:
        if created_temp:
            try:
                directory.rmdir()
            except OSError:
                pass


def write_bound_record(
    private_key_path: Path,
    output: Path,
    *,
    baseline_sha256: str | None = None,
) -> None:
    digest = derive_bound_transport_public_identity(
        private_key_path,
        baseline_sha256=baseline_sha256,
    )
    output.write_text(build_record(digest), encoding="utf-8")


def verify_bound_record(
    private_key_path: Path,
    record_path: Path,
    *,
    baseline_sha256: str | None = None,
) -> str:
    bound = derive_bound_transport_public_identity(
        private_key_path,
        baseline_sha256=baseline_sha256,
    )
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
    derive_bound.add_argument("--baseline-sha256", required=False)
    write_bound = sub.add_parser("write-bound-record")
    write_bound.add_argument("--private-key", type=Path, required=True)
    write_bound.add_argument("--output", type=Path, required=True)
    write_bound.add_argument("--baseline-sha256", required=False)
    verify_bound = sub.add_parser("verify-bound-record")
    verify_bound.add_argument("--private-key", type=Path, required=True)
    verify_bound.add_argument("--baseline-sha256", required=False)
    verify_bound.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "derive-from-ssh-keygen-y":
            digest = digest_from_ssh_keygen_y(sys.stdin.read())
            print(digest)
            return 0
        if args.command == "derive-bound":
            print(derive_bound_transport_public_identity(
                args.private_key,
                baseline_sha256=args.baseline_sha256,
            ))
            return 0
        if args.command == "write-bound-record":
            write_bound_record(
                args.private_key,
                args.output,
                baseline_sha256=args.baseline_sha256,
            )
            return 0
        digest = verify_bound_record(
            args.private_key,
            args.record,
            baseline_sha256=args.baseline_sha256,
        )
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
