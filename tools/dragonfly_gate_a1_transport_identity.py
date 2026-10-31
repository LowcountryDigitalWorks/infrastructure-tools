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
import secrets
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
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _SetFilePointerEx = _kernel32.SetFilePointerEx
    _SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LARGE_INTEGER,
        ctypes.POINTER(wintypes.LARGE_INTEGER),
        wintypes.DWORD,
    ]
    _SetFilePointerEx.restype = wintypes.BOOL
    _SetEndOfFile = _kernel32.SetEndOfFile
    _SetEndOfFile.argtypes = [wintypes.HANDLE]
    _SetEndOfFile.restype = wintypes.BOOL
    _FlushFileBuffers = _kernel32.FlushFileBuffers
    _FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _FlushFileBuffers.restype = wintypes.BOOL
    _SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _SetFileInformationByHandle.restype = wintypes.BOOL

    class _FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _FileInfoByHandle(ctypes.Structure):
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

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BYTE)]

    _FILE_DISPOSITION_INFO = 4
    _FILE_BEGIN = 0
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _DELETE = 0x00010000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _CREATE_NEW = 1
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


def _invalid_handle(handle: int) -> bool:
    return handle is None or handle == -1 or handle == int(ctypes.c_void_p(-1).value)


def _write_file_handle(handle: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 65536]
        written = wintypes.DWORD(0)
        ok = _kernel32.WriteFile(
            handle,
            chunk,
            len(chunk),
            ctypes.byref(written),
            None,
        )
        if not ok or written.value == 0:
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_BIND_FAILED")
        offset += int(written.value)


def _file_info_by_handle(handle: int) -> _FileInfoByHandle:
    _require_windows_64()
    info = _FileInfoByHandle()
    if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
    return info


def _bound_file_identity(handle: int) -> tuple[int, int, int]:
    info = _file_info_by_handle(handle)
    return (
        int(info.dwVolumeSerialNumber),
        int(info.nFileIndexHigh),
        int(info.nFileIndexLow),
    )


def _file_size_from_handle(handle: int) -> int:
    info = _file_info_by_handle(handle)
    return (int(info.nFileSizeHigh) << 32) + int(info.nFileSizeLow)


def _set_file_pointer(handle: int, offset: int) -> None:
    _require_windows_64()
    distance = wintypes.LARGE_INTEGER(offset)
    if not _SetFilePointerEx(handle, distance, None, _FILE_BEGIN):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")


def _verify_handle_region_is_zero(handle: int, size: int) -> None:
    if size == 0:
        return
    _set_file_pointer(handle, 0)
    remaining = size
    while remaining > 0:
        chunk = min(remaining, 65536)
        buffer = ctypes.create_string_buffer(chunk)
        read = wintypes.DWORD(0)
        ok = _kernel32.ReadFile(handle, buffer, chunk, ctypes.byref(read), None)
        if not ok:
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
        if int(read.value) == 0:
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
        if buffer.raw[: int(read.value)] != b"\0" * int(read.value):
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
        remaining -= int(read.value)


def _mark_handle_delete_on_close(handle: int) -> None:
    _require_windows_64()
    info = _FileDispositionInfo(DeleteFile=1)
    if not _SetFileInformationByHandle(
        handle,
        _FILE_DISPOSITION_INFO,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")


def _open_nofollow_for_verified_delete(path: Path) -> int:
    _require_windows_64()
    handle = _CreateFileW(
        str(path),
        _GENERIC_READ | _DELETE,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle is None or int(handle) == -1 or int(handle) == int(ctypes.c_void_p(-1).value):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
    opened = int(handle)
    if _handle_is_reparse(opened):
        _CloseHandle(opened)
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_REPARSE")
    return opened


def _delete_temp_key_path_if_same_object(
    path: Path,
    expected_identity: tuple[int, int, int],
) -> None:
    """Delete via handle only when no-follow reopen matches the zeroed temp object identity."""
    _require_windows_64()
    if not path.exists():
        return
    handle = _open_nofollow_for_verified_delete(path)
    try:
        if _bound_file_identity(handle) != expected_identity:
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
        _mark_handle_delete_on_close(handle)
    except TransportIdentityError:
        _CloseHandle(handle)
        raise
    if not _CloseHandle(handle):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
    if path.exists():
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")


def _finalize_bound_temp_key_cleanup(handle: int, path: Path) -> None:
    """Zero on the consumption handle, then verified identity delete (never blind pathname unlink)."""
    _require_windows_64()
    bound_identity = _bound_file_identity(handle)
    try:
        original_size = _file_size_from_handle(handle)
        if original_size:
            _set_file_pointer(handle, 0)
            remaining = original_size
            zero_block = b"\0" * 65536
            while remaining > 0:
                chunk_len = min(remaining, len(zero_block))
                _write_file_handle(handle, zero_block[:chunk_len])
                remaining -= chunk_len
            if remaining != 0:
                raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
            if not _FlushFileBuffers(handle):
                raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
            _verify_handle_region_is_zero(handle, original_size)
    except TransportIdentityError:
        _CloseHandle(handle)
        raise
    if not _CloseHandle(handle):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
    _delete_temp_key_path_if_same_object(path, bound_identity)


def _destroy_bound_temp_key_handle(handle: int, path: Path) -> None:
    _finalize_bound_temp_key_cleanup(handle, path)


def _destroy_posix_temp_key_fd(fd: int) -> None:
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = size
            zero_block = b"\0" * 65536
            while remaining > 0:
                chunk_len = min(remaining, len(zero_block))
                written = os.write(fd, zero_block[:chunk_len])
                if written <= 0:
                    raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
                remaining -= written
            os.ftruncate(fd, 0)
            os.fsync(fd)
    finally:
        os.close(fd)


def _remove_temp_key_pathname(path: Path) -> None:
    """Remove the temp pathname only. Private bytes must already be destroyed on the bound object."""
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED") from exc
    if path.exists():
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")


def _new_exclusive_temp_key_path(temp_dir: Path) -> Path:
    for _ in range(32):
        candidate = temp_dir / f"ldw-gate-a1-key-{secrets.token_hex(16)}"
        if not candidate.exists():
            return candidate
    raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_BIND_FAILED")


def _harden_openssh_private_key_acl(path: Path) -> None:
    """Strip inherited ACL so System32 OpenSSH accepts the bound temp key (share flags unchanged)."""
    _require_windows_64()
    principal = os.environ.get("USERNAME", "").strip()
    if not principal:
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_BIND_FAILED")
    proc = subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{principal}:(F)",
            "/remove",
            "Owner Rights",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_BIND_FAILED")


def _create_bound_temp_key_handle(path: Path, key_bytes: bytes) -> int:
    """Create temp key file and keep a handle open through ssh-keygen (no DELETE/WRITE share)."""
    _require_windows_64()
    handle = _CreateFileW(
        str(path),
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ,
        None,
        _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if _invalid_handle(int(handle)):
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_BIND_FAILED")
    opened = int(handle)
    try:
        _write_file_handle(opened, key_bytes)
        _harden_openssh_private_key_acl(path)
    except TransportIdentityError:
        _CloseHandle(opened)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED") from exc
        raise
    return opened


def _purge_temp_directory(directory: Path) -> None:
    try:
        if any(directory.iterdir()):
            raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED")
        directory.rmdir()
    except OSError as exc:
        raise TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED") from exc


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
    key_path = _new_exclusive_temp_key_path(temp_dir)
    win_handle: int | None = None
    posix_fd = -1
    try:
        if sys.platform == "win32":
            win_handle = _create_bound_temp_key_handle(key_path, key_bytes)
        else:
            posix_fd, name = tempfile.mkstemp(prefix="ldw-gate-a1-key-", dir=temp_dir)
            key_path = Path(name)
            os.write(posix_fd, key_bytes)
        proc = subprocess.run(
            [str(ssh_keygen), "-y", "-P", "", "-f", str(key_path)],
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
        if win_handle is not None:
            _finalize_bound_temp_key_cleanup(win_handle, key_path)
            win_handle = None
        if posix_fd >= 0:
            _destroy_posix_temp_key_fd(posix_fd)
            posix_fd = -1
            _remove_temp_key_pathname(key_path)


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
            _purge_temp_directory(directory)


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
