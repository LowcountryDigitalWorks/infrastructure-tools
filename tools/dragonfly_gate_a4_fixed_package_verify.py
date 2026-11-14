"""Real descriptor-bound REDRIX A4 package-byte observer; NO trust admission.

This is reusable file-reading code for a FUTURE independently accepted Linux
protected launcher. It never installs, executes, imports, forks, sudoes,
opens a network socket, changes a process capability, or authorizes A4/JIT.
The current Crostini owner UID has unrestricted sudo and therefore cannot
establish an independent root trust boundary by calling this function.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
import sys

MARKER = "LDW_REDRIX_A4_FIXED_PACKAGE_BYTES_V1"
PROTECTED_INSTALL_ENABLED = False
PHYSICAL_EXECUTION_ENABLED = False
FIXED_PACKAGE_PARTS = ("usr", "libexec", "ldw-redrix-a4")
FIXED_INSPECTOR_FILE = "dragonfly_gate_a4_live_evidence.py"
PINNED_INSPECTOR_GIT_BLOB = "a939c5204f3164a6e21dc8c6998260332d1ffd24"
PINNED_INSPECTOR_SHA256 = "da0f4ea038cc623424bdff16b0971b15ddbc0babc541b7094c0c1d1a6030cdcc"
PINNED_INSPECTOR_SIZE = 8107
MAX_INSPECTOR_BYTES = 32768
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
# O_NONBLOCK makes FIFO/special leaf candidates fail the regular-file check
# without hanging at open() before fstat(). It has no effect on regular files.
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class _Hold(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _report(code: str, matched: bool = False) -> dict[str, object]:
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED" if matched else "HOLD",
        "reasonCode": "INDEPENDENT_ROOT_ISSUER_AND_CHANNEL_NOT_INSTALLED" if matched else code,
        "fixedPackageBytesObserved": matched,
        "protectedInstallAuthorized": False,
        "physicalExecutionAuthorized": False,
        "privilegedChannelAuthenticated": False,
        "a4Pass": False,
        "runtimeAuthority": False,
        "jitAdmissionAuthorized": False,
        "hostMutationPerformed": False,
    }


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _check_directory(info: os.stat_result, owner_uid: int, owner_gid: int) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise _Hold("PACKAGE_NOT_DIRECTORY")
    if info.st_uid != owner_uid or info.st_gid != owner_gid:
        raise _Hold("PACKAGE_OWNER_UNTRUSTED")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise _Hold("PACKAGE_ANCESTOR_WRITABLE")


def _check_file(info: os.stat_result, owner_uid: int, owner_gid: int) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise _Hold("INSPECTOR_NOT_REGULAR")
    if info.st_uid != owner_uid or info.st_gid != owner_gid:
        raise _Hold("INSPECTOR_OWNER_UNTRUSTED")
    if info.st_nlink != 1:
        raise _Hold("INSPECTOR_HARDLINK_REFUSED")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise _Hold("INSPECTOR_WRITABLE_BY_UNTRUSTED")
    if info.st_size != PINNED_INSPECTOR_SIZE or info.st_size > MAX_INSPECTOR_BYTES:
        raise _Hold("INSPECTOR_SIZE_DRIFT")


def _read_pinned(fd: int) -> bytes:
    buf = bytearray()
    while len(buf) <= MAX_INSPECTOR_BYTES:
        part = os.read(fd, min(8192, MAX_INSPECTOR_BYTES + 1 - len(buf)))
        if not part:
            break
        buf.extend(part)
    if len(buf) > MAX_INSPECTOR_BYTES:
        raise _Hold("INSPECTOR_SIZE_DRIFT")
    data = bytes(buf)
    if len(data) != PINNED_INSPECTOR_SIZE:
        raise _Hold("INSPECTOR_SIZE_DRIFT")
    blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    if blob != PINNED_INSPECTOR_GIT_BLOB:
        raise _Hold("INSPECTOR_BLOB_DRIFT")
    if hashlib.sha256(data).hexdigest() != PINNED_INSPECTOR_SHA256:
        raise _Hold("INSPECTOR_DIGEST_DRIFT")
    return data


def _observe_tree(root: Path, owner_uid: int, owner_gid: int) -> dict[str, object]:
    """Non-authorizing descriptor-bound real filesystem read.

    Passing a synthetic root/owner is only for hostile in-memory/source
    fixture tests; it can never attest real privilege or authorize anything.
    The production entrypoint below fixes root to / and UID/GID to 0.
    """
    if sys.platform != "linux" or not isinstance(root, Path) or type(owner_uid) is not int or type(owner_gid) is not int:
        return _report("PLATFORM_OR_SOURCE_SHAPE_REFUSED")
    try:
        with ExitStack() as stack:
            root_fd = os.open(root, _DIR_FLAGS)
            stack.callback(os.close, root_fd)
            root_info = os.fstat(root_fd)
            _check_directory(root_info, owner_uid, owner_gid)
            dirs: list[tuple[int | None, str | None, int, tuple[int, ...]]] = [
                (None, None, root_fd, _identity(root_info))
            ]
            parent_fd = root_fd
            for segment in FIXED_PACKAGE_PARTS:
                fd = os.open(segment, _DIR_FLAGS, dir_fd=parent_fd)
                stack.callback(os.close, fd)
                current = os.fstat(fd)
                _check_directory(current, owner_uid, owner_gid)
                link = os.stat(segment, dir_fd=parent_fd, follow_symlinks=False)
                if _identity(link) != _identity(current):
                    raise _Hold("PACKAGE_DIRECTORY_REPLACED")
                dirs.append((parent_fd, segment, fd, _identity(current)))
                parent_fd = fd

            inspector_fd = os.open(FIXED_INSPECTOR_FILE, _FILE_FLAGS, dir_fd=parent_fd)
            stack.callback(os.close, inspector_fd)
            before = os.fstat(inspector_fd)
            _check_file(before, owner_uid, owner_gid)
            named = os.stat(FIXED_INSPECTOR_FILE, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(named) != _identity(before):
                raise _Hold("INSPECTOR_PATH_REPLACED")
            _read_pinned(inspector_fd)
            after = os.fstat(inspector_fd)
            if _identity(after) != _identity(before):
                raise _Hold("INSPECTOR_DESCRIPTOR_CHANGED")
            named_after = os.stat(FIXED_INSPECTOR_FILE, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(named_after) != _identity(before):
                raise _Hold("INSPECTOR_PATH_REPLACED")

            for parent, name, fd, frozen in reversed(dirs):
                if _identity(os.fstat(fd)) != frozen:
                    raise _Hold("PACKAGE_DIRECTORY_CHANGED")
                if parent is not None and name is not None:
                    named_dir = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if _identity(named_dir) != frozen:
                        raise _Hold("PACKAGE_DIRECTORY_REPLACED")
            return _report("", matched=True)
    except _Hold as exc:
        return _report(exc.reason)
    except (OSError, ValueError, OverflowError, TypeError):
        return _report("PACKAGE_READ_UNAVAILABLE")


def observe_fixed_package() -> dict[str, object]:
    """Only production path: read fixed root path, never execute or trust it."""
    return _observe_tree(Path("/"), 0, 0)
