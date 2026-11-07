"""Fixed read-only Linux /proc ProcPort adapter for REDRIX A4 FD inspector core (#139).

DATA-ONLY / NON-AUTHORIZING: no CLI, subprocess, sudo, network, shell, or filesystem writes.
Does not establish runtime A4 PASS, trusted privileged producer identity, or full kernel
atomic coverage. Production binding uses the fixed host path ``/proc`` only.

Raises ``OSError`` with normalized errno values so the accepted inspector core can map
failures without cross-module exception identity issues.
"""
from __future__ import annotations

import errno
import os
import platform
import re
from pathlib import Path
from typing import Union

_LIVE_PROC_ROOT = Path("/proc")
_NUMERIC_PID = re.compile(r"^[1-9][0-9]*$")
_NUMERIC_FD = re.compile(r"^[0-9]+$")


def _validate_pid(pid: int) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise OSError(errno.EINVAL, "invalid pid")
    if pid <= 0:
        raise OSError(errno.EINVAL, "invalid pid")
    return pid


def _resolved_under(root: Path, path: Path) -> Path:
    try:
        resolved_root = root.resolve(strict=False)
        resolved_path = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OSError(errno.ELOOP, "proc path resolution failed") from exc
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise OSError(errno.EINVAL, "proc path escapes root") from exc
    return path


def _proc_path(proc_root: Path, pid: int, *parts: str) -> Path:
    _validate_pid(pid)
    base = proc_root / str(pid)
    if base.name != str(pid):
        raise OSError(errno.EINVAL, "invalid pid path")
    _resolved_under(proc_root, base)
    path = base.joinpath(*parts)
    if any(part in {".", ".."} for part in path.parts):
        raise OSError(errno.EINVAL, "invalid proc path segment")
    _resolved_under(proc_root, path)
    return path


def _read_text_strict(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OSError(errno.EINVAL, "malformed proc text") from exc
    except OSError:
        raise


class LinuxProcPort:
    """Read-only ProcPort over a closed proc filesystem root."""

    __slots__ = ("_proc_root",)

    def __init__(self, proc_root: Path) -> None:
        self._proc_root = proc_root

    def list_numeric_pids(self) -> list[int]:
        try:
            names = os.listdir(self._proc_root)
        except OSError:
            raise
        pids: list[int] = []
        seen: set[int] = set()
        for name in names:
            if not _NUMERIC_PID.fullmatch(name):
                continue
            pid = int(name)
            if pid in seen:
                raise OSError(errno.ENOTEMPTY, "duplicate pid directory")
            seen.add(pid)
            pids.append(pid)
        pids.sort()
        return pids

    def read_stat_line(self, pid: int) -> str:
        path = _proc_path(self._proc_root, pid, "stat")
        data = _read_text_strict(path)
        line = data.splitlines()[0] if data else ""
        if not line.strip():
            raise OSError(errno.EINVAL, "empty proc stat")
        return line

    def read_status_text(self, pid: int) -> str:
        path = _proc_path(self._proc_root, pid, "status")
        return _read_text_strict(path)

    def list_fd_targets(self, pid: int) -> list[str]:
        fd_dir = _proc_path(self._proc_root, pid, "fd")
        try:
            entries = os.listdir(fd_dir)
        except OSError:
            raise
        targets: list[str] = []
        for name in entries:
            if name in {".", ".."}:
                continue
            if not _NUMERIC_FD.fullmatch(name):
                raise OSError(errno.ENOTDIR, "non-numeric fd entry")
            link_path = fd_dir / name
            try:
                target = os.readlink(link_path)
            except OSError:
                raise
            if not target or ".." in target or "\x00" in target:
                raise OSError(errno.ELOOP, "ambiguous fd symlink")
            if "/fd/" in target and str(pid) in target:
                raise OSError(errno.ELOOP, "ambiguous fd symlink")
            targets.append(target)
        targets.sort(key=lambda item: (len(item), item))
        return targets


def open_linux_proc_port() -> LinuxProcPort:
    """Return a ProcPort bound to the live host ``/proc`` (Linux only)."""
    if platform.system() != "Linux":
        raise OSError(errno.ENOTSUP, "linux proc port requires Linux")
    root = _LIVE_PROC_ROOT
    if not root.is_dir():
        raise OSError(errno.ENOENT, "live /proc not available")
    return LinuxProcPort(root)


def proc_port_for_tests(proc_root: Union[str, os.PathLike[str]]) -> LinuxProcPort:
    """TEST ONLY — not runtime authority. Never targets live ``/proc``."""
    try:
        root = Path(proc_root).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("invalid test proc root") from exc
    if root == _LIVE_PROC_ROOT.resolve(strict=False):
        raise ValueError("test proc root must not be live /proc")
    if not root.is_dir():
        raise ValueError("test proc root must be an existing directory")
    return LinuxProcPort(root)
