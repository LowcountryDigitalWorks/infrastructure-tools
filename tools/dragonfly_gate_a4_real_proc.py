"""Fixed read-only Linux /proc ProcPort adapter for REDRIX A4 FD inspector core (#139).

DATA-ONLY / NON-AUTHORIZING: no CLI, subprocess, sudo, network, shell, or filesystem writes.
Does not establish runtime A4 PASS, trusted privileged producer identity, or full kernel
atomic coverage. Production binding uses the fixed host path ``/proc`` only.
"""
from __future__ import annotations

import errno
import os
import platform
import re
import importlib.util
from pathlib import Path
from typing import Union

_CORE_PATH = Path(__file__).resolve().parent / "dragonfly_gate_a4_fd_inspector_core.py"
_CORE_SPEC = importlib.util.spec_from_file_location(
    "dragonfly_gate_a4_fd_inspector_core", _CORE_PATH
)
assert _CORE_SPEC and _CORE_SPEC.loader
import sys

_CORE = importlib.util.module_from_spec(_CORE_SPEC)
sys.modules[_CORE_SPEC.name] = _CORE
_CORE_SPEC.loader.exec_module(_CORE)
ProcAccessDenied = _CORE.ProcAccessDenied

_LIVE_PROC_ROOT = Path("/proc")
_NUMERIC_PID = re.compile(r"^[1-9][0-9]*$")
_NUMERIC_FD = re.compile(r"^[0-9]+$")


def _validate_pid(pid: int) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int):
        raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
    if pid <= 0:
        raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
    return pid


def _proc_path(proc_root: Path, pid: int, *parts: str) -> Path:
    _validate_pid(pid)
    base = proc_root / str(pid)
    if not base.name == str(pid):
        raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
    resolved = base.resolve(strict=False)
    try:
        resolved.relative_to(proc_root.resolve(strict=False))
    except ValueError as exc:
        raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE") from exc
    path = base.joinpath(*parts)
    path_resolved = path.resolve(strict=False)
    try:
        path_resolved.relative_to(proc_root.resolve(strict=False))
    except ValueError as exc:
        raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE") from exc
    return path


def _map_os_error(exc: OSError, *, fd_context: bool = False) -> ProcAccessDenied:
    if exc.errno == errno.ENOENT:
        return ProcAccessDenied("A4_FD_PROCESS_VANISHED" if fd_context else "A4_FD_STAT_UNAVAILABLE")
    if exc.errno in (errno.EACCES, errno.EPERM):
        return ProcAccessDenied("A4_FD_DENIED_FD" if fd_context else "A4_FD_STAT_UNAVAILABLE")
    return ProcAccessDenied("A4_FD_INCOMPLETE_ENUMERATION")


class LinuxProcPort:
    """Read-only ProcPort over a closed proc filesystem root."""

    __slots__ = ("_proc_root",)

    def __init__(self, proc_root: Path) -> None:
        self._proc_root = proc_root

    def list_numeric_pids(self) -> list[int]:
        try:
            names = os.listdir(self._proc_root)
        except OSError as exc:
            raise _map_os_error(exc) from exc
        pids: list[int] = []
        seen: set[int] = set()
        for name in names:
            if not _NUMERIC_PID.fullmatch(name):
                continue
            pid = int(name)
            if pid in seen:
                raise ProcAccessDenied("A4_FD_INCOMPLETE_ENUMERATION")
            seen.add(pid)
            pids.append(pid)
        pids.sort()
        return pids

    def read_stat_line(self, pid: int) -> str:
        path = _proc_path(self._proc_root, pid, "stat")
        try:
            data = path.read_text(encoding="utf-8", errors="strict")
        except OSError as exc:
            raise _map_os_error(exc) from exc
        line = data.splitlines()[0] if data else ""
        if not line.strip():
            raise ProcAccessDenied("A4_FD_MALFORMED_STAT")
        return line

    def read_status_text(self, pid: int) -> str:
        path = _proc_path(self._proc_root, pid, "status")
        try:
            return path.read_text(encoding="utf-8", errors="strict")
        except OSError as exc:
            raise _map_os_error(exc) from exc

    def list_fd_targets(self, pid: int) -> list[str]:
        fd_dir = _proc_path(self._proc_root, pid, "fd")
        try:
            entries = os.listdir(fd_dir)
        except OSError as exc:
            raise _map_os_error(exc, fd_context=True) from exc
        numeric = sorted(
            (name for name in entries if _NUMERIC_FD.fullmatch(name)),
            key=lambda item: int(item),
        )
        if not numeric and entries:
            raise ProcAccessDenied("A4_FD_INCOMPLETE_ENUMERATION")
        targets: list[str] = []
        for name in numeric:
            link_path = fd_dir / name
            try:
                target = os.readlink(link_path)
            except OSError as exc:
                raise _map_os_error(exc, fd_context=True) from exc
            if not target or ".." in target or "\x00" in target:
                raise ProcAccessDenied("A4_FD_SYMLINK_AMBIGUOUS")
            if "/fd/" in target and str(pid) in target:
                raise ProcAccessDenied("A4_FD_SYMLINK_AMBIGUOUS")
            targets.append(target)
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
    root = Path(proc_root).resolve()
    if root == _LIVE_PROC_ROOT.resolve():
        raise ValueError("test proc root must not be live /proc")
    if not root.is_dir():
        raise ValueError("test proc root must be an existing directory")
    return LinuxProcPort(root)
