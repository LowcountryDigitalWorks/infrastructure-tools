"""Read-only self privilege and namespace sample for REDRIX A4 (#139).

DATA-ONLY / NON-AUTHORIZING. Production reads only ``/proc/self/status``, ``/proc/self/ns/user``, and
``/proc/self/ns/pid``.
There is no CLI, no selected proc root, and no command input.

A successful sample reports this process's effective UID and whether
CAP_SYS_PTRACE (bit 19) and CAP_DAC_READ_SEARCH (bit 2) are set in CapEff.
Namespace links contribute local user and pid namespace ids. Those readings
do not prove PTRACE_MODE_READ_FSCREDS against any other process, dumpability,
an LSM allow, complete file-descriptor coverage, immutable package identity,
an operator channel, or an A4 pass. ``read_scope_complete`` stays false.
The observed namespace is not a confirmed target namespace.

``kernel_measured`` means those fixed fields parsed. It does not authenticate
the caller or a protected launcher.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import importlib.util
import os
from pathlib import Path
import re
import sys
from typing import Optional, Union

MARKER = "DRAGONFLY_GATE_A4_SELF_PRIVILEGE_V1"
_STATUS_PATH = "/proc/self/status"
_USER_NS_PATH = "/proc/self/ns/user"
_PID_NS_PATH = "/proc/self/ns/pid"
_CAP_DAC_READ_SEARCH = 2
_CAP_SYS_PTRACE = 19
_UID_MAX = 2**32 - 1
_NS_MAX = 2**64 - 1
_CAP_TEXT = re.compile(r"^[0-9a-fA-F]{1,16}$")
_USER_NS = re.compile(r"^user:\[([0-9]+)\]$")
_PID_NS = re.compile(r"^pid:\[([0-9]+)\]$")
_REASON = re.compile(r"A4_PV_[A-Z0-9_]+")
_TARGET_USER = "target-unconfirmed"
_TARGET_PID = "target-unconfirmed"
_CORRELATION = "self-status"
_NONCE = "self-sample"


class _MeasureError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TestSample:
    """One fixed test sample. This is not a filesystem path."""

    status: str
    user_ns: str
    pid_ns: str
    status_errno: Optional[int] = None
    user_errno: Optional[int] = None
    pid_errno: Optional[int] = None


class TestSelfScript:
    """TEST ONLY scripted samples. Production never accepts this as a path."""

    def __init__(self, samples: tuple[TestSample, ...]):
        if type(samples) is not tuple or not samples or any(type(item) is not TestSample for item in samples):
            raise ValueError("test samples required")
        self._samples = samples
        self._index = 0

    def take(self) -> TestSample:
        sample = self._samples[self._index]
        if self._index < len(self._samples) - 1:
            self._index += 1
        return sample


class _ProductionSelfReader:
    """Fixed self paths only."""

    def read_status(self) -> str:
        return Path(_STATUS_PATH).read_text(encoding="utf-8")

    def read_user_ns(self) -> str:
        return os.readlink(_USER_NS_PATH)

    def read_pid_ns(self) -> str:
        return os.readlink(_PID_NS_PATH)


def _hold(reason: str, **fields: object) -> dict[str, object]:
    if not _REASON.fullmatch(reason):
        reason = "A4_PV_MALFORMED_STATUS"
    body: dict[str, object] = {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reasonCode": reason,
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "kernelMeasured": False,
        "readScopeComplete": False,
    }
    body.update(fields)
    return body


def _lines(text: str, name: str) -> list[str]:
    found = []
    prefix = name + ":"
    for raw in text.splitlines():
        if raw.startswith(prefix):
            found.append(raw[len(prefix) :].strip())
    return found


def _one(text: str, name: str, missing: str) -> str:
    found = _lines(text, name)
    if len(found) != 1 or not found[0]:
        raise _MeasureError(missing)
    return found[0]


def _parse_cap(text: str, name: str) -> int:
    raw = _one(text, name, "A4_PV_MALFORMED_CAP")
    if _CAP_TEXT.fullmatch(raw) is None:
        raise _MeasureError("A4_PV_MALFORMED_CAP")
    return int(raw, 16)


def _parse_euid(text: str) -> int:
    found = _lines(text, "Uid")
    if len(found) != 1:
        raise _MeasureError("A4_PV_UID_MISMATCH" if len(found) > 1 else "A4_PV_MALFORMED_UID")
    parts = found[0].split()
    if len(parts) != 4:
        raise _MeasureError("A4_PV_MALFORMED_UID")
    values = []
    for part in parts:
        if not part.isascii() or not part.isdigit():
            raise _MeasureError("A4_PV_MALFORMED_UID")
        number = int(part)
        if number > _UID_MAX:
            raise _MeasureError("A4_PV_MALFORMED_UID")
        values.append(number)
    return values[1]


def _parse_ns(link: str, kind: str) -> str:
    pattern = _USER_NS if kind == "user" else _PID_NS
    match = pattern.fullmatch(link.strip())
    if match is None:
        raise _MeasureError("A4_PV_NAMESPACE_AMBIGUOUS")
    inode_text = match.group(1)
    if len(inode_text) > 1 and inode_text.startswith("0"):
        raise _MeasureError("A4_PV_NAMESPACE_AMBIGUOUS")
    inode = int(inode_text)
    if inode > _NS_MAX:
        raise _MeasureError("A4_PV_NAMESPACE_AMBIGUOUS")
    token = f"{kind}-{inode}"
    if len(token) > 128:
        raise _MeasureError("A4_PV_NAMESPACE_AMBIGUOUS")
    return token


def _accepted_snapshot_type():
    path = Path(__file__).resolve().with_name("dragonfly_gate_a4_fd_preflight.py")
    name = "_ldw_a4_self_privilege_preflight"
    module = sys.modules.get(name)
    file = getattr(module, "__file__", None) if module is not None else None
    if module is None or not isinstance(file, str) or Path(file).resolve() != path:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise _MeasureError("A4_PV_MALFORMED_STATUS")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    snapshot = getattr(module, "PrivilegeSnapshot", None)
    if snapshot is None:
        raise _MeasureError("A4_PV_MALFORMED_STATUS")
    return snapshot


class LinuxSelfPrivilegePort:
    """PrivilegePort over a fixed self reader or an explicit test script."""

    def __init__(self, reader: Union[_ProductionSelfReader, TestSelfScript]):
        if type(reader) is not _ProductionSelfReader and type(reader) is not TestSelfScript:
            raise TypeError("privilege reader refused")
        self._reader = reader

    def _measure_once(self):
        try:
            if type(self._reader) is TestSelfScript:
                sample = self._reader.take()
                if sample.status_errno is not None:
                    raise OSError(sample.status_errno, "test status unreadable")
                if sample.user_errno is not None:
                    raise OSError(sample.user_errno, "test user namespace unreadable")
                if sample.pid_errno is not None:
                    raise OSError(sample.pid_errno, "test pid namespace unreadable")
                status = sample.status
                user_ns = sample.user_ns
                pid_ns = sample.pid_ns
            else:
                status = self._reader.read_status()
                user_ns = self._reader.read_user_ns()
                pid_ns = self._reader.read_pid_ns()
        except OSError:
            raise
        if type(status) is not str or type(user_ns) is not str or type(pid_ns) is not str:
            raise _MeasureError("A4_PV_MALFORMED_STATUS")
        cap_eff = _parse_cap(status, "CapEff")
        cap_bnd = _parse_cap(status, "CapBnd")
        if cap_eff & ~cap_bnd:
            raise _MeasureError("A4_PV_CAP_INCONSISTENT")
        snapshot_type = _accepted_snapshot_type()
        return snapshot_type(
            kernel_measured=True,
            euid=_parse_euid(status),
            cap_sys_ptrace=bool(cap_eff & (1 << _CAP_SYS_PTRACE)),
            cap_dac_read_search=bool(cap_eff & (1 << _CAP_DAC_READ_SEARCH)),
            user_namespace=_parse_ns(user_ns, "user"),
            pid_namespace=_parse_ns(pid_ns, "pid"),
            target_user_namespace=_TARGET_USER,
            target_pid_namespace=_TARGET_PID,
            read_scope_complete=False,
            correlation=_CORRELATION,
            nonce=_NONCE,
            claims_receiver_authenticated=False,
        )

    def read_privilege(self):
        try:
            measured = self._measure_once()
        except OSError:
            raise
        except _MeasureError as exc:
            raise OSError(errno.EINVAL, exc.reason) from exc
        return measured


def open_self_privilege_port() -> LinuxSelfPrivilegePort:
    """Production port. Reads the fixed self paths and takes no root argument."""
    return LinuxSelfPrivilegePort(_ProductionSelfReader())


def privilege_port_for_tests(script: object) -> LinuxSelfPrivilegePort:
    """TEST ONLY. Refuses path strings and any non-script reader."""
    if type(script) is not TestSelfScript:
        raise TypeError("test script required")
    return LinuxSelfPrivilegePort(script)


def sample_self_privilege(port: LinuxSelfPrivilegePort) -> dict[str, object]:
    """Sample twice. A parsed local view is still not A4 authority."""
    if type(port) is not LinuxSelfPrivilegePort:
        return _hold("A4_PV_MALFORMED_STATUS")
    try:
        first = port._measure_once()
        second = port._measure_once()
    except OSError:
        return _hold("A4_PV_UNREADABLE")
    except _MeasureError as exc:
        return _hold(exc.reason)
    if first != second:
        return _hold("A4_PV_MEASUREMENT_DRIFT")
    return _hold(
        "A4_PV_TARGET_NAMESPACE_UNCONFIRMED",
        kernelMeasured=True,
        readScopeComplete=False,
        euid=first.euid,
        capSysPtrace=first.cap_sys_ptrace,
        capDacReadSearch=first.cap_dac_read_search,
        userNamespace=first.user_namespace,
        pidNamespace=first.pid_namespace,
    )
