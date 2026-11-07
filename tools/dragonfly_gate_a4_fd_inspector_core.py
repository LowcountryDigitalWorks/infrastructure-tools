"""Non-authorizing synthetic / injected proc+FD inspection core for REDRIX Gate A4 (#139).

This module is DATA-ONLY. It does not invoke sudo, launch processes, open network
sockets, write disk state, or establish runtime A4 PASS. Continuous Linux /proc
churn can cause conservative HOLD between paired snapshots; future pidfd anchoring
may be required for stronger stability guarantees on live hosts.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Optional, Protocol

MARKER = "DRAGONFLY_GATE_A4_FD_INSPECTOR_CORE_V1"
DEFAULT_UID = 1000
QEMU_NAMES = {"qemu-kvm", "kvm"}
KVM_TARGET = "/dev/kvm"


class FdInspectorError(Exception):
    """Synthetic inspection failure surfaced as HOLD."""


def parse_proc_stat(stat_line: str) -> tuple[int, str, int, int]:
    """Parse /proc/<pid>/stat: pid, comm, uid field (14), starttime (22)."""
    stat_line = stat_line.strip()
    match = re.match(r"^(\d+) \((.*)\) (\S.*)$", stat_line)
    if not match:
        raise FdInspectorError("A4_FD_MALFORMED_STAT")
    pid = int(match.group(1))
    comm = match.group(2)
    tail = match.group(3).split()
    # state, ppid, ... starttime is field 22 overall => index 19 in tail (0-based)
    if len(tail) < 20:
        raise FdInspectorError("A4_FD_MALFORMED_STAT")
    try:
        uid = int(tail[11])
        starttime = int(tail[19])
    except ValueError as exc:
        raise FdInspectorError("A4_FD_MALFORMED_STAT") from exc
    return pid, comm, uid, starttime


def looks_like_qemu_token(token: str) -> bool:
    token = token.strip("'\";()[]{}:,=")
    if not token:
        return False
    name = token.rsplit("/", 1)[-1]
    return name in QEMU_NAMES or name.startswith("qemu-system-")


def process_is_qemu_like(comm: str, exec_tokens: tuple[str, ...]) -> bool:
    if looks_like_qemu_token(comm):
        return True
    return any(looks_like_qemu_token(token) for token in exec_tokens)


class ProcPort(Protocol):
    def list_numeric_pids(self) -> list[int]: ...
    def read_stat_line(self, pid: int) -> str: ...
    def list_fd_targets(self, pid: int) -> list[str]: ...


class ProcAccessDenied(FdInspectorError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProcessFixture:
    pid: int
    uid: int
    starttime: int
    comm: str
    exec_tokens: tuple[str, ...] = ()
    fd_targets: tuple[str, ...] = ()
    stat_available: bool = True
    fd_available: bool = True
    ambiguous_symlink: bool = False
    vanish_after_first: bool = False
    starttime_after_first: Optional[int] = None


@dataclass
class SyntheticProcRoot:
    """In-memory /proc substitute for deterministic tests only."""

    processes: dict[int, ProcessFixture]
    extra_numeric_dirs: tuple[int, ...] = ()
    enumeration_incomplete: bool = False

    def list_numeric_pids(self) -> list[int]:
        if self.enumeration_incomplete:
            return sorted({pid for pid in self.processes if pid % 2 == 0})
        return sorted(set(self.processes) | set(self.extra_numeric_dirs))

    def read_stat_line(self, pid: int) -> str:
        proc = self.processes.get(pid)
        if proc is None:
            raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
        if not proc.stat_available:
            raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
        if proc.vanish_after_first and getattr(self, "_first_pass_done", False):
            raise ProcAccessDenied("A4_FD_PROCESS_VANISHED")
        starttime = proc.starttime
        if proc.starttime_after_first is not None and getattr(self, "_first_pass_done", False):
            starttime = proc.starttime_after_first
        # Build minimal stat tail; uid is field 14, starttime field 22.
        # Fields 4-13 between state and uid, then gid/starttime through field 22.
        tail = ["S", *("0",) * 10, str(proc.uid), str(proc.uid), *("0",) * 6, str(starttime)]
        return f"{proc.pid} ({proc.comm}) " + " ".join(tail)

    def list_fd_targets(self, pid: int) -> list[str]:
        proc = self.processes.get(pid)
        if proc is None:
            raise ProcAccessDenied("A4_FD_DENIED_FD")
        if proc.vanish_after_first and getattr(self, "_first_pass_done", False):
            raise ProcAccessDenied("A4_FD_PROCESS_VANISHED")
        if not proc.fd_available:
            raise ProcAccessDenied("A4_FD_DENIED_FD")
        if proc.ambiguous_symlink:
            raise ProcAccessDenied("A4_FD_SYMLINK_AMBIGUOUS")
        return list(proc.fd_targets)

    def mark_first_pass_complete(self) -> None:
        self._first_pass_done = True


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    starttime: int
    uid: int
    kvm_fd_present: bool
    qemu_like: bool
    fd_enumeration_complete: bool


@dataclass(frozen=True)
class Snapshot:
    observations: tuple[ProcessObservation, ...]
    same_uid_process_count: int
    kvm_fd_process_count: int
    qemu_like_process_count: int


def _observe_process(port: ProcPort, pid: int, expected_uid: int) -> Optional[ProcessObservation]:
    try:
        stat_line = port.read_stat_line(pid)
    except ProcAccessDenied as exc:
        raise FdInspectorError(exc.code) from exc
    parsed_pid, comm, uid, starttime = parse_proc_stat(stat_line)
    if parsed_pid != pid:
        raise FdInspectorError("A4_FD_UID_MISMATCH")
    if uid != expected_uid:
        return None
    try:
        fd_targets = port.list_fd_targets(pid)
    except ProcAccessDenied as exc:
        raise FdInspectorError(exc.code) from exc
    if port.read_stat_line(pid) != stat_line:
        raise FdInspectorError("A4_FD_PROCESS_VANISHED")
    reparsed_pid, _, reparsed_uid, reparsed_start = parse_proc_stat(port.read_stat_line(pid))
    if reparsed_pid != pid or reparsed_uid != uid or reparsed_start != starttime:
        raise FdInspectorError("A4_FD_PID_REUSE")
    kvm_present = any(target == KVM_TARGET for target in fd_targets)
    exec_tokens = ()
    proc = getattr(port, "processes", {}).get(pid)
    if isinstance(proc, ProcessFixture):
        exec_tokens = proc.exec_tokens
    qemu_like = process_is_qemu_like(comm, exec_tokens)
    return ProcessObservation(
        pid=pid,
        starttime=starttime,
        uid=uid,
        kvm_fd_present=kvm_present,
        qemu_like=qemu_like,
        fd_enumeration_complete=True,
    )


def inspect_once(port: ProcPort, *, expected_uid: int = DEFAULT_UID) -> Snapshot:
    observations: list[ProcessObservation] = []
    try:
        pids = port.list_numeric_pids()
    except OSError as exc:
        raise FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION") from exc
    if not pids and getattr(port, "enumeration_incomplete", False):
        raise FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION")
    seen_uid_pids: set[int] = set()
    for pid in pids:
        obs = _observe_process(port, pid, expected_uid)
        if obs is None:
            continue
        seen_uid_pids.add(pid)
        if obs.kvm_fd_present:
            raise FdInspectorError("A4_FD_KVM_FD_PRESENT")
        if obs.qemu_like:
            raise FdInspectorError("A4_FD_QEMU_PROCESS_PRESENT")
        observations.append(obs)
    # Ensure every declared same-UID fixture was enumerated when using SyntheticProcRoot.
    if isinstance(port, SyntheticProcRoot):
        required = {p.pid for p in port.processes.values() if p.uid == expected_uid and p.stat_available}
        if seen_uid_pids != required:
            raise FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION")
    observations.sort(key=lambda item: item.pid)
    return Snapshot(
        observations=tuple(observations),
        same_uid_process_count=len(observations),
        kvm_fd_process_count=0,
        qemu_like_process_count=0,
    )


def _snapshot_key(snapshot: Snapshot) -> tuple:
    return tuple(
        (obs.pid, obs.starttime, obs.uid, obs.kvm_fd_present, obs.qemu_like, obs.fd_enumeration_complete)
        for obs in snapshot.observations
    )


def inspect_stable(
    port: ProcPort,
    *,
    expected_uid: int = DEFAULT_UID,
    bind_a4_readback: bool = True,
) -> dict[str, object]:
    """Return a sanitized, non-authorizing inspection envelope."""
    if not bind_a4_readback:
        return hold("A4_FD_SNAPSHOT_UNSTABLE")
    try:
        first = inspect_once(port, expected_uid=expected_uid)
        if isinstance(port, SyntheticProcRoot):
            port.mark_first_pass_complete()
        second = inspect_once(port, expected_uid=expected_uid)
    except FdInspectorError as exc:
        return hold(str(exc))
    if _snapshot_key(first) != _snapshot_key(second):
        return hold("A4_FD_PID_REUSE")
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED",
        "reasonCode": "EXTERNAL_TRUST_GATES_REQUIRED",
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "expectedUid": expected_uid,
        "stabilityPasses": 2,
        "sameUidProcessCount": second.same_uid_process_count,
        "kvmFdProcessCount": second.kvm_fd_process_count,
        "qemuLikeProcessCount": second.qemu_like_process_count,
        "processObservations": [
            {
                "pid": obs.pid,
                "starttime": obs.starttime,
                "uid": obs.uid,
                "kvmFdPresent": obs.kvm_fd_present,
                "qemuLike": obs.qemu_like,
                "fdEnumerationComplete": obs.fd_enumeration_complete,
            }
            for obs in second.observations
        ],
    }


def hold(reason: str) -> dict[str, object]:
    if not re.fullmatch(r"A4_FD_[A-Z0-9_]+", reason):
        reason = "A4_FD_PROCESS_VISIBILITY_UNCERTAIN"
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reasonCode": reason,
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
    }
