"""Non-authorizing synthetic / injected proc+FD inspection core for REDRIX Gate A4 (#139).

This module is DATA-ONLY. It does not invoke sudo, launch processes, open network
sockets, write disk state, or establish runtime A4 PASS. Continuous Linux /proc
churn can cause conservative HOLD between paired snapshots; future pidfd anchoring
may be required for stronger stability guarantees on live hosts.

Effective UID is taken from /proc/<pid>/status (Uid: R/E/S/FS), never from
/proc/stat or from /proc/<pid> directory ownership (which may be root:root for
non-dumpable targets). Accepted pinned A0 QEMU enumeration across all visible PIDs
remains mandatory for runtime A4; this core performs a fail-closed synthetic
all-PID QEMU probe only.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import re
from typing import Optional, Protocol

MARKER = "DRAGONFLY_GATE_A4_FD_INSPECTOR_CORE_V1"
DEFAULT_UID = 1000
QEMU_NAMES = {"qemu-kvm", "kvm"}
KVM_TARGET = "/dev/kvm"


class FdInspectorError(Exception):
    """Synthetic inspection failure surfaced as HOLD."""


def parse_proc_status_uids(status_text: str) -> tuple[int, int, int, int]:
    """Parse /proc/<pid>/status Uid line: real, effective, saved, fs."""
    for raw in status_text.splitlines():
        line = raw.strip()
        if not line.startswith("Uid:"):
            continue
        parts = line.split()
        if len(parts) != 5:
            raise FdInspectorError("A4_FD_MALFORMED_STATUS")
        try:
            return tuple(int(parts[i]) for i in range(1, 5))  # type: ignore[return-value]
        except ValueError as exc:
            raise FdInspectorError("A4_FD_MALFORMED_STATUS") from exc
    raise FdInspectorError("A4_FD_MALFORMED_STATUS")


def parse_proc_stat(stat_line: str) -> tuple[int, str, int, int]:
    """Parse /proc/<pid>/stat: pid, comm, utime (field 14), starttime (field 22).

    /proc/stat does not expose UID; callers must use /proc/status Uid fields.
    """
    stat_line = stat_line.strip()
    match = re.match(r"^(\d+) \((.*)\) (\S.*)$", stat_line)
    if not match:
        raise FdInspectorError("A4_FD_MALFORMED_STAT")
    pid = int(match.group(1))
    comm = match.group(2)
    tail = match.group(3).split()
    if len(tail) < 20:
        raise FdInspectorError("A4_FD_MALFORMED_STAT")
    try:
        utime = int(tail[11])
        starttime = int(tail[19])
    except ValueError as exc:
        raise FdInspectorError("A4_FD_MALFORMED_STAT") from exc
    return pid, comm, utime, starttime


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
    def read_status_text(self, pid: int) -> str: ...
    def list_fd_targets(self, pid: int) -> list[str]: ...


class ProcAccessDenied(FdInspectorError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _map_os_error(exc: OSError, *, fd_context: bool = False) -> FdInspectorError:
    if exc.errno in (errno.EACCES, errno.EPERM):
        return FdInspectorError("A4_FD_DENIED_FD" if fd_context else "A4_FD_STAT_UNAVAILABLE")
    return FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION")


@dataclass(frozen=True)
class ProcessFixture:
    pid: int
    uid: int
    starttime: int
    comm: str
    utime: int = 100
    uid_real: Optional[int] = None
    uid_saved: Optional[int] = None
    uid_fs: Optional[int] = None
    proc_dir_uid: int = -1
    exec_tokens: tuple[str, ...] = ()
    fd_targets: tuple[str, ...] = ()
    stat_available: bool = True
    status_available: bool = True
    fd_available: bool = True
    ambiguous_symlink: bool = False
    vanish_after_first: bool = False
    starttime_after_first: Optional[int] = None
    utime_after_first: Optional[int] = None
    fd_os_error: Optional[int] = None
    effective_uid_after_first: Optional[int] = None
    uid_saved_after_first: Optional[int] = None
    uid_fs_after_first: Optional[int] = None


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

    def _fixture(self, pid: int) -> ProcessFixture:
        proc = self.processes.get(pid)
        if proc is None:
            raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
        if proc.vanish_after_first and getattr(self, "_first_pass_done", False):
            raise ProcAccessDenied("A4_FD_PROCESS_VANISHED")
        return proc

    def _status_uids(self, proc: ProcessFixture) -> tuple[int, int, int, int]:
        effective = proc.uid
        if proc.effective_uid_after_first is not None and getattr(self, "_first_pass_done", False):
            effective = proc.effective_uid_after_first
        real = proc.uid_real if proc.uid_real is not None else effective
        saved = proc.uid_saved if proc.uid_saved is not None else effective
        fs = proc.uid_fs if proc.uid_fs is not None else effective
        if getattr(self, "_first_pass_done", False):
            if proc.uid_saved_after_first is not None:
                saved = proc.uid_saved_after_first
            if proc.uid_fs_after_first is not None:
                fs = proc.uid_fs_after_first
        return real, effective, saved, fs

    def read_status_text(self, pid: int) -> str:
        proc = self._fixture(pid)
        if not proc.status_available:
            raise ProcAccessDenied("A4_FD_DENIED_STATUS")
        real, effective, saved, fs = self._status_uids(proc)
        dir_uid = proc.proc_dir_uid if proc.proc_dir_uid >= 0 else effective
        return (
            f"Name:\t{proc.comm}\n"
            f"Pid:\t{proc.pid}\n"
            f"Uid:\t{real}\t{effective}\t{saved}\t{fs}\n"
            f"ProcDirUidHint:\t{dir_uid}\n"
        )

    def read_stat_line(self, pid: int) -> str:
        proc = self._fixture(pid)
        if not proc.stat_available:
            raise ProcAccessDenied("A4_FD_STAT_UNAVAILABLE")
        utime = proc.utime
        if proc.utime_after_first is not None and getattr(self, "_first_pass_done", False):
            utime = proc.utime_after_first
        starttime = proc.starttime
        if proc.starttime_after_first is not None and getattr(self, "_first_pass_done", False):
            starttime = proc.starttime_after_first
        tail = ["S", *("0",) * 10, str(utime), "0", *("0",) * 6, str(starttime)]
        return f"{proc.pid} ({proc.comm}) " + " ".join(tail)

    def list_fd_targets(self, pid: int) -> list[str]:
        proc = self._fixture(pid)
        if proc.fd_os_error is not None:
            raise OSError(proc.fd_os_error, "synthetic fd permission denied")
        if not proc.fd_available:
            raise ProcAccessDenied("A4_FD_DENIED_FD")
        if proc.ambiguous_symlink:
            raise ProcAccessDenied("A4_FD_SYMLINK_AMBIGUOUS")
        return list(proc.fd_targets)

    def mark_first_pass_complete(self) -> None:
        self._first_pass_done = True


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    comm: str
    utime: int
    starttime: int
    uid: int
    uid_real: int
    uid_saved: int
    uid_fs: int


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    starttime: int
    uid: int
    uid_real: int
    uid_saved: int
    uid_fs: int
    kvm_fd_present: bool
    qemu_like: bool
    fd_enumeration_complete: bool


@dataclass(frozen=True)
class Snapshot:
    observations: tuple[ProcessObservation, ...]
    same_uid_process_count: int
    kvm_fd_process_count: int
    qemu_like_process_count: int
    all_uid_qemu_process_count: int


def _exec_tokens(port: ProcPort, pid: int) -> tuple[str, ...]:
    proc = getattr(port, "processes", {}).get(pid)
    if isinstance(proc, ProcessFixture):
        return proc.exec_tokens
    return ()


def _read_identity(port: ProcPort, pid: int) -> ProcessIdentity:
    try:
        stat_line = port.read_stat_line(pid)
    except ProcAccessDenied as exc:
        raise FdInspectorError(exc.code) from exc
    except OSError as exc:
        raise _map_os_error(exc) from exc
    parsed_pid, comm, utime, starttime = parse_proc_stat(stat_line)
    if parsed_pid != pid:
        raise FdInspectorError("A4_FD_PID_MISMATCH")
    try:
        status_text = port.read_status_text(pid)
    except ProcAccessDenied as exc:
        raise FdInspectorError(exc.code) from exc
    except OSError as exc:
        raise _map_os_error(exc) from exc
    uid_real, uid_effective, uid_saved, uid_fs = parse_proc_status_uids(status_text)
    return ProcessIdentity(
        pid=parsed_pid,
        comm=comm,
        utime=utime,
        starttime=starttime,
        uid=uid_effective,
        uid_real=uid_real,
        uid_saved=uid_saved,
        uid_fs=uid_fs,
    )


def _identity_stable(before: ProcessIdentity, after: ProcessIdentity) -> bool:
    return (
        before.pid == after.pid
        and before.uid == after.uid
        and before.uid_real == after.uid_real
        and before.uid_saved == after.uid_saved
        and before.uid_fs == after.uid_fs
        and before.starttime == after.starttime
    )


def _qemu_like_any_uid(port: ProcPort, pid: int) -> bool:
    identity = _read_identity(port, pid)
    return process_is_qemu_like(identity.comm, _exec_tokens(port, pid))


def _enumerate_all_uid_qemu(port: ProcPort, pids: list[int]) -> int:
    matches = 0
    for pid in pids:
        try:
            if _qemu_like_any_uid(port, pid):
                matches += 1
        except FdInspectorError:
            raise
        except OSError as exc:
            raise _map_os_error(exc) from exc
    return matches


def _observe_same_uid_process(port: ProcPort, pid: int, expected_uid: int) -> Optional[ProcessObservation]:
    before = _read_identity(port, pid)
    if before.uid != expected_uid:
        return None
    try:
        fd_targets = port.list_fd_targets(pid)
    except ProcAccessDenied as exc:
        raise FdInspectorError(exc.code) from exc
    except OSError as exc:
        raise _map_os_error(exc, fd_context=True) from exc
    after = _read_identity(port, pid)
    if not _identity_stable(before, after):
        raise FdInspectorError("A4_FD_PID_REUSE")
    kvm_present = any(target == KVM_TARGET for target in fd_targets)
    qemu_like = process_is_qemu_like(before.comm, _exec_tokens(port, pid))
    return ProcessObservation(
        pid=before.pid,
        starttime=before.starttime,
        uid=before.uid,
        uid_real=before.uid_real,
        uid_saved=before.uid_saved,
        uid_fs=before.uid_fs,
        kvm_fd_present=kvm_present,
        qemu_like=qemu_like,
        fd_enumeration_complete=True,
    )


def inspect_once(port: ProcPort, *, expected_uid: int = DEFAULT_UID) -> Snapshot:
    if getattr(port, "enumeration_incomplete", False):
        raise FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION")
    observations: list[ProcessObservation] = []
    try:
        pids = port.list_numeric_pids()
    except OSError as exc:
        raise _map_os_error(exc) from exc
    all_uid_qemu = _enumerate_all_uid_qemu(port, pids)
    if all_uid_qemu:
        raise FdInspectorError("A4_FD_QEMU_PROCESS_PRESENT")
    seen_uid_pids: set[int] = set()
    for pid in pids:
        obs = _observe_same_uid_process(port, pid, expected_uid)
        if obs is None:
            continue
        seen_uid_pids.add(pid)
        if obs.kvm_fd_present:
            raise FdInspectorError("A4_FD_KVM_FD_PRESENT")
        if obs.qemu_like:
            raise FdInspectorError("A4_FD_QEMU_PROCESS_PRESENT")
        observations.append(obs)
    if isinstance(port, SyntheticProcRoot):
        required = {
            p.pid
            for p in port.processes.values()
            if p.uid == expected_uid and p.stat_available and p.status_available
        }
        if seen_uid_pids != required:
            raise FdInspectorError("A4_FD_INCOMPLETE_ENUMERATION")
    observations.sort(key=lambda item: item.pid)
    return Snapshot(
        observations=tuple(observations),
        same_uid_process_count=len(observations),
        kvm_fd_process_count=0,
        qemu_like_process_count=0,
        all_uid_qemu_process_count=all_uid_qemu,
    )


def _snapshot_key(snapshot: Snapshot) -> tuple:
    return tuple(
        (
            obs.pid,
            obs.starttime,
            obs.uid,
            obs.uid_real,
            obs.uid_saved,
            obs.uid_fs,
            obs.kvm_fd_present,
            obs.qemu_like,
            obs.fd_enumeration_complete,
        )
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
        "complementaryA0QemuEnumerationRequired": True,
        "expectedUid": expected_uid,
        "stabilityPasses": 2,
        "sameUidProcessCount": second.same_uid_process_count,
        "kvmFdProcessCount": second.kvm_fd_process_count,
        "qemuLikeProcessCount": second.qemu_like_process_count,
        "allUidQemuProcessCount": second.all_uid_qemu_process_count,
        "processObservations": [
            {
                "pid": obs.pid,
                "starttime": obs.starttime,
                "uid": obs.uid,
                "uidReal": obs.uid_real,
                "uidSaved": obs.uid_saved,
                "uidFs": obs.uid_fs,
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
        "complementaryA0QemuEnumerationRequired": True,
    }
