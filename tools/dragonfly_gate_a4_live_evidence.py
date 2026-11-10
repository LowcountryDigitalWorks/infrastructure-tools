"""REDRIX A4: bounded live Linux /proc evidence candidate, NOT a launcher.

DATA-ONLY_NOT_AUTHORIZED.  No CLI, subprocess, privilege escalation, network,
service, writes, or injected proc-root path.  The eventual protected launcher
must independently pin these exact bytes, authenticate its own one-shot
channel, bind A0/A4 and #10, and establish a separate trusted first install.
A local root or self-declared process cannot grant JIT authority here.
"""
from __future__ import annotations

from contextlib import ExitStack
import errno
import os
from pathlib import Path
import re
import select
import sys
import time

MARKER = "DRAGONFLY_GATE_A4_LIVE_FD_EVIDENCE_V1"
PROC_ROOT = Path("/proc")
TARGET_UID = 1000
MAX_PROCESSES = 4096
MAX_FDS_PER_PROCESS = 4096
MAX_READ_BYTES = 131072
MAX_CAPTURE_SECONDS = 6.0
CAP_DAC_READ_SEARCH = 2
CAP_SYS_PTRACE = 19
_UID_RE = re.compile(r"(?m)^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
_CAP_RE = re.compile(r"(?m)^Cap(Eff|Bnd):\s*([0-9a-fA-F]+)\s*$")
_NAME_RE = re.compile(r"^[1-9]\d*$")
_FD_RE = re.compile(r"^\d+$")


class EvidenceHold(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _fail(code: str) -> None:
    raise EvidenceHold(code)


def _public_result(code: str, *, valid: bool = False, count: int = 0) -> dict[str, object]:
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED" if valid else "HOLD",
        "reasonCode": "EXTERNAL_TRUST_GATES_REQUIRED" if valid else code,
        "kernelReadbackComplete": bool(valid),
        "sameUidProcessCount": count if valid else None,
        "pairedSnapshots": 2 if valid else 0,
        "a4Pass": False,
        "runtimeAuthority": False,
        "privilegedChannelAuthenticated": False,
        "jitAdmissionAuthorized": False,
        "sourceOnly": True,
    }


def _bounded_text(path: Path) -> str:
    with path.open("rb") as handle:
        payload = handle.read(MAX_READ_BYTES + 1)
    if not payload or len(payload) > MAX_READ_BYTES or b"\x00" in payload:
        _fail("A4_LIVE_PROC_MALFORMED")
    try:
        return payload.decode("ascii", "strict")
    except UnicodeError as exc:
        raise EvidenceHold("A4_LIVE_PROC_MALFORMED") from exc


def _identity(root: Path, pid: int) -> tuple[int, int, tuple[int, int, int, int], str]:
    """PID, kernel starttime, full UID quartet, comm; no argv or environ."""
    if type(pid) is not int or pid <= 0:
        _fail("A4_LIVE_PID_INVALID")
    line = _bounded_text(root / str(pid) / "stat").strip()
    start = line.find("(")
    end = line.rfind(")")
    if start < 0 or end <= start or line[:start].strip() != str(pid):
        _fail("A4_LIVE_PROC_MALFORMED")
    comm = line[start + 1 : end]
    tail = line[end + 1 :].split()
    if len(tail) < 20:
        _fail("A4_LIVE_PROC_MALFORMED")
    try:
        starttime = int(tail[19])
    except ValueError as exc:
        raise EvidenceHold("A4_LIVE_PROC_MALFORMED") from exc
    if starttime <= 0:
        _fail("A4_LIVE_PROC_MALFORMED")
    status = _bounded_text(root / str(pid) / "status")
    matches = _UID_RE.findall(status)
    if len(matches) != 1:
        _fail("A4_LIVE_PROC_MALFORMED")
    uids = tuple(int(uid) for uid in matches[0])
    return pid, starttime, uids, comm


def _capabilities(proc: Path) -> bool:
    status = _bounded_text(proc / "self" / "status")
    pairs = _CAP_RE.findall(status)
    caps = {key: int(hexvalue, 16) for key, hexvalue in pairs}
    if len(pairs) != 2 or len(caps) != 2:
        _fail("A4_LIVE_CAPABILITY_UNVERIFIED")
    needed = (1 << CAP_SYS_PTRACE) | (1 << CAP_DAC_READ_SEARCH)
    return all((caps[key] & needed) == needed for key in ("Eff", "Bnd"))


def _namespaces(proc: Path) -> tuple[str, str, str]:
    current = (
        os.readlink(proc / "self" / "ns" / "user"),
        os.readlink(proc / "self" / "ns" / "pid"),
        os.readlink(proc / "self" / "ns" / "mnt"),
    )
    target = (
        os.readlink(proc / "1" / "ns" / "user"),
        os.readlink(proc / "1" / "ns" / "pid"),
        os.readlink(proc / "1" / "ns" / "mnt"),
    )
    if current != target:
        _fail("A4_LIVE_NAMESPACE_MISMATCH")
    if not all(value.startswith(prefix) and value.endswith("]")
               for value, prefix in zip(current, ("user:[", "pid:[", "mnt:["))):
        _fail("A4_LIVE_NAMESPACE_UNVERIFIED")
    return current


def _alive_pidfd(fd: int) -> bool:
    """A pidfd becomes poll-readable when its process exits."""
    watcher = select.poll()
    watcher.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not watcher.poll(0)


def _snapshot(proc: Path, ns: tuple[str, str, str], pins: dict[int, int],
              resources: ExitStack) -> tuple[tuple[int, ...], tuple[tuple, ...]]:
    names = os.listdir(proc)
    pids = sorted(int(n) for n in names if _NAME_RE.fullmatch(n))
    if not pids or len(pids) > MAX_PROCESSES or len(set(pids)) != len(pids):
        _fail("A4_LIVE_PID_SCOPE_INCOMPLETE")
    observed: list[tuple] = []
    for pid in pids:
        before = _identity(proc, pid)
        if "qemu" in before[3].lower() or before[3].lower() == "kvm":
            _fail("A4_LIVE_QEMU_PRESENT")
        if TARGET_UID not in before[2]:
            continue
        if pid not in pins:
            if not hasattr(os, "pidfd_open"):
                _fail("A4_LIVE_PIDFD_UNAVAILABLE")
            fd = os.pidfd_open(pid, 0)
            pins[pid] = fd
            resources.callback(os.close, fd)
        if not _alive_pidfd(pins[pid]):
            _fail("A4_LIVE_PID_EXITED")
        userns = os.readlink(proc / str(pid) / "ns" / "user")
        pidns = os.readlink(proc / str(pid) / "ns" / "pid")
        mountns = os.readlink(proc / str(pid) / "ns" / "mnt")
        if (userns, pidns, mountns) != ns:
            _fail("A4_LIVE_NAMESPACE_MISMATCH")
        # exe readlink itself is a kernel ptrace READ_FSCREDS-gated lookup.
        # FD symlink readlink similarly requires a real kernel authorization.
        os.readlink(proc / str(pid) / "exe")
        entries = os.listdir(proc / str(pid) / "fd")
        if len(entries) > MAX_FDS_PER_PROCESS or any(
            _FD_RE.fullmatch(n) is None for n in entries
        ):
            _fail("A4_LIVE_FD_SCOPE_INCOMPLETE")
        fds = []
        for name in sorted(entries, key=int):
            target = os.readlink(proc / str(pid) / "fd" / name)
            if target == "/dev/kvm":
                _fail("A4_LIVE_KVM_FD_PRESENT")
            fds.append((int(name), target))
        after = _identity(proc, pid)
        if before != after or not _alive_pidfd(pins[pid]):
            _fail("A4_LIVE_PID_IDENTITY_DRIFT")
        observed.append((pid, before[1], before[2], tuple(fds)))
    return tuple(pids), tuple(observed)


def collect_live_evidence() -> dict[str, object]:
    """Fixed physical /proc source; always returns a non-authorizing record."""
    if sys.platform != "linux" or not hasattr(os, "getuid"):
        return _public_result("A4_LIVE_LINUX_REQUIRED")
    if os.geteuid() != 0:
        return _public_result("A4_LIVE_PRIVILEGE_REQUIRED")
    try:
        if not _capabilities(PROC_ROOT):
            _fail("A4_LIVE_CAPABILITY_UNVERIFIED")
        ns = _namespaces(PROC_ROOT)
        started = time.monotonic()
        with ExitStack() as resources:
            pins: dict[int, int] = {}
            before = _snapshot(PROC_ROOT, ns, pins, resources)
            after = _snapshot(PROC_ROOT, ns, pins, resources)
            if before != after or set(pins) != {obs[0] for obs in after[1]}:
                _fail("A4_LIVE_SNAPSHOT_DRIFT")
            if time.monotonic() - started > MAX_CAPTURE_SECONDS:
                _fail("A4_LIVE_CAPTURE_STALE")
            return _public_result("", valid=True, count=len(after[1]))
    except EvidenceHold as exc:
        return _public_result(exc.code)
    except (OSError, ValueError, RuntimeError, OverflowError):
        # Never return OS exception strings that may expose paths or process info.
        return _public_result("A4_LIVE_KERNEL_READBACK_INCOMPLETE")
