#!/usr/bin/env python3
"""One-shot offline nested-KVM capacity executor. Not JIT, provider, or production admission."""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import math
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

MARKER = "LDW_REDRIX_CAPACITY_GUEST_EXECUTOR"
SUCCESS_PREFIX = "LDW_REDRIX_GUEST_EXEC_OK"
PUBLIC_SYNTHETIC_NOTE = (
    "PUBLIC_SYNTHETIC_TEST_MARKER_ONLY_NOT_LAUNCH_AUTHORITY"
)
EXPECTED_CONTROLLER_BLOB = "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a"
EXPECTED_BASE_SHA512 = (
    "3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538"
    "d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e"
)
BASE_FILENAME = "debian-13-genericcloud-amd64.qcow2"
GUEST_MIB = 2048
PRODUCTION_RESERVE_MIB = 8192
RESEARCH_RESERVE_MIB = 6144
RESEARCH_FLOOR_MIB = GUEST_MIB + RESEARCH_RESERVE_MIB
GUEST_CPUS = 2
WORKLOAD_MIB = 1024
HOLD_SECONDS = 15
TIMEOUT_SECONDS = 210
MIN_SAMPLES, MAX_SAMPLES = 3, 6
SAMPLE_INTERVAL = 1.0
MIN_FREE_DISK_GIB = 16
MAX_LOAD_FRACTION = 0.70
# Research hypothesis only; physical load proof requires independent corroboration.
MIN_QEMU_RSS_RESEARCH_KIB = 768 * 1024
SERIAL_TAIL_MAX_BYTES = 256 * 1024
SERIAL_MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PROC_PID = 2**22
MAX_PROC_STARTTIME = (1 << 63) - 1
MAX_PSI_SOME_AVG10 = 1.0
MAX_PSI_FULL_AVG10 = 1.0
CONTROLLER_STATE_MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
CONTROLLER_STATE_SCHEMA = 1
GUEST_LOCK_NAME = "guest.lock"
ALLOWED_CONTROLLER_STATES = frozenset({"STOPPED", "AVAILABLE"})
RUN_ONCE_FLAG = "--run-once-local"
# Independent IR required before any physical --run-once-local on REDRIX.
PHYSICAL_EXECUTION_ENABLED = False


def _execution_permitted(ctx: "RunContext") -> bool:
    """Physical path requires flag; unit tests may set RunContext.synthetic_test_admission only."""
    if PHYSICAL_EXECUTION_ENABLED:
        return True
    return bool(ctx.synthetic_test_admission)


class GuestLockBusy(Exception):
    """Non-blocking guest.lock acquisition failed."""


def _report(**fields: object) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reason": "HOLD",
        "physical_guest_executed": False,
        "jit_admission_authorized": False,
        "provider_admission_authorized": False,
        "production_policy_changed": False,
        "production_reserve_mib": PRODUCTION_RESERVE_MIB,
        "research_floor_mib": RESEARCH_FLOOR_MIB,
        "guest_mib": GUEST_MIB,
        "network": "none",
        "public_synthetic_note": PUBLIC_SYNTHETIC_NOTE,
        "chromeos_host_corroboration": "UNVERIFIED",
        "evidence_retained": False,
    }
    body.update(fields)
    for key in (
        "jit_admission_authorized",
        "provider_admission_authorized",
        "production_policy_changed",
    ):
        body[key] = False
    body["production_reserve_mib"] = PRODUCTION_RESERVE_MIB
    return body


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    return None


def parse_controller_text(text: str) -> dict | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    found: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id in ("GUEST_MEMORY_MIB", "MIN_RESERVE_MIB"):
            if isinstance(node.value, ast.Constant) and type(node.value.value) is int:
                found[target.id] = node.value.value
        elif target.id == "BASE_SHA512":
            value = _string_constant(node.value)
            if value is None:
                return None
            found[target.id] = value
    guest = found.get("GUEST_MEMORY_MIB")
    reserve = found.get("MIN_RESERVE_MIB")
    digest = found.get("BASE_SHA512")
    if guest != GUEST_MIB or reserve != PRODUCTION_RESERVE_MIB or digest != EXPECTED_BASE_SHA512:
        return None
    return {"guest_mib": guest, "reserve_mib": reserve, "base_sha512": digest}


def read_controller_identity(path: Path) -> dict | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        data = path.read_bytes().replace(b"\r\n", b"\n")
        parsed = parse_controller_text(data.decode("utf-8"))
        if parsed is None:
            return None
        parsed["blob"] = git_blob_sha1(data)
        return parsed
    except (OSError, UnicodeError, ValueError):
        return None


def discover_memory_events_path(
    cgroup_file: Path = Path("/proc/self/cgroup"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    *,
    max_lines: int = 32,
) -> Path | None:
    """Resolve cgroup v2 unified hierarchy `0::/path` memory.events only."""
    try:
        lines = cgroup_file.read_text(encoding="ascii").splitlines()[:max_lines]
    except OSError:
        return None
    rel: str | None = None
    for line in lines:
        if not line.startswith("0::"):
            continue
        rel = line[3:].strip().lstrip("/")
        break
    if rel is None:
        return None
    if ".." in rel.split("/") or rel.startswith(".."):
        return None
    candidate = (cgroup_root / rel / "memory.events") if rel else cgroup_root / "memory.events"
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None
    root_s = str(cgroup_root.resolve(strict=False)).replace("\\", "/")
    resolved_s = str(resolved).replace("\\", "/")
    if not resolved_s.startswith(root_s):
        return None
    return candidate if candidate.is_file() and not candidate.is_symlink() else None


def read_controller_runtime_state(state_path: Path, runs_root: Path) -> str | None:
    """Return a HOLD reason when controller state cannot be trusted; else None."""
    if state_path.is_symlink() or not state_path.is_file():
        return "CONTROLLER_STATE_UNAVAILABLE"
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return "CONTROLLER_STATE_UNAVAILABLE"
    if not isinstance(payload, dict):
        return "CONTROLLER_STATE_INVALID"
    if payload.get("schema") != CONTROLLER_STATE_SCHEMA or payload.get("marker") != CONTROLLER_STATE_MARKER:
        return "CONTROLLER_STATE_INVALID"
    state = payload.get("state")
    if not isinstance(state, str) or state not in ALLOWED_CONTROLLER_STATES | {"RUNNING", "DRAINING", "HOLD", "FAILED"}:
        return "CONTROLLER_STATE_INVALID"
    if state not in ALLOWED_CONTROLLER_STATES:
        return "CONTROLLER_STATE_REFUSED"
    qemu_pid = payload.get("qemu_pid")
    if qemu_pid is not None and (not isinstance(qemu_pid, int) or isinstance(qemu_pid, bool) or qemu_pid <= 0):
        return "CONTROLLER_STATE_INVALID"
    if qemu_pid:
        return "QEMU_ALREADY_PRESENT"
    if runs_root.is_symlink():
        return "SYMLINK_REFUSED"
    if not runs_root.is_dir():
        if runs_root.exists():
            return "CONTROLLER_RUNS_RESIDUE"
        return None
    try:
        for entry in runs_root.iterdir():
            if entry.is_symlink():
                return "CONTROLLER_RUNS_RESIDUE"
            if not entry.is_dir():
                return "CONTROLLER_RUNS_RESIDUE"
    except OSError:
        return "CONTROLLER_RUNS_RESIDUE"
    return None


def read_oom_events(path: Path) -> tuple[int, int] | None:
    if not path.is_file():
        return None
    try:
        values: dict[str, int] = {}
        for line in path.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] not in ("oom", "oom_kill"):
                continue
            n = int(fields[1])
            if n < 0:
                return None
            if fields[0] in values:
                return None
            values[fields[0]] = n
        if set(values) == {"oom", "oom_kill"}:
            return values["oom"], values["oom_kill"]
        return None
    except (OSError, UnicodeError, ValueError):
        return None


def parse_vmstat_balloon_inflate(vmstat_text: str) -> int | None:
    try:
        for line in vmstat_text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "balloon_inflate":
                value = int(parts[1])
                if value < 0 or value > 2**53:
                    return None
                return value
        return None
    except (ValueError, TypeError):
        return None


def _finite_load(value: object) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def fixed_qemu_argv(overlay: Path, seed: Path, serial_path: Path) -> list[str] | None:
    for part in (overlay, seed, serial_path):
        if part.is_symlink():
            return None
        resolved = str(part.resolve())
        if not resolved or "\x00" in resolved or resolved.startswith("-"):
            return None
    return [
        "qemu-system-x86_64",
        "-accel",
        "kvm",
        "-machine",
        "q35",
        "-cpu",
        "host",
        "-smp",
        str(GUEST_CPUS),
        "-m",
        f"{GUEST_MIB}M",
        "-nic",
        "none",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        f"file:{serial_path}",
        "-no-reboot",
        "-drive",
        f"if=virtio,format=qcow2,file={overlay}",
        "-drive",
        f"if=virtio,format=raw,readonly=on,file={seed}",
    ]


def guest_workload_shell_body(nonce_hex: str) -> str:
    marker_line = f"{SUCCESS_PREFIX} nonce={nonce_hex}"
    return (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "python3 - <<'PY'\n"
        "import hashlib,time\n"
        f"chunks={WORKLOAD_MIB}\n"
        "buf=[]\n"
        "for _ in range(chunks):\n"
        "    page=bytearray(1024*1024)\n"
        "    for i in range(0,len(page),4096):\n"
        "        page[i]=1\n"
        "    buf.append(page)\n"
        "digest=hashlib.sha256(b''.join(buf[:64])).hexdigest()\n"
        "open('/tmp/redrix-exec.bin','wb').write(digest.encode())\n"
        f"time.sleep({HOLD_SECONDS})\n"
        "PY\n"
        f"printf '%s\\n' '{marker_line}' > /dev/ttyS0\n"
    )


def build_cloud_config(nonce_hex: str) -> str:
    script = guest_workload_shell_body(nonce_hex)
    indented = "\n".join(f"      {line}" if line else "      " for line in script.splitlines())
    return (
        "#cloud-config\n"
        "hostname: ldw-redrix-capacity-exec\n"
        "ssh_pwauth: false\n"
        "disable_root: true\n"
        "network:\n"
        "  config: disabled\n"
        "write_files:\n"
        "  - path: /usr/local/sbin/ldw-redrix-exec.sh\n"
        "    permissions: '0755'\n"
        "    owner: root:root\n"
        "    content: |\n"
        f"{indented}\n"
        "runcmd:\n"
        "  - [ /usr/local/sbin/ldw-redrix-exec.sh ]\n"
        "power_state:\n"
        "  delay: now\n"
        "  mode: poweroff\n"
        "  message: LDW offline capacity executor complete\n"
        "  timeout: 60\n"
        "  condition: true\n"
    )


def assess_serial_success(serial_text: str, nonce_hex: str) -> str | None:
    """Return HOLD reason when serial proof is missing or ambiguous."""
    expected = f"{SUCCESS_PREFIX} nonce={nonce_hex}"
    exact: list[str] = []
    for line in serial_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == expected:
            exact.append(stripped)
        elif stripped.startswith(f"{SUCCESS_PREFIX} "):
            return "SERIAL_MARKER_CONFLICT"
    if not exact:
        return "SUCCESS_MARKER_MISSING"
    if len(exact) > 1:
        return "SERIAL_DUPLICATE_MARKER"
    return None


def parse_success_line(serial_text: str, nonce_hex: str) -> bool:
    return assess_serial_success(serial_text, nonce_hex) is None


def read_serial_tail_text(
    path: Path,
    *,
    max_tail_bytes: int = SERIAL_TAIL_MAX_BYTES,
) -> str | None:
    """Bounded tail read via O_NOFOLLOW regular file; None => treat as SERIAL_UNAVAILABLE."""
    if path.is_symlink():
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        import stat as stat_mod

        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            return None
        size = st.st_size
        if size < 0 or size > SERIAL_MAX_FILE_BYTES:
            return None
        read_len = min(size, max_tail_bytes)
        os.lseek(fd, max(0, size - read_len), os.SEEK_SET)
        data = os.read(fd, read_len)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data.decode("utf-8", errors="replace")


@dataclass
class PreflightObservation:
    mem_available_mib: list[int]
    psi_some_full: list[tuple[float, float]]
    balloon_inflate: list[int]
    oom_before: tuple[int, int]
    load_fraction: float
    free_disk_gib: int
    kvm_rw: bool
    qemu_present: bool
    controller_state: str
    lock_busy: bool
    residue_runs: int
    symlink_refused: bool
    controller_blob: str
    base_sha512: str
    uid: int
    memory_events_path: str


def assess_preflight(obs: PreflightObservation) -> str | None:
    if obs.uid != 1000:
        return "UID_REFUSED"
    if obs.symlink_refused:
        return "SYMLINK_REFUSED"
    if obs.controller_blob != EXPECTED_CONTROLLER_BLOB:
        return "CONTROLLER_BLOB_MISMATCH"
    if obs.base_sha512 != EXPECTED_BASE_SHA512:
        return "BASE_SHA512_MISMATCH"
    if obs.lock_busy:
        return "GUEST_LOCK_BUSY"
    if obs.qemu_present:
        return "QEMU_ALREADY_PRESENT"
    if obs.controller_state not in ALLOWED_CONTROLLER_STATES:
        return "CONTROLLER_STATE_REFUSED"
    if obs.residue_runs != 0:
        return "CONTROLLER_RUNS_RESIDUE"
    if not MIN_SAMPLES <= len(obs.mem_available_mib) <= MAX_SAMPLES:
        return "SAMPLE_COUNT_REFUSED"
    if any(item < RESEARCH_FLOOR_MIB for item in obs.mem_available_mib):
        return "RESEARCH_MEMORY_FLOOR"
    if len(obs.psi_some_full) != len(obs.mem_available_mib):
        return "PSI_UNAVAILABLE"
    if any(item != obs.psi_some_full[0] for item in obs.psi_some_full):
        return "PSI_UNSTABLE"
    for some, full in obs.psi_some_full:
        if some > MAX_PSI_SOME_AVG10 or full > MAX_PSI_FULL_AVG10:
            return "PSI_PRESSURE"
    if len(obs.balloon_inflate) != len(obs.mem_available_mib):
        return "BALLOON_UNAVAILABLE"
    for idx in range(1, len(obs.balloon_inflate)):
        before = obs.balloon_inflate[idx - 1]
        after = obs.balloon_inflate[idx]
        if not isinstance(before, int) or not isinstance(after, int):
            return "BALLOON_UNAVAILABLE"
        if after < before:
            return "BALLOON_NONMONOTONIC"
        if after > before:
            return "BALLOON_INFLATION"
    for item in obs.mem_available_mib:
        if not isinstance(item, int) or item < 0:
            return "MEMORY_OR_PRESSURE_UNAVAILABLE"
    load = _finite_load(obs.load_fraction)
    if load is None or load > MAX_LOAD_FRACTION:
        return "CAPACITY_CPU"
    if obs.free_disk_gib < MIN_FREE_DISK_GIB:
        return "CAPACITY_DISK"
    if not obs.kvm_rw:
        return "KVM_NOT_READY"
    if not obs.memory_events_path:
        return "OOM_COUNTER_UNAVAILABLE"
    return None


class ProcessHandle(Protocol):
    pid: int
    starttime: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass
class ExecutorHooks:
    """Injectable host port for tests; live REDRIX uses LinuxHostHooks."""

    uid: Callable[[], int] = lambda: os.getuid()
    discover_memory_events: Callable[[], Path | None] = discover_memory_events_path
    read_oom: Callable[[Path], tuple[int, int] | None] = read_oom_events
    now: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    make_work_root: Callable[[], Path] | None = None
    acquire_guest_lock: Callable[[Path], Iterator[None]] | None = None
    prepare_guest_artifacts: Callable[..., str | None] | None = None
    read_proc_status: Callable[[int], int | None] | None = None
    read_proc_starttime: Callable[[int], int | None] | None = None
    recheck_under_guest_lock: Callable[[RunContext], str | None] | None = None
    workload_host_check: Callable[[], str | None] | None = None


@dataclass
class RunContext:
    hooks: ExecutorHooks
    guest_lock_path: Path
    state_lock_path: Path
    controller_path: Path
    base_image_path: Path
    state_path: Path
    runs_root: Path
    kvm_path: Path = Path("/dev/kvm")
    meminfo_path: Path = Path("/proc/meminfo")
    psi_cgroup: Path = Path("/sys/fs/cgroup/memory.pressure")
    psi_proc: Path = Path("/proc/pressure/memory")
    vmstat_path: Path = Path("/proc/vmstat")
    extra_argv: bool = False
    qemu_factory: Callable[[list[str]], ProcessHandle] | None = None
    tools_present: bool = True
    sample_count: int = MIN_SAMPLES
    preflight_observation: PreflightObservation | None = None
    # True only in deterministic unit tests; never set from CLI or wire_linux_executor.
    synthetic_test_admission: bool = False


def _read_mem_mib(path: Path) -> int | None:
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) == 3 and parts[2] == "kB":
                    return int(parts[1]) // 1024
        return None
    except (OSError, ValueError):
        return None


def _read_psi(path_a: Path, path_b: Path) -> tuple[float, float] | None:
    for path in (path_a, path_b):
        try:
            found: dict[str, float] = {}
            for line in path.read_text(encoding="ascii").splitlines():
                fields = line.split()
                if not fields or fields[0] not in ("some", "full"):
                    continue
                values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
                number = float(values["avg10"])
                if not math.isfinite(number) or not 0 <= number <= 100:
                    return None
                found[fields[0]] = number
            if set(found) == {"some", "full"}:
                return found["some"], found["full"]
        except (OSError, ValueError, KeyError):
            continue
    return None


def collect_preflight(ctx: RunContext) -> PreflightObservation | dict[str, Any]:
    if ctx.extra_argv:
        return _report(reason="ARGV_OR_PATH_REFUSED")
    identity = read_controller_identity(ctx.controller_path)
    if identity is None:
        return _report(reason="CONTROLLER_CONTRACT_MISMATCH")
    try:
        if ctx.base_image_path.is_symlink():
            return _report(reason="SYMLINK_REFUSED")
        base_digest = hashlib.sha512()
        with ctx.base_image_path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                base_digest.update(block)
        base_sha = base_digest.hexdigest()
    except OSError:
        return _report(reason="BASE_SHA512_MISMATCH")
    if base_sha != EXPECTED_BASE_SHA512:
        return _report(reason="BASE_SHA512_MISMATCH")
    events_path = ctx.hooks.discover_memory_events()
    if events_path is None:
        return _report(reason="OOM_COUNTER_UNAVAILABLE")
    oom_before = ctx.hooks.read_oom(events_path)
    if oom_before is None:
        return _report(reason="OOM_COUNTER_UNAVAILABLE")
    mem: list[int] = []
    psi: list[tuple[float, float]] = []
    balloon: list[int] = []
    try:
        vmstat0 = ctx.vmstat_path.read_text(encoding="ascii")
    except OSError:
        return _report(reason="BALLOON_UNAVAILABLE")
    if not MIN_SAMPLES <= ctx.sample_count <= MAX_SAMPLES:
        return _report(reason="SAMPLE_COUNT_REFUSED")
    for _ in range(ctx.sample_count):
        sample = _read_mem_mib(ctx.meminfo_path)
        if sample is None:
            return _report(reason="MEMORY_OR_PRESSURE_UNAVAILABLE")
        pressure = _read_psi(ctx.psi_cgroup, ctx.psi_proc)
        if pressure is None:
            return _report(reason="PSI_UNAVAILABLE")
        bval = parse_vmstat_balloon_inflate(vmstat0)
        if bval is None:
            return _report(reason="BALLOON_UNAVAILABLE")
        mem.append(sample)
        psi.append(pressure)
        balloon.append(bval)
        ctx.hooks.sleep(SAMPLE_INTERVAL)
        try:
            vmstat0 = ctx.vmstat_path.read_text(encoding="ascii")
        except OSError:
            return _report(reason="BALLOON_UNAVAILABLE")
    state_problem = read_controller_runtime_state(ctx.state_path, ctx.runs_root)
    if state_problem:
        return _report(reason=state_problem)
    try:
        state = json.loads(ctx.state_path.read_text(encoding="utf-8"))
        controller_state = str(state["state"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return _report(reason="CONTROLLER_STATE_UNAVAILABLE")
    qemu_present = False
    residue = 0
    load = _finite_load(0.0)
    free_disk = MIN_FREE_DISK_GIB
    try:
        import shutil

        load = _finite_load(os.getloadavg()[0] / max(os.cpu_count() or 1, 1))
        free_disk = shutil.disk_usage(ctx.base_image_path.parent).free // (1024**3)
    except (OSError, AttributeError):
        pass
    if load is None:
        return _report(reason="CAPACITY_CPU")
    kvm_rw = False
    try:
        kvm_rw = ctx.kvm_path.exists() and os.access(ctx.kvm_path, os.R_OK | os.W_OK)
    except OSError:
        kvm_rw = False
    return PreflightObservation(
        mem_available_mib=mem,
        psi_some_full=psi,
        balloon_inflate=balloon,
        oom_before=oom_before,
        load_fraction=load,
        free_disk_gib=int(free_disk),
        kvm_rw=kvm_rw,
        qemu_present=qemu_present,
        controller_state=controller_state,
        lock_busy=False,
        residue_runs=residue,
        symlink_refused=False,
        controller_blob=identity["blob"],
        base_sha512=base_sha,
        uid=ctx.hooks.uid(),
        memory_events_path=str(events_path),
    )


def make_private_work_root(hooks: ExecutorHooks) -> Path:
    if hooks.make_work_root is not None:
        return hooks.make_work_root()
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="ldw-redrix-exec-"))
    os.chmod(root, 0o700)
    return root


@contextlib.contextmanager
def _noop_lock(_path: Path) -> Iterator[None]:
    yield


def parse_proc_stat_text(
    text: str,
    *,
    expected_pid: int | None = None,
    expected_uid: int | None = None,
) -> tuple[int, int, int] | None:
    """Parse pid, starttime (field 22), real uid from /proc/pid/stat (+ status uid)."""
    if not text or len(text) > 4096:
        return None
    space = text.find(" ")
    if space < 1:
        return None
    try:
        pid = int(text[:space])
    except ValueError:
        return None
    if pid <= 0 or pid > MAX_PROC_PID:
        return None
    if expected_pid is not None and pid != expected_pid:
        return None
    lparen = text.find("(", space)
    rparen = text.rfind(")")
    if lparen < 0 or rparen <= lparen:
        return None
    tail = text[rparen + 1 :].strip()
    if not tail:
        return None
    fields = tail.split()
    # state=fields[0]; starttime is proc field 22 => tail index 19
    if len(fields) < 20:
        return None
    try:
        starttime = int(fields[19])
    except ValueError:
        return None
    if starttime < 0 or starttime > MAX_PROC_STARTTIME:
        return None
    uid = _read_proc_uid(pid) if expected_uid is not None else None
    if expected_uid is not None and uid != expected_uid:
        return None
    return pid, starttime, uid if uid is not None else -1


def _read_proc_uid(pid: int) -> int | None:
    if pid <= 0 or pid > MAX_PROC_PID:
        return None
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
        return None
    except (OSError, ValueError, IndexError):
        return None


def read_proc_stat_identity(
    pid: int,
    *,
    expected_uid: int | None = None,
) -> tuple[int, int, int] | None:
    if pid <= 0 or pid > MAX_PROC_PID:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError):
        return None
    return parse_proc_stat_text(text, expected_pid=pid, expected_uid=expected_uid)


def verify_owned_process(pid: int, starttime: int, hooks: ExecutorHooks) -> bool:
    if pid <= 0 or starttime < 0:
        return False
    reader = hooks.read_proc_starttime
    if reader is not None:
        observed = reader(pid)
        return observed is not None and observed == starttime
    identity = read_proc_stat_identity(pid, expected_uid=hooks.uid())
    if identity is None:
        return False
    obs_pid, obs_start, obs_uid = identity
    if obs_uid >= 0 and obs_uid != hooks.uid():
        return False
    return obs_pid == pid and obs_start == starttime


def sample_workload_host_telemetry(
    ctx: RunContext,
    *,
    mem_floor_mib: int,
    balloon_baseline: int,
    oom_before: tuple[int, int],
    memory_events_path: str,
) -> str | None:
    mem = _read_mem_mib(ctx.meminfo_path)
    if mem is None or mem < mem_floor_mib:
        return "WORKLOAD_MEMORY_PRESSURE"
    psi = _read_psi(ctx.psi_cgroup, ctx.psi_proc)
    if psi is None:
        return "WORKLOAD_PSI_UNAVAILABLE"
    if psi[0] > MAX_PSI_SOME_AVG10 or psi[1] > MAX_PSI_FULL_AVG10:
        return "WORKLOAD_PSI_PRESSURE"
    try:
        vmstat = ctx.vmstat_path.read_text(encoding="ascii")
    except OSError:
        return "WORKLOAD_BALLOON_UNAVAILABLE"
    balloon = parse_vmstat_balloon_inflate(vmstat)
    if balloon is None:
        return "WORKLOAD_BALLOON_UNAVAILABLE"
    if balloon < balloon_baseline:
        return "WORKLOAD_BALLOON_NONMONOTONIC"
    if balloon > balloon_baseline:
        return "WORKLOAD_BALLOON_INFLATION"
    events_path = Path(memory_events_path)
    if not events_path.is_file():
        return "WORKLOAD_OOM_UNAVAILABLE"
    oom_now = ctx.hooks.read_oom(events_path)
    if oom_now is None:
        return "WORKLOAD_OOM_UNAVAILABLE"
    if oom_now[0] > oom_before[0] or oom_now[1] > oom_before[1]:
        return "WORKLOAD_OOM_INCREASED"
    return None


def terminate_owned_child(process: ProcessHandle, hooks: ExecutorHooks) -> bool:
    if not verify_owned_process(process.pid, process.starttime, hooks):
        return False
    if process.poll() is not None:
        return True
    process.terminate()
    try:
        process.wait(timeout=10)
    except Exception:
        if not verify_owned_process(process.pid, process.starttime, hooks):
            return False
        process.kill()
        try:
            process.wait(timeout=5)
        except Exception:
            return False
    return process.poll() is not None


def validate_guest_lock_path(lock_path: Path, *, expected_uid: int) -> str | None:
    if lock_path.is_symlink():
        return "SYMLINK_REFUSED"
    parent = lock_path.parent
    try:
        if parent.is_symlink():
            return "SYMLINK_REFUSED"
        if not parent.is_dir():
            return "GUEST_LOCK_BUSY"
        pst = parent.stat()
        import stat as stat_mod

        if not stat_mod.S_ISDIR(pst.st_mode):
            return "GUEST_LOCK_BUSY"
        if pst.st_uid != expected_uid:
            return "GUEST_LOCK_BUSY"
        if (pst.st_mode & 0o002) or (pst.st_mode & 0o020 and pst.st_gid != os.getgid()):
            return "GUEST_LOCK_BUSY"
    except OSError:
        return "GUEST_LOCK_BUSY"
    if lock_path.exists():
        try:
            lst = lock_path.lstat()
            import stat as stat_mod

            if stat_mod.S_ISLNK(lst.st_mode):
                return "SYMLINK_REFUSED"
        except OSError:
            return "GUEST_LOCK_BUSY"
    return None


def passive_state_lock_readback(
    state_lock_path: Path,
    state_path: Path,
    runs_root: Path,
) -> str | None:
    """Non-blocking shared flock on state.lock, then fail-closed controller read."""
    if state_lock_path.is_symlink() or state_path.is_symlink():
        return "SYMLINK_REFUSED"
    if not state_lock_path.is_file():
        return "STATE_LOCK_UNAVAILABLE"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        import fcntl
        import stat as stat_mod

        fd = os.open(str(state_lock_path), flags)
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            return "STATE_LOCK_UNAVAILABLE"
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return "STATE_LOCK_BUSY"
        return read_controller_runtime_state(state_path, runs_root)
    except OSError:
        return "STATE_LOCK_UNAVAILABLE"
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def run_once_local(ctx: RunContext) -> dict[str, Any]:
    """Execute one bounded guest when hooks provide a live host; never writes controller state."""
    if not _execution_permitted(ctx):
        return _report(
            reason="RUNTIME_NO_START",
            runtime_status="DRAFT_HOLD",
            physical_guest_executed=False,
        )
    pre = ctx.preflight_observation
    if pre is None:
        collected = collect_preflight(ctx)
        if isinstance(collected, dict):
            return collected
        pre = collected
    problem = assess_preflight(pre)
    if problem:
        return _report(reason=problem)
    if not ctx.tools_present:
        return _report(reason="TOOLING_UNAVAILABLE")
    if ctx.qemu_factory is None:
        return _report(reason="EXECUTOR_PORT_NOT_LIVE")
    if PHYSICAL_EXECUTION_ENABLED:
        lock_problem = validate_guest_lock_path(ctx.guest_lock_path, expected_uid=ctx.hooks.uid())
    else:
        lock_problem = None
        try:
            if ctx.guest_lock_path.is_symlink():
                lock_problem = "SYMLINK_REFUSED"
        except OSError:
            lock_problem = "GUEST_LOCK_BUSY"
    if lock_problem:
        return _report(reason=lock_problem)

    lock_cm = ctx.hooks.acquire_guest_lock or _noop_lock
    try:
        lock_iter = lock_cm(ctx.guest_lock_path)
    except GuestLockBusy:
        return _report(reason="GUEST_LOCK_BUSY")
    if not hasattr(lock_iter, "__enter__"):
        return _report(reason="GUEST_LOCK_BUSY")

    nonce = secrets.token_hex(16)
    work_root = make_private_work_root(ctx.hooks)

    overlay = work_root / "guest.qcow2"
    seed = work_root / "seed.img"
    user_data = work_root / "user-data"
    serial_path = work_root / "serial.log"
    manifest_path = work_root / "ownership.json"

    argv = fixed_qemu_argv(overlay, seed, serial_path)
    if argv is None:
        retained = not cleanup_work_root(work_root)
        return _report(reason="ARGV_OR_PATH_REFUSED", evidence_retained=retained)

    manifest_path.write_text(
        json.dumps(
            {
                "marker": MARKER,
                "nonce": nonce,
                "overlay": str(overlay),
                "serial": str(serial_path),
                "base_sha512": EXPECTED_BASE_SHA512,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    started = ctx.hooks.now()
    process: ProcessHandle | None = None
    peak_rss = 0
    balloon_baseline = pre.balloon_inflate[-1]
    mem_during: list[int] = []
    evidence_path = work_root
    try:
        with lock_iter:
            if ctx.hooks.recheck_under_guest_lock is not None:
                again = ctx.hooks.recheck_under_guest_lock(ctx)
                if again:
                    return _report(reason=again, evidence_retained=True)
            elif PHYSICAL_EXECUTION_ENABLED:
                again = passive_state_lock_readback(
                    ctx.state_lock_path, ctx.state_path, ctx.runs_root
                )
            else:
                again = read_controller_runtime_state(ctx.state_path, ctx.runs_root)
            if again:
                return _report(reason=again, evidence_retained=True)
            if ctx.hooks.prepare_guest_artifacts is not None:
                prep_error = ctx.hooks.prepare_guest_artifacts(
                    ctx, work_root, overlay, seed, user_data, serial_path, nonce
                )
                if prep_error is not None:
                    return _report(
                        reason=prep_error,
                        evidence_retained=not cleanup_work_root(work_root),
                    )
            elif not user_data.exists():
                user_data.write_text(build_cloud_config(nonce), encoding="utf-8")
                os.chmod(user_data, 0o600)
            process = ctx.qemu_factory(argv)
            if not verify_owned_process(process.pid, process.starttime, ctx.hooks):
                return _report(reason="CHILD_OWNERSHIP_UNCERTAIN", evidence_retained=True)
            while ctx.hooks.now() - started < TIMEOUT_SECONDS:
                if not verify_owned_process(process.pid, process.starttime, ctx.hooks):
                    return _report(reason="CHILD_OWNERSHIP_UNCERTAIN", evidence_retained=True)
                rss = read_proc_rss_kib(process.pid, ctx.hooks)
                if rss is not None:
                    peak_rss = max(peak_rss, rss)
                if ctx.hooks.workload_host_check is not None:
                    host_problem = ctx.hooks.workload_host_check()
                else:
                    host_problem = sample_workload_host_telemetry(
                        ctx,
                        mem_floor_mib=RESEARCH_FLOOR_MIB,
                        balloon_baseline=balloon_baseline,
                        oom_before=pre.oom_before,
                        memory_events_path=pre.memory_events_path,
                    )
                if host_problem:
                    if not terminate_owned_child(process, ctx.hooks):
                        return _report(reason="CHILD_TERMINATION_UNCERTAIN", evidence_retained=True)
                    return _report(
                        reason=host_problem,
                        evidence_retained=not cleanup_work_root(evidence_path),
                        physical_guest_executed=True,
                    )
                sample = _read_mem_mib(ctx.meminfo_path)
                if sample is not None:
                    mem_during.append(sample)
                if process.poll() is not None:
                    break
                ctx.hooks.sleep(0.15)
            if process.poll() is None:
                if not terminate_owned_child(process, ctx.hooks):
                    return _report(reason="CHILD_TERMINATION_UNCERTAIN", evidence_retained=True)
                return _report(
                    reason="GUEST_TIMEOUT",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )

            events_path = Path(pre.memory_events_path)
            oom_after = ctx.hooks.read_oom(events_path)
            if oom_after is None:
                return _report(
                    reason="OOM_COUNTER_UNAVAILABLE",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )
            if oom_after[0] > pre.oom_before[0] or oom_after[1] > pre.oom_before[1]:
                return _report(
                    reason="OOM_EVENT_INCREASED",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )

            serial_text = read_serial_tail_text(serial_path)
            if serial_text is None:
                return _report(
                    reason="SERIAL_UNAVAILABLE",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )
            marker_problem = assess_serial_success(serial_text, nonce)
            if marker_problem:
                return _report(
                    reason=marker_problem,
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )
            if peak_rss < MIN_QEMU_RSS_RESEARCH_KIB:
                return _report(
                    reason="QEMU_RSS_INSUFFICIENT",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )
            if process.poll() != 0:
                return _report(
                    reason="QEMU_NONZERO_EXIT",
                    evidence_retained=not cleanup_work_root(evidence_path),
                    physical_guest_executed=True,
                )

            cleaned = cleanup_work_root(evidence_path)
            return _report(
                classification="LOCAL_SYNTHETIC_MEASURED_NOT_AUTHORIZED",
                reason="OFFLINE_SYNTHETIC_COMPLETE",
                physical_guest_executed=True,
                peak_qemu_rss_kib=peak_rss,
                oom_delta=oom_after[0] - pre.oom_before[0],
                oom_kill_delta=oom_after[1] - pre.oom_before[1],
                minimum_memavailable_mib=min(pre.mem_available_mib + mem_during),
                rss_research_threshold_kib=MIN_QEMU_RSS_RESEARCH_KIB,
                nonce_bound=nonce,
                cleanup_complete=cleaned,
            )
    except GuestLockBusy:
        return _report(reason="GUEST_LOCK_BUSY", evidence_retained=not cleanup_work_root(evidence_path))
    except Exception:
        if process is not None:
            with contextlib.suppress(Exception):
                terminate_owned_child(process, ctx.hooks)
        return _report(reason="EXECUTION_UNCERTAIN", evidence_retained=True)


def read_proc_rss_kib(pid: int, hooks: ExecutorHooks) -> int | None:
    if hooks.read_proc_status is not None:
        return hooks.read_proc_status(pid)
    status_path = Path(f"/proc/{pid}/status")
    try:
        for line in status_path.read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        return None
    return None


def cleanup_work_root(path: Path) -> bool:
    """Remove owned regular files only; return True when fully removed."""
    try:
        if not path.exists():
            return True
        if path.is_symlink():
            return False
        for child in path.iterdir():
            if child.is_symlink():
                return False
            if child.is_file():
                child.unlink(missing_ok=True)
            else:
                return False
        path.rmdir()
        return not path.exists()
    except OSError:
        return path.exists() is False


def wire_linux_executor(ctx: RunContext) -> None:
    """Bind live subprocess helpers on Linux only when physical execution is admitted."""
    if not PHYSICAL_EXECUTION_ENABLED:
        ctx.tools_present = False
        ctx.qemu_factory = None
        ctx.hooks.prepare_guest_artifacts = None
        ctx.hooks.acquire_guest_lock = None
        return
    import shutil
    import subprocess

    tools = ("qemu-img", "cloud-localds", "qemu-system-x86_64")
    if any(shutil.which(name) is None for name in tools):
        ctx.tools_present = False
        return

    def _prepare(
        run_ctx: RunContext,
        work_root: Path,
        overlay: Path,
        seed: Path,
        user_data_path: Path,
        serial_path: Path,
        nonce_hex: str,
    ) -> str | None:
        del work_root, serial_path
        try:
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    "-b",
                    str(run_ctx.base_image_path),
                    str(overlay),
                    "8G",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            user_data_path.write_text(build_cloud_config(nonce_hex), encoding="utf-8")
            os.chmod(user_data_path, 0o600)
            subprocess.run(
                ["cloud-localds", str(seed), str(user_data_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError):
            return "DISK_PREP_FAILED"
        return None

    @contextlib.contextmanager
    def _guest_lock(path: Path) -> Iterator[None]:
        import fcntl
        import stat as stat_mod

        problem = validate_guest_lock_path(path, expected_uid=ctx.hooks.uid())
        if problem:
            raise GuestLockBusy(problem)
        if not path.parent.is_dir():
            raise GuestLockBusy
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat_mod.S_ISREG(st.st_mode):
                raise GuestLockBusy
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            os.close(fd)
            raise GuestLockBusy from exc
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    class _OwnedPopen:
        def __init__(self, popen: subprocess.Popen[bytes]) -> None:
            self._popen = popen
            self.pid = popen.pid or -1
            ident = read_proc_stat_identity(self.pid, expected_uid=os.getuid())
            self.starttime = ident[1] if ident else -1

        def poll(self) -> int | None:
            return self._popen.poll()

        def terminate(self) -> None:
            self._popen.terminate()

        def kill(self) -> None:
            self._popen.kill()

        def wait(self, timeout: float | None = None) -> int:
            return self._popen.wait(timeout=timeout)

    def _popen(argv: list[str]) -> ProcessHandle:
        popen = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return _OwnedPopen(popen)

    ctx.hooks.prepare_guest_artifacts = _prepare
    ctx.hooks.acquire_guest_lock = _guest_lock
    ctx.qemu_factory = _popen
    ctx.tools_present = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(RUN_ONCE_FLAG, action="store_true", dest="run_once_local")
    args, extras = parser.parse_known_args(argv)
    if extras or not args.run_once_local:
        print(json.dumps(_report(reason="CLI_REFUSED"), sort_keys=True, separators=(",", ":")))
        return 2
    if not PHYSICAL_EXECUTION_ENABLED:
        print(
            json.dumps(
                _report(
                    reason="RUNTIME_NO_START",
                    runtime_status="DRAFT_HOLD",
                    physical_guest_executed=False,
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    if sys.platform != "linux":
        print(json.dumps(_report(reason="PLATFORM_REFUSED"), sort_keys=True, separators=(",", ":")))
        return 2
    controller = Path(__file__).with_name("dragonfly_jit.py")
    data_root = Path.home() / ".local/share/ldw-jit"
    state_root = Path.home() / ".local/state/ldw-dragonfly-jit"
    ctx = RunContext(
        hooks=ExecutorHooks(),
        guest_lock_path=state_root / GUEST_LOCK_NAME,
        state_lock_path=state_root / "state.lock",
        controller_path=controller,
        base_image_path=data_root / "base" / BASE_FILENAME,
        state_path=state_root / "status.json",
        runs_root=state_root / "runs",
    )
    wire_linux_executor(ctx)
    report = run_once_local(ctx)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("classification") == "LOCAL_SYNTHETIC_MEASURED_NOT_AUTHORIZED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
