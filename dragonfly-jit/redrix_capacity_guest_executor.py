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
MIN_QEMU_RSS_KIB = 256 * 1024
GUEST_LOCK_NAME = "guest.lock"
ALLOWED_CONTROLLER_STATES = frozenset({"STOPPED", "AVAILABLE"})
RUN_ONCE_FLAG = "--run-once-local"


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
    """Resolve the calling process leaf memory.events without assuming root cgroup."""
    try:
        lines = cgroup_file.read_text(encoding="ascii").splitlines()[:max_lines]
    except OSError:
        return None
    rel: str | None = None
    for line in lines:
        if not line or line.count(":") < 2:
            continue
        _id, _controllers, path = line.split(":", 2)
        if path in ("", "/"):
            rel = path.lstrip("/") or None
            continue
        rel = path.lstrip("/")
        if rel:
            break
    if rel is None:
        events = cgroup_root / "memory.events"
        return events if events.is_file() else None
    candidate = cgroup_root / rel / "memory.events"
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None
    resolved_s = str(resolved).replace("\\", "/")
    root_s = str(cgroup_root.resolve(strict=False)).replace("\\", "/")
    if not resolved_s.startswith(root_s + "/") and resolved_s != root_s:
        return None
    if ".." in rel.split("/"):
        return None
    return candidate if candidate.is_file() else None


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


def guest_workload_script(nonce_hex: str) -> str:
    return (
        "import hashlib,time\n"
        f"NONCE={nonce_hex!r}\n"
        f"MARKER={SUCCESS_PREFIX!r}\n"
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
        "print(MARKER+' nonce='+NONCE)\n"
    )


def build_cloud_config(nonce_hex: str) -> str:
    script = guest_workload_script(nonce_hex).replace("\n", "\\n")
    return (
        "#cloud-config\n"
        "hostname: ldw-redrix-capacity-exec\n"
        "ssh_pwauth: false\n"
        "disable_root: true\n"
        "network:\n"
        "  config: disabled\n"
        "runcmd:\n"
        f"  - [ python3, -c, \"{script}\" ]\n"
        "power_state:\n"
        "  delay: now\n"
        "  mode: poweroff\n"
        "  message: LDW offline capacity executor complete\n"
        "  timeout: 60\n"
        "  condition: true\n"
    )


def parse_success_line(serial_text: str, nonce_hex: str) -> bool:
    expected = f"{SUCCESS_PREFIX} nonce={nonce_hex}"
    matches = [line.strip() for line in serial_text.splitlines() if line.strip() == expected]
    return len(matches) == 1


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
    if len(obs.balloon_inflate) != len(obs.mem_available_mib):
        return "BALLOON_UNAVAILABLE"
    for idx in range(1, len(obs.balloon_inflate)):
        if obs.balloon_inflate[idx] < obs.balloon_inflate[idx - 1]:
            return "BALLOON_NONMONOTONIC"
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
    try:
        state = json.loads(ctx.state_path.read_text(encoding="utf-8"))
        controller_state = str(state.get("state", "HOLD"))
        qemu_pid = state.get("qemu_pid")
    except (OSError, json.JSONDecodeError):
        controller_state = "STOPPED"
        qemu_pid = None
    qemu_present = bool(qemu_pid)
    try:
        residue = len([p for p in ctx.runs_root.iterdir() if p.is_dir() and not p.is_symlink()])
    except OSError:
        residue = -1
    if residue < 0:
        return _report(reason="CONTROLLER_RUNS_RESIDUE")
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


def run_once_local(ctx: RunContext) -> dict[str, Any]:
    """Execute one bounded guest when hooks provide a live host; never writes controller state."""
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
    try:
        if ctx.guest_lock_path.exists() and ctx.guest_lock_path.is_symlink():
            return _report(reason="SYMLINK_REFUSED")
    except OSError:
        return _report(reason="GUEST_LOCK_BUSY")

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
        cleanup_work_root(work_root)
        return _report(reason="ARGV_OR_PATH_REFUSED", evidence_retained=True)

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
    try:
        with lock_iter:
            if ctx.hooks.prepare_guest_artifacts is not None:
                prep_error = ctx.hooks.prepare_guest_artifacts(
                    ctx, work_root, overlay, seed, user_data, serial_path, nonce
                )
                if prep_error is not None:
                    cleanup_work_root(work_root)
                    return _report(reason=prep_error, evidence_retained=True)
            elif not user_data.exists():
                user_data.write_text(build_cloud_config(nonce), encoding="utf-8")
                os.chmod(user_data, 0o600)
            process = ctx.qemu_factory(argv)
            while ctx.hooks.now() - started < TIMEOUT_SECONDS:
                rss = read_proc_rss_kib(process.pid, ctx.hooks)
                if rss is not None:
                    peak_rss = max(peak_rss, rss)
                if process.poll() is not None:
                    break
                ctx.hooks.sleep(0.15)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except Exception:
                    process.kill()
                    process.wait(timeout=5)
                cleanup_work_root(work_root)
                return _report(reason="GUEST_TIMEOUT", evidence_retained=True, physical_guest_executed=True)

            events_path = Path(pre.memory_events_path)
            oom_after = ctx.hooks.read_oom(events_path)
            if oom_after is None:
                cleanup_work_root(work_root)
                return _report(reason="OOM_COUNTER_UNAVAILABLE", evidence_retained=True, physical_guest_executed=True)

            serial_text = ""
            try:
                serial_text = serial_path.read_text(encoding="utf-8", errors="replace")[:65536]
            except OSError:
                cleanup_work_root(work_root)
                return _report(reason="SERIAL_UNAVAILABLE", evidence_retained=True, physical_guest_executed=True)

            if not parse_success_line(serial_text, nonce):
                cleanup_work_root(work_root)
                return _report(reason="SUCCESS_MARKER_MISSING", evidence_retained=True, physical_guest_executed=True)
            if peak_rss < MIN_QEMU_RSS_KIB:
                cleanup_work_root(work_root)
                return _report(reason="QEMU_RSS_INSUFFICIENT", evidence_retained=True, physical_guest_executed=True)
            if process.poll() != 0:
                cleanup_work_root(work_root)
                return _report(reason="QEMU_NONZERO_EXIT", evidence_retained=True, physical_guest_executed=True)

            cleanup_work_root(work_root)
            return _report(
                classification="LOCAL_SYNTHETIC_MEASURED_NOT_AUTHORIZED",
                reason="OFFLINE_SYNTHETIC_COMPLETE",
                physical_guest_executed=True,
                peak_qemu_rss_kib=peak_rss,
                oom_delta=max(0, oom_after[0] - pre.oom_before[0]),
                oom_kill_delta=max(0, oom_after[1] - pre.oom_before[1]),
                minimum_memavailable_mib=min(pre.mem_available_mib),
                nonce_bound=nonce,
            )
    except GuestLockBusy:
        cleanup_work_root(work_root)
        return _report(reason="GUEST_LOCK_BUSY")
    except Exception:
        if process is not None:
            with contextlib.suppress(Exception):
                if process.poll() is None:
                    process.kill()
        cleanup_work_root(work_root)
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


def cleanup_work_root(path: Path) -> None:
    try:
        if not path.exists():
            return
        for child in sorted(path.iterdir(), key=lambda p: p.name, reverse=True):
            if child.is_symlink():
                continue
            if child.is_file():
                child.unlink(missing_ok=True)
        path.rmdir()
    except OSError:
        pass


def wire_linux_executor(ctx: RunContext) -> None:
    """Bind live subprocess helpers on Linux only; author task does not invoke main."""
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

        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise GuestLockBusy from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()

    def _popen(argv: list[str]) -> ProcessHandle:
        return subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

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
