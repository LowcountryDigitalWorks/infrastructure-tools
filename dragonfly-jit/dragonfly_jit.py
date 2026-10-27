#!/usr/bin/env python3
"""Fail-closed local lifecycle foundation for CI-RUNNER-DRAGONFLY-JIT-001.

This module deliberately contains no GitHub API, runner registration, queue polling,
credential handling, or workflow-routing logic. LDW01 remains the control plane.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
STATE_SCHEMA = 1
MANIFEST_SCHEMA = 1
BASE_FILENAME = "debian-13-genericcloud-amd64.qcow2"
BASE_SHA512 = (
    "3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538"
    "d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e"
)
ALLOWED_STATES = {"STOPPED", "AVAILABLE", "RUNNING", "DRAINING", "HOLD", "FAILED"}
GUEST_CPUS = 2
GUEST_MEMORY_MIB = 2048
MIN_RESERVE_MIB = 8192
MIN_FREE_DISK_GIB = 16
MAX_LOAD_FRACTION = 0.70
SMOKE_TIMEOUT_SECONDS = 180
PR_SET_PDEATHSIG = 1


class DragonflyError(RuntimeError):
    pass


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _xdg_dir(env_name: str, fallback: str) -> Path:
    value = os.environ.get(env_name)
    if value:
        return Path(value).expanduser()
    return Path.home() / fallback


def default_data_root() -> Path:
    return _xdg_dir("XDG_DATA_HOME", ".local/share") / "ldw-jit"


def default_state_root() -> Path:
    return _xdg_dir("XDG_STATE_HOME", ".local/state") / "ldw-dragonfly-jit"


def _assert_no_symlink(path: Path, *, allow_missing_leaf: bool = False) -> None:
    path = path.expanduser().absolute()
    cursor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        is_leaf = index == len(parts) - 1
        if not cursor.exists() and not cursor.is_symlink():
            if is_leaf and allow_missing_leaf:
                return
            continue
        if cursor.is_symlink():
            raise DragonflyError(f"SYMLINK_PATH_REFUSED:{cursor}")


def _assert_owned_child(root: Path, child: Path) -> Path:
    root_resolved = root.resolve(strict=True)
    child_abs = child.expanduser().absolute()
    _assert_no_symlink(child_abs, allow_missing_leaf=not child_abs.exists())
    try:
        child_resolved = child_abs.resolve(strict=child_abs.exists())
    except FileNotFoundError:
        child_resolved = child_abs.parent.resolve(strict=True) / child_abs.name
    if child_resolved == root_resolved or root_resolved not in child_resolved.parents:
        raise DragonflyError("PATH_OUTSIDE_OWNED_ROOT")
    return child_resolved


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_reason(reason: object) -> bool:
    return (
        isinstance(reason, str)
        and reason.isupper()
        and len(reason) <= 64
        and reason.replace("_", "").isalnum()
    )


def _validate_state_payload(value: dict) -> None:
    if value.get("schema") != STATE_SCHEMA or value.get("marker") != MARKER:
        raise DragonflyError("STATE_CONTRACT_INVALID")
    state = value.get("state")
    if state not in ALLOWED_STATES:
        raise DragonflyError("STATE_VALUE_INVALID")
    allowed = {"schema", "marker", "state", "updated_at", "run_id", "qemu_pid", "reason"}
    if set(value) - allowed:
        raise DragonflyError("STATE_FIELDS_INVALID")
    updated_at = value.get("updated_at")
    if updated_at is not None and not isinstance(updated_at, str):
        raise DragonflyError("STATE_TIMESTAMP_INVALID")
    run_id = value.get("run_id")
    if run_id is not None:
        if not isinstance(run_id, str):
            raise DragonflyError("STATE_RUN_ID_INVALID")
        try:
            uuid.UUID(run_id)
        except ValueError as exc:
            raise DragonflyError("STATE_RUN_ID_INVALID") from exc
    qemu_pid = value.get("qemu_pid")
    if qemu_pid is not None and (not isinstance(qemu_pid, int) or isinstance(qemu_pid, bool) or qemu_pid <= 0):
        raise DragonflyError("STATE_PID_INVALID")
    if qemu_pid is not None and run_id is None:
        raise DragonflyError("STATE_IDENTITY_INVALID")
    reason = value.get("reason")
    if reason is not None and not _valid_reason(reason):
        raise DragonflyError("STATE_REASON_INVALID")
    if state in {"STOPPED", "AVAILABLE"} and (run_id is not None or qemu_pid is not None):
        raise DragonflyError("STATE_IDENTITY_INVALID")
    if state == "RUNNING" and (run_id is None or qemu_pid is None):
        raise DragonflyError("STATE_IDENTITY_INVALID")
    if state == "DRAINING" and ((run_id is None) != (qemu_pid is None)):
        raise DragonflyError("STATE_IDENTITY_INVALID")


def _atomic_json(path: Path, payload: dict) -> None:
    _assert_no_symlink(path.parent, allow_missing_leaf=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink(path.parent)
    _assert_no_symlink(path, allow_missing_leaf=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def _read_json(path: Path) -> dict:
    _assert_no_symlink(path)
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise DragonflyError("JSON_OBJECT_REQUIRED")
    return value


def _pid_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_pidfile(path: Path) -> int | None:
    if not path.exists() and not path.is_symlink():
        return None
    _assert_no_symlink(path)
    text = path.read_text(encoding="ascii").strip()
    if not text.isdigit():
        raise DragonflyError("PIDFILE_INVALID")
    pid = int(text)
    if pid <= 0:
        raise DragonflyError("PIDFILE_INVALID")
    return pid


def _set_parent_death_signal() -> None:
    """Linux/Crostini child hook: QEMU must not outlive an abruptly dead controller."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() == 1:
        os.kill(os.getpid(), signal.SIGTERM)


@contextlib.contextmanager
def _file_lock(path: Path, *, blocking: bool = False):
    _assert_no_symlink(path.parent, allow_missing_leaf=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink(path.parent)
    _assert_no_symlink(path, allow_missing_leaf=True)
    handle = path.open("a+")
    try:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(handle.fileno(), flags)
        except BlockingIOError as exc:
            raise DragonflyError("LOCK_BUSY") from exc
        yield handle
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def read_mem_available_mib() -> int:
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    raise DragonflyError("MEMAVAILABLE_UNAVAILABLE")


def read_load_fraction() -> float:
    with open("/proc/loadavg", "r", encoding="utf-8") as handle:
        load1 = float(handle.read().split()[0])
    cpus = os.cpu_count() or 1
    return load1 / cpus


def free_disk_gib(path: Path) -> int:
    usage = shutil.disk_usage(path)
    return usage.free // (1024 ** 3)


def resource_snapshot(path: Path) -> dict:
    return {
        "mem_available_mib": read_mem_available_mib(),
        "load_fraction": round(read_load_fraction(), 3),
        "free_disk_gib": free_disk_gib(path),
        "visible_cpus": os.cpu_count() or 1,
    }


def assert_admission(snapshot: dict) -> None:
    required_mem = GUEST_MEMORY_MIB + MIN_RESERVE_MIB
    if snapshot["mem_available_mib"] < required_mem:
        raise DragonflyError("CAPACITY_MEMORY")
    if snapshot["free_disk_gib"] < MIN_FREE_DISK_GIB:
        raise DragonflyError("CAPACITY_DISK")
    if snapshot["load_fraction"] > MAX_LOAD_FRACTION:
        raise DragonflyError("CAPACITY_CPU")


class Controller:
    def __init__(self, *, data_root: Path | None = None, state_root: Path | None = None):
        self.data_root = (data_root or default_data_root()).expanduser().absolute()
        self.state_root = (state_root or default_state_root()).expanduser().absolute()
        self.base_path = self.data_root / "base" / BASE_FILENAME
        self.runs_root = self.state_root / "runs"
        self.state_path = self.state_root / "status.json"
        self.state_lock_path = self.state_root / "state.lock"
        self.guest_lock_path = self.state_root / "guest.lock"

    def ensure_roots(self) -> None:
        _assert_no_symlink(self.state_root, allow_missing_leaf=True)
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _assert_no_symlink(self.state_root)
        _assert_no_symlink(self.runs_root, allow_missing_leaf=True)
        self.runs_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _assert_no_symlink(self.runs_root)
        os.chmod(self.state_root, 0o700)
        os.chmod(self.runs_root, 0o700)

    def _run_dirs(self) -> list[Path]:
        entries = list(self.runs_root.iterdir())
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                raise DragonflyError("RUN_ROOT_CONTAMINATED")
        return entries

    def verify_base(self) -> dict:
        if not self.base_path.is_file():
            raise DragonflyError("VERIFIED_BASE_REQUIRED")
        _assert_no_symlink(self.base_path)
        actual = sha512_file(self.base_path)
        if actual != BASE_SHA512:
            raise DragonflyError("BASE_SHA512_MISMATCH")
        return {"filename": BASE_FILENAME, "sha512": BASE_SHA512}

    def read_state(self) -> dict:
        if not self.state_path.exists():
            return {
                "schema": STATE_SCHEMA,
                "marker": MARKER,
                "state": "STOPPED",
                "updated_at": None,
                "run_id": None,
                "qemu_pid": None,
                "reason": None,
            }
        value = _read_json(self.state_path)
        _validate_state_payload(value)
        return value

    def write_state(self, state: str, *, run_id: str | None = None,
                    qemu_pid: int | None = None, reason: str | None = None) -> dict:
        payload = {
            "schema": STATE_SCHEMA,
            "marker": MARKER,
            "state": state,
            "updated_at": _utc_now(),
            "run_id": run_id,
            "qemu_pid": qemu_pid,
            "reason": reason,
        }
        _validate_state_payload(payload)
        _atomic_json(self.state_path, payload)
        return payload

    def _guest_lock_available(self) -> bool:
        try:
            with _file_lock(self.guest_lock_path):
                return True
        except DragonflyError as exc:
            if str(exc) == "LOCK_BUSY":
                return False
            raise

    def start(self) -> dict:
        self.ensure_roots()
        self.verify_base()
        snapshot = resource_snapshot(self.state_root)
        assert_admission(snapshot)
        with _file_lock(self.state_lock_path):
            current = self.read_state()
            if current["state"] in {"FAILED", "HOLD"}:
                raise DragonflyError("RECOVERY_REQUIRED")
            if self._run_dirs():
                raise DragonflyError("STALE_RUN_STATE_REFUSED")
            if not self._guest_lock_available() or current["state"] in {"RUNNING", "DRAINING"}:
                raise DragonflyError("ACTIVE_GUEST_REFUSED")
            return self.write_state("AVAILABLE")

    def drain(self) -> dict:
        self.ensure_roots()
        with _file_lock(self.state_lock_path):
            current = self.read_state()
            if current["state"] in {"FAILED", "HOLD"}:
                return current
            if current["state"] in {"RUNNING", "DRAINING"}:
                return self.write_state(
                    "DRAINING",
                    run_id=current.get("run_id"),
                    qemu_pid=current.get("qemu_pid"),
                    reason="DRAIN_REQUESTED",
                )
            if current["state"] == "AVAILABLE" and not self._guest_lock_available():
                return self.write_state("DRAINING", reason="DRAIN_REQUESTED")
            return self.write_state("STOPPED")

    def status(self) -> dict:
        self.ensure_roots()
        current = self.read_state()
        try:
            residue_count = len(self._run_dirs())
        except DragonflyError:
            residue_count = -1
            current = dict(current)
            current["state"] = "HOLD"
            current["reason"] = "RUN_ROOT_CONTAMINATED"
        if current.get("qemu_pid") and not _pid_alive(current["qemu_pid"]):
            current = dict(current)
            current["reason"] = "PID_NOT_RUNNING"
            if current["state"] in {"RUNNING", "DRAINING"}:
                current["state"] = "HOLD"
        if residue_count > 0 and current["state"] in {"STOPPED", "AVAILABLE"}:
            current = dict(current)
            current["state"] = "HOLD"
            current["reason"] = "STALE_RUN_STATE"
        snapshot = resource_snapshot(self.state_root)
        return {
            "marker": MARKER,
            "state": current["state"],
            "updated_at": current.get("updated_at"),
            "run_id": current.get("run_id"),
            "qemu_pid": current.get("qemu_pid"),
            "reason": current.get("reason"),
            "residue_count": residue_count,
            "base_present": self.base_path.is_file() and not self.base_path.is_symlink(),
            **snapshot,
        }

    def _new_run(self) -> tuple[str, Path, Path, Path, Path, Path, Path]:
        run_id = str(uuid.uuid4())
        run_dir = self.runs_root / run_id
        _assert_owned_child(self.runs_root, run_dir)
        run_dir.mkdir(mode=0o700)
        overlay = run_dir / "guest.qcow2"
        seed = run_dir / "seed.img"
        user_data = run_dir / "user-data"
        pidfile = run_dir / "qemu.pid"
        manifest = run_dir / "ownership.json"
        return run_id, run_dir, overlay, seed, user_data, pidfile, manifest

    @staticmethod
    def _smoke_user_data() -> str:
        return """#cloud-config
hostname: ldw-dragonfly-smoke
manage_etc_hosts: true
timezone: UTC
ssh_pwauth: false
disable_root: true
runcmd:
  - [ sh, -c, 'systemctl mask --now ssh.service || true' ]
power_state:
  delay: now
  mode: poweroff
  message: 'LDW disposable smoke complete'
  timeout: 120
  condition: true
"""

    def _write_manifest(self, run_id: str, run_dir: Path, overlay: Path, seed: Path,
                        pidfile: Path, qemu_pid: int | None = None) -> None:
        payload = {
            "schema": MANIFEST_SCHEMA,
            "marker": MARKER,
            "run_id": run_id,
            "run_dir": str(run_dir),
            "overlay": str(overlay),
            "seed": str(seed),
            "pidfile": str(pidfile),
            "base_filename": BASE_FILENAME,
            "base_sha512": BASE_SHA512,
            "qemu_pid": qemu_pid,
        }
        _atomic_json(run_dir / "ownership.json", payload)

    def _validate_manifest(self, run_dir: Path) -> dict:
        _assert_owned_child(self.runs_root, run_dir)
        manifest_path = run_dir / "ownership.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise DragonflyError("OWNERSHIP_MANIFEST_REQUIRED")
        value = _read_json(manifest_path)
        required = {
            "schema", "marker", "run_id", "run_dir", "overlay", "seed", "pidfile",
            "base_filename", "base_sha512", "qemu_pid"
        }
        if set(value) != required:
            raise DragonflyError("OWNERSHIP_FIELDS_INVALID")
        if value["schema"] != MANIFEST_SCHEMA or value["marker"] != MARKER:
            raise DragonflyError("OWNERSHIP_CONTRACT_INVALID")
        if value["base_filename"] != BASE_FILENAME or value["base_sha512"] != BASE_SHA512:
            raise DragonflyError("OWNERSHIP_BASE_MISMATCH")
        try:
            uuid.UUID(value["run_id"])
        except (ValueError, TypeError) as exc:
            raise DragonflyError("OWNERSHIP_RUN_ID_INVALID") from exc
        if Path(value["run_dir"]).resolve(strict=True) != run_dir.resolve(strict=True):
            raise DragonflyError("OWNERSHIP_RUN_DIR_MISMATCH")
        for key, expected_name in (
            ("overlay", "guest.qcow2"), ("seed", "seed.img"), ("pidfile", "qemu.pid")
        ):
            candidate = Path(value[key])
            if candidate.name != expected_name:
                raise DragonflyError("OWNERSHIP_FILE_MISMATCH")
            _assert_owned_child(run_dir, candidate)
        pid = value["qemu_pid"]
        if pid is not None and (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0):
            raise DragonflyError("OWNERSHIP_PID_INVALID")
        return value

    def _cleanup_owned_run(self, run_dir: Path) -> None:
        manifest = self._validate_manifest(run_dir)
        manifest_pid = manifest.get("qemu_pid")
        pidfile_pid = _read_pidfile(Path(manifest["pidfile"]))
        if _pid_alive(manifest_pid) or _pid_alive(pidfile_pid):
            raise DragonflyError("LIVE_GUEST_CLEANUP_REFUSED")
        allowed_names = {"ownership.json", "guest.qcow2", "seed.img", "user-data", "qemu.pid"}
        existing = {entry.name for entry in run_dir.iterdir()}
        unknown = existing - allowed_names
        if unknown:
            raise DragonflyError("UNKNOWN_RUN_ARTIFACT_REFUSED")
        for name in ("guest.qcow2", "seed.img", "user-data", "qemu.pid", "ownership.json"):
            path = run_dir / name
            if path.exists() or path.is_symlink():
                _assert_owned_child(run_dir, path)
                if path.is_symlink():
                    raise DragonflyError("SYMLINK_ARTIFACT_REFUSED")
                path.unlink()
        run_dir.rmdir()

    def smoke(self) -> dict:
        self.ensure_roots()
        self.verify_base()
        assert_admission(resource_snapshot(self.state_root))
        for tool in ("qemu-img", "cloud-localds", "qemu-system-x86_64"):
            if shutil.which(tool) is None:
                raise DragonflyError(f"TOOL_REQUIRED_{tool.upper().replace('-', '_')}")

        with _file_lock(self.guest_lock_path):
            with _file_lock(self.state_lock_path):
                current = self.read_state()
                if current["state"] != "AVAILABLE":
                    raise DragonflyError("HOST_NOT_AVAILABLE")
                if self._run_dirs():
                    raise DragonflyError("STALE_RUN_STATE_REFUSED")

            run_id, run_dir, overlay, seed, user_data, pidfile, _manifest_path = self._new_run()
            result: dict | None = None
            try:
                user_data.write_text(self._smoke_user_data(), encoding="utf-8")
                os.chmod(user_data, 0o600)
                self._write_manifest(run_id, run_dir, overlay, seed, pidfile)

                subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                     str(self.base_path), str(overlay), "8G"],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["cloud-localds", str(seed), str(user_data)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )

                process: subprocess.Popen | None = None
                with _file_lock(self.state_lock_path):
                    current = self.read_state()
                    if current["state"] == "DRAINING":
                        result = {"run_id": run_id, "result": "DRAINED"}
                    elif current["state"] != "AVAILABLE":
                        raise DragonflyError("HOST_STATE_CHANGED")
                    else:
                        command = [
                            "qemu-system-x86_64", "-accel", "kvm", "-machine", "q35",
                            "-cpu", "host", "-smp", str(GUEST_CPUS), "-m", f"{GUEST_MEMORY_MIB}M",
                            "-drive", f"if=virtio,format=qcow2,file={overlay}",
                            "-drive", f"if=virtio,format=raw,readonly=on,file={seed}",
                            "-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0",
                            "-display", "none", "-serial", "none", "-monitor", "none",
                            "-pidfile", str(pidfile), "-no-reboot",
                        ]
                        process = subprocess.Popen(
                            command,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=_set_parent_death_signal,
                        )
                        self._write_manifest(run_id, run_dir, overlay, seed, pidfile, qemu_pid=process.pid)
                        self.write_state("RUNNING", run_id=run_id, qemu_pid=process.pid)

                if process is not None:
                    try:
                        rc = process.wait(timeout=SMOKE_TIMEOUT_SECONDS)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                        raise DragonflyError("SMOKE_TIMEOUT")

                    self._write_manifest(run_id, run_dir, overlay, seed, pidfile, qemu_pid=None)
                    if rc != 0:
                        raise DragonflyError("QEMU_NONZERO_EXIT")
                    result = {"run_id": run_id, "result": "PASS"}
            except Exception:
                with _file_lock(self.state_lock_path):
                    self.write_state("FAILED", reason="SMOKE_FAILED")
                raise
            finally:
                manifest_path = run_dir / "ownership.json"
                if manifest_path.exists():
                    try:
                        self._cleanup_owned_run(run_dir)
                    except DragonflyError:
                        with _file_lock(self.state_lock_path):
                            self.write_state("HOLD", run_id=run_id, reason="CLEANUP_UNCERTAIN")
                        raise

            if result is None:
                raise DragonflyError("SMOKE_RESULT_MISSING")
            with _file_lock(self.state_lock_path):
                current = self.read_state()
                if result["result"] == "DRAINED" or current["state"] == "DRAINING":
                    self.write_state("STOPPED")
                elif current["state"] == "RUNNING":
                    self.write_state("AVAILABLE")
                else:
                    raise DragonflyError("POST_SMOKE_STATE_INVALID")
            return result

    def recover(self) -> dict:
        self.ensure_roots()
        with _file_lock(self.guest_lock_path):
            with _file_lock(self.state_lock_path):
                current = self.read_state()
                if _pid_alive(current.get("qemu_pid")):
                    self.write_state(
                        "HOLD",
                        run_id=current.get("run_id"),
                        qemu_pid=current.get("qemu_pid"),
                        reason="RECOVERY_LIVE_STATE",
                    )
                    raise DragonflyError("LIVE_STATE_PID_REFUSED")
            try:
                run_dirs = self._run_dirs()
                if len(run_dirs) > 1:
                    raise DragonflyError("MULTIPLE_RUN_DIRS")
                if run_dirs:
                    self._cleanup_owned_run(run_dirs[0])
            except DragonflyError:
                with _file_lock(self.state_lock_path):
                    self.write_state("HOLD", reason="RECOVERY_UNCERTAIN")
                raise
            with _file_lock(self.state_lock_path):
                current = self.read_state()
                if current["state"] in {"RUNNING", "DRAINING", "FAILED", "HOLD"}:
                    state = self.write_state("STOPPED", reason="RECOVERED")
                else:
                    state = current
            return {"result": "CLEAN", "state": state["state"]}


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LDW Dragonfly disposable KVM host controller")
    parser.add_argument("--data-root", type=Path, default=None)
    parser.add_argument("--state-root", type=Path, default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("verify-base", "start", "drain", "status", "smoke", "recover"):
        sub.add_parser(name)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    controller = Controller(data_root=args.data_root, state_root=args.state_root)
    try:
        if args.command == "verify-base":
            _emit(controller.verify_base())
        elif args.command == "start":
            _emit(controller.start())
        elif args.command == "drain":
            _emit(controller.drain())
        elif args.command == "status":
            _emit(controller.status())
        elif args.command == "smoke":
            _emit(controller.smoke())
        elif args.command == "recover":
            _emit(controller.recover())
        else:
            raise DragonflyError("COMMAND_INVALID")
        return 0
    except DragonflyError as exc:
        print(f"ERROR:{exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError:
        print("ERROR:SUBPROCESS_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
