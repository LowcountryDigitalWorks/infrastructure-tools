#!/usr/bin/env python3
"""Manual, read-only Crostini R2 health observation; never admits CI or repairs hosts.

This is NOT a pre-login ChromeOS detector, scheduler, recovery watchdog, network
probe, privileged checker, or GitHub/runner controller. It emits no tailnet, PID,
run ID, SSH key, health-detail string, or other operator-private content.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time

MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
DEFAULT_SAMPLES = 3


def _command(args: list[str]) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5,
                                check=False)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    if result.returncode != 0 or len(result.stdout) > 1_000_000:
        return None
    return result.stdout.strip()


def _systemctl(action: str, service: str) -> bool:
    # is-active/is-enabled are read-only; never issue start/restart/enable.
    return _command(["systemctl", action, "--quiet", service]) == ""


def _has_symlink_component(path: Path) -> bool:
    """Reject a symlink in ANY path component, not only the leaf."""
    return any(component.is_symlink() for component in (path, *path.parents))


def _safe_json_file(path: Path) -> dict | None:
    """Bounded Linux-only read through no-follow directory/file descriptors.

    Opening each path component with O_DIRECTORY|O_NOFOLLOW prevents a
    TOCTOU substitution of a parent directory with a symlink. O_NONBLOCK
    prevents blocking on a swapped-in FIFO. No writable file is opened.
    """
    if os.name != "posix" or not path.is_absolute():
        return None
    needed = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in needed):
        return None
    directory_fd = None
    file_fd = None
    try:
        parts = path.parts
        if len(parts) < 2 or parts[0] != os.sep or any(
            part in ("", ".", "..") for part in parts[1:]
        ):
            return None
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        directory_fd = os.open(os.sep, directory_flags)
        for component in parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        entry = os.fstat(file_fd)
        if not stat.S_ISREG(entry.st_mode) or not 0 < entry.st_size <= 16_384:
            return None
        with os.fdopen(file_fd, "rb") as stream:
            file_fd = None
            raw = stream.read(16_385)
        if len(raw) > 16_384:
            return None
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _jit_state() -> dict:
    base_state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    base_data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    state_root = base_state / "ldw-dragonfly-jit"
    runs = state_root / "runs"
    state_file = state_root / "status.json"
    base_file = base_data / "ldw-jit/base/debian-13-genericcloud-amd64.qcow2"
    # Fail closed on links in critical state paths; do not traverse owned run content.
    try:
        if any(_has_symlink_component(x) for x in (state_root, runs, state_file, base_file)):
            return {"clean": False}
        record = _safe_json_file(state_file)
        if record is None or record.get("schema") != 1 or record.get("marker") != MARKER:
            return {"clean": False}
        if not runs.is_dir():
            return {"clean": False}
        entries = list(runs.iterdir())
        if any(x.is_symlink() or not x.is_dir() for x in entries):
            return {"clean": False}
        clean = (
            record.get("state") in ("STOPPED", "AVAILABLE")
            and record.get("run_id") is None
            and record.get("qemu_pid") is None
            and not entries
            and base_file.is_file()
        )
        return {"clean": bool(clean)}
    except OSError:
        return {"clean": False}


def _qemu_absent() -> bool:
    # Normal-user visibility is limited in Crostini; absence is NOT A4 proof.
    # Exit 1 with stdout "0" is the normal pgrep no-match result.
    try:
        result = subprocess.run(["pgrep", "-fc", "[q]emu-system"],
                                capture_output=True, text=True, timeout=5, check=False)
        return result.returncode in (0, 1) and result.stdout.strip() == "0"
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return False


def sample() -> dict:
    raw = _command(["tailscale", "status", "--json"])
    ts: dict = {}
    if raw:
        try:
            candidate = json.loads(raw)
            if isinstance(candidate, dict):
                ts = candidate
        except ValueError:
            pass
    health = ts.get("Health")
    health_ok = isinstance(health, list) and len(health) == 0 if ts else False
    qemu_absent = _qemu_absent()
    return {
        "tailscaled_active": _systemctl("is-active", "tailscaled"),
        "tailscaled_enabled": _systemctl("is-enabled", "tailscaled"),
        "ssh_active": _systemctl("is-active", "ssh"),
        "ssh_enabled": _systemctl("is-enabled", "ssh"),
        "backend": ts.get("BackendState"),
        "self_online": ts.get("Self", {}).get("Online") if isinstance(ts.get("Self"), dict) else None,
        "health_ok": health_ok,
        "jit_clean": _jit_state()["clean"],
        "kvm_rw": os.access("/dev/kvm", os.R_OK | os.W_OK),
        "qemu_absent": qemu_absent,
    }


def classify(samples: list[dict]) -> dict:
    # All output is bounded category-only; never emit individual samples.
    result = {
        "classification": "HOLD",
        "reasons": [],
        "sample_count": len(samples),
        "peer_side_corrob": "UNVERIFIED",
        "process_visibility": "UNVERIFIED",
        "ci_dispatch_authorized": False,
    }
    if not DEFAULT_SAMPLES <= len(samples) <= 6 or any(not isinstance(s, dict) for s in samples):
        result["reasons"] = ["INSUFFICIENT_SAMPLES"]
        return result
    if any(not (s.get("jit_clean") is True and s.get("qemu_absent") is True)
           for s in samples):
        result["reasons"] = ["JIT_STATE_OR_QEMU_UNSAFE"]
        return result
    if any(s.get("kvm_rw") is not True for s in samples):
        result["classification"] = "DEGRADED_HOST"
        result["reasons"] = ["KVM_NOT_READ_WRITE"]
        return result
    if any(not all(s.get(x) is True for x in (
        "tailscaled_active", "tailscaled_enabled", "ssh_active", "ssh_enabled"
    )) for s in samples):
        result["classification"] = "DEGRADED_SERVICE"
        result["reasons"] = ["REQUIRED_SERVICE_NOT_READY"]
        return result
    if any(s.get("backend") != "Running" or s.get("self_online") is not True
           or s.get("health_ok") is not True for s in samples):
        result["classification"] = "DEGRADED_NETWORK"
        result["reasons"] = ["TAILSCALE_SELF_OR_HEALTH_NOT_STABLE"]
        return result
    result["classification"] = "LOCAL_SERVICES_HEALTHY_UNVERIFIED"
    result["reasons"] = ["EXTERNAL_PEER_AND_PRIVILEGED_PROCESS_PROOF_REQUIRED"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--interval-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if args.samples < DEFAULT_SAMPLES or args.samples > 6 or not (0.0 <= args.interval_seconds <= 5.0):
        parser.error("samples must be 3..6 and interval 0..5 seconds")
    records = []
    try:
        for i in range(args.samples):
            records.append(sample())
            if i + 1 < args.samples:
                time.sleep(args.interval_seconds)
        result = classify(records)
    except (Exception, KeyboardInterrupt):
        # Never print raw subprocess, path, tailnet or exception data.
        result = {
            "classification": "HOLD",
            "reasons": ["SAMPLE_FAILED"],
            "sample_count": len(records),
            "peer_side_corrob": "UNVERIFIED",
            "process_visibility": "UNVERIFIED",
            "ci_dispatch_authorized": False,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Manual diagnostic only; even local-healthy does not authorize CI/JIT.
    return 0 if result["classification"] == "LOCAL_SERVICES_HEALTHY_UNVERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
