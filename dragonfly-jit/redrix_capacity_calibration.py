#!/usr/bin/env python3
"""Passive REDRIX resource-envelope calibration; NEVER a CI/JIT admission source."""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import time

MARKER = "LDW_REDRIX_CAPACITY_CALIBRATION"
RESEARCH_RESERVE_MIB = 6144
MIN_SAMPLES, MAX_SAMPLES = 3, 6
VIRTIO_BALLOON_DRIVER = Path("/sys/bus/virtio/drivers/virtio_balloon")
_VIRTIO_DEVICE_RE = re.compile(r"^virtio\d+$")
_MAX_DRIVER_ENTRIES = 32
_MAX_VMSTAT_PAGE_COUNT = 2**53


def controller_memory_contract(path: Path) -> tuple[int, int] | None:
    """Parse only numeric source constants; do not import/execute controller code."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id in ("GUEST_MEMORY_MIB", "MIN_RESERVE_MIB"):
                    if isinstance(node.value, ast.Constant) and type(node.value.value) is int:
                        found[target.id] = node.value.value
        guest, reserve = found.get("GUEST_MEMORY_MIB"), found.get("MIN_RESERVE_MIB")
        if guest is None or reserve is None or not 512 <= guest <= 32768 or not 1024 <= reserve <= 65536:
            return None
        return guest, reserve
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return None


def read_available_mib(path: Path = Path("/proc/meminfo")) -> int | None:
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) == 3 and parts[2] == "kB":
                    value = int(parts[1])
                    return value // 1024 if value >= 0 else None
        return None
    except (OSError, UnicodeError, ValueError):
        return None


def read_pressure_avg10(path: Path) -> tuple[float, float] | None:
    try:
        found = {}
        for line in path.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if not fields or fields[0] not in ("some", "full"):
                continue
            values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
            number = float(values["avg10"])
            if not 0 <= number <= 100:
                return None
            found[fields[0]] = number
        if set(found) != {"some", "full"}:
            return None
        return found["some"], found["full"]
    except (OSError, UnicodeError, ValueError, KeyError):
        return None


def read_memory_pressure_avg10(
    cgroup_path: Path = Path("/sys/fs/cgroup/memory.pressure"),
    proc_psi_path: Path = Path("/proc/pressure/memory"),
) -> tuple[float, float] | None:
    """Prefer cgroup PSI; fall back to /proc/pressure/memory when bounded and readable."""
    cgroup = read_pressure_avg10(cgroup_path)
    if cgroup is not None:
        return cgroup
    return read_pressure_avg10(proc_psi_path)


def read_oom_events(path: Path = Path("/sys/fs/cgroup/memory.events")) -> tuple[int, int] | None:
    if not path.is_file():
        return None
    try:
        values = {}
        for line in path.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] in ("oom", "oom_kill"):
                n = int(fields[1])
                if n < 0:
                    return None
                values[fields[0]] = n
        if set(values) == {"oom", "oom_kill"}:
            return values["oom"], values["oom_kill"]
        return None
    except (OSError, UnicodeError, ValueError):
        return None


def _balloon_driver_path_allowed(driver_dir: Path) -> bool:
    """Production uses only the fixed driver sysfs path; tests may inject fixture roots."""
    if driver_dir == VIRTIO_BALLOON_DRIVER:
        return True
    normalized = str(driver_dir).replace("\\", "/")
    if normalized.startswith("/sys/"):
        try:
            return driver_dir.resolve() == VIRTIO_BALLOON_DRIVER.resolve()
        except OSError:
            return False
    return True


def _symlink_resolves_to_directory(entry: Path, *, max_hops: int = 8) -> bool:
    """Walk virtio sysfs-style symlinks; reject cycles and non-directory targets."""
    current = entry
    seen: set[Path] = set()
    for _ in range(max_hops):
        if current in seen:
            return False
        seen.add(current)
        try:
            if current.is_dir() and not current.is_symlink():
                return True
            if not current.is_symlink():
                return False
            link = os.readlink(current)
            nxt = Path(link) if Path(link).is_absolute() else current.parent / link
            current = nxt
        except OSError:
            return False
    return False


def _virtio_balloon_binding_present(entry: Path, driver_dir: Path) -> bool:
    """Kernel driver bindings are symlinks to device directories; accept both forms."""
    if not _VIRTIO_DEVICE_RE.fullmatch(entry.name):
        return False
    try:
        if entry.is_symlink():
            return _symlink_resolves_to_directory(entry)
        return entry.is_dir()
    except OSError:
        return False


def observe_virtio_balloon_sysfs(driver_dir: Path = VIRTIO_BALLOON_DRIVER) -> str:
    """Presence via bounded driver-dir scan; does not read balloon size or host spare memory."""
    if not _balloon_driver_path_allowed(driver_dir):
        return "UNVERIFIED"
    try:
        if not driver_dir.is_dir():
            return "UNVERIFIED"
        entries = list(driver_dir.iterdir())
    except OSError:
        return "UNVERIFIED"
    if len(entries) > _MAX_DRIVER_ENTRIES:
        entries = entries[:_MAX_DRIVER_ENTRIES]
    for entry in entries:
        if _virtio_balloon_binding_present(entry, driver_dir):
            return "PRESENT"
    return "UNVERIFIED"


def read_balloon_vmstat_pages(vmstat_path: Path = Path("/proc/vmstat")) -> tuple[int, int] | None:
    """Cumulative balloon_inflate/deflate page counts from vmstat (4 KiB pages each)."""
    try:
        found: dict[str, int] = {}
        for line in vmstat_path.read_text(encoding="ascii").splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[0] not in ("balloon_inflate", "balloon_deflate"):
                continue
            value = int(parts[1])
            if value < 0 or value > _MAX_VMSTAT_PAGE_COUNT:
                return None
            key = parts[0]
            if key in found:
                return None
            found[key] = value
        if set(found) != {"balloon_inflate", "balloon_deflate"}:
            return None
        return found["balloon_inflate"], found["balloon_deflate"]
    except (OSError, UnicodeError, ValueError):
        return None


def _balloon_deltas(samples: list[tuple[int, int] | None]) -> dict[str, object]:
    """Indicative guest VM activity only; not current balloon size or ChromeOS headroom."""
    present = [s for s in samples if s is not None]
    if not present:
        return {"balloon_vmstat": "UNVERIFIED", "balloon_indicative_note": "counters absent"}
    if len(present) != len(samples):
        return {"balloon_vmstat": "UNVERIFIED", "balloon_indicative_note": "partial samples"}
    for pair in present:
        if pair[0] > _MAX_VMSTAT_PAGE_COUNT or pair[1] > _MAX_VMSTAT_PAGE_COUNT:
            return {"balloon_vmstat": "HOLD", "balloon_indicative_note": "counter overflow"}
    for idx in range(1, len(present)):
        prev, cur = present[idx - 1], present[idx]
        if cur[0] < prev[0] or cur[1] < prev[1]:
            return {"balloon_vmstat": "HOLD", "balloon_indicative_note": "nonmonotonic cumulative counters"}
    first, last = present[0], present[-1]
    return {
        "balloon_vmstat": "MEASURED_INDICATIVE",
        "balloon_inflate_pages_delta": max(0, last[0] - first[0]),
        "balloon_deflate_pages_delta": max(0, last[1] - first[1]),
        "balloon_indicative_note": "cumulative vmstat only; not current balloon or host spare",
    }


def classify(
    samples: list[
        tuple[
            int | None,
            tuple[float, float] | None,
            tuple[int, int] | None,
            tuple[int, int] | None,
        ]
    ],
    contract: tuple[int, int] | None,
    *,
    virtio_balloon_sysfs: str = "UNVERIFIED",
) -> dict:
    """One bounded, sanitized diagnostic response; never permits execution."""
    report = {
        "schema": 1,
        "marker": MARKER,
        "mode": "OBSERVE_ONLY",
        "sample_count": len(samples),
        "classification": "HOLD",
        "ci_dispatch_authorized": False,
        "jit_admission_authorized": False,
        "chromeos_host_corroboration": "UNVERIFIED",
        "guest_memory_peak": "UNMEASURED",
        "candidate_is_policy": False,
        "virtio_balloon_sysfs": virtio_balloon_sysfs,
    }
    balloon_samples = [s[3] for s in samples]
    report.update(_balloon_deltas(balloon_samples))
    if contract is None or not MIN_SAMPLES <= len(samples) <= MAX_SAMPLES:
        report["reason"] = "INPUT_OR_CONTRACT_UNAVAILABLE"
        return report
    guest, reserve = contract
    report["accepted_profile"] = {"guest_mib": guest, "reserve_mib": reserve, "floor_mib": guest + reserve}
    report["research_only_profile"] = {
        "guest_mib": guest,
        "reserve_mib": RESEARCH_RESERVE_MIB,
        "floor_mib": guest + RESEARCH_RESERVE_MIB,
        "approved": False,
    }
    if any(a is None or p is None for a, p, _, _ in samples):
        report["reason"] = "MEMORY_OR_PRESSURE_UNAVAILABLE"
        return report
    available = [a for a, _, _, _ in samples if a is not None]
    pressures = [p for _, p, _, _ in samples if p is not None]
    report["minimum_memavailable_mib"] = min(available)
    report["maximum_psi_some_avg10_pct"] = max(p[0] for p in pressures)
    report["maximum_psi_full_avg10_pct"] = max(p[1] for p in pressures)
    report["accepted_memory_floor_met_all_samples"] = min(available) >= guest + reserve
    report["research_only_floor_met_all_samples"] = min(available) >= guest + RESEARCH_RESERVE_MIB
    oom_pairs = [o for _, _, o, _ in samples]
    if any(o is None for o in oom_pairs):
        report["oom_event_delta"] = "UNAVAILABLE"
    else:
        # The observer must never turn a counter reset, malformed sample, or
        # intermediate decline into an apparently reassuring zero-OOM delta.
        valid = all(
            isinstance(o, tuple)
            and len(o) == 2
            and all(type(value) is int and 0 <= value <= 2**53 for value in o)
            for o in oom_pairs
        )
        if not valid:
            report["reason"] = "OOM_COUNTER_INVALID"
            report["oom_event_delta"] = "UNVERIFIED"
            return report
        if any(
            current[0] < prior[0] or current[1] < prior[1]
            for prior, current in zip(oom_pairs, oom_pairs[1:])
        ):
            report["reason"] = "OOM_COUNTER_NONMONOTONIC"
            report["oom_event_delta"] = "UNVERIFIED"
            return report
        first, last = oom_pairs[0], oom_pairs[-1]
        report["observed_oom_delta"] = last[0] - first[0]
        report["observed_oom_kill_delta"] = last[1] - first[1]
        report["oom_event_observation"] = (
            "INCREASED" if (last[0] > first[0] or last[1] > first[1]) else "UNCHANGED"
        )
    report["classification"] = "MEASURED_NOT_AUTHORIZED"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--interval-seconds", type=float, default=1)
    args = parser.parse_args(argv)
    if not MIN_SAMPLES <= args.samples <= MAX_SAMPLES or not 0 <= args.interval_seconds <= 5:
        parser.error("samples must be 3..6 and interval 0..5")
    try:
        contract = controller_memory_contract(Path(__file__).with_name("dragonfly_jit.py"))
        balloon_sysfs = observe_virtio_balloon_sysfs()
        samples = []
        for n in range(args.samples):
            samples.append(
                (
                    read_available_mib(),
                    read_memory_pressure_avg10(),
                    read_oom_events(),
                    read_balloon_vmstat_pages(),
                )
            )
            if n + 1 < args.samples:
                time.sleep(args.interval_seconds)
        report = classify(samples, contract, virtio_balloon_sysfs=balloon_sysfs)
    except (Exception, KeyboardInterrupt):
        report = classify([], None)
        report["reason"] = "SAMPLING_FAILED"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["classification"] == "MEASURED_NOT_AUTHORIZED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
