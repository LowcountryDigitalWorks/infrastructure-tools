#!/usr/bin/env python3
"""Passive REDRIX resource-envelope calibration; NEVER a CI/JIT admission source."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import time

MARKER = "LDW_REDRIX_CAPACITY_CALIBRATION"
RESEARCH_RESERVE_MIB = 6144
MIN_SAMPLES, MAX_SAMPLES = 3, 6


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


def read_pressure_avg10(path: Path = Path("/sys/fs/cgroup/memory.pressure")) -> tuple[float, float] | None:
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


def read_oom_events(path: Path = Path("/sys/fs/cgroup/memory.events")) -> tuple[int, int] | None:
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


def classify(samples: list[tuple[int | None, tuple[float, float] | None, tuple[int, int] | None]],
             contract: tuple[int, int] | None) -> dict:
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
    }
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
    if any(a is None or p is None for a, p, _ in samples):
        report["reason"] = "MEMORY_OR_PRESSURE_UNAVAILABLE"
        return report
    available = [a for a, _, _ in samples if a is not None]
    pressures = [p for _, p, _ in samples if p is not None]
    report["minimum_memavailable_mib"] = min(available)
    report["maximum_psi_some_avg10_pct"] = max(p[0] for p in pressures)
    report["maximum_psi_full_avg10_pct"] = max(p[1] for p in pressures)
    report["accepted_memory_floor_met_all_samples"] = min(available) >= guest + reserve
    report["research_only_floor_met_all_samples"] = min(available) >= guest + RESEARCH_RESERVE_MIB
    if samples[0][2] is not None and samples[-1][2] is not None:
        first, last = samples[0][2], samples[-1][2]
        report["observed_oom_delta"] = max(0, last[0] - first[0])
        report["observed_oom_kill_delta"] = max(0, last[1] - first[1])
    else:
        report["oom_event_delta"] = "UNAVAILABLE"
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
        samples = []
        for n in range(args.samples):
            samples.append((read_available_mib(), read_pressure_avg10(), read_oom_events()))
            if n + 1 < args.samples:
                time.sleep(args.interval_seconds)
        report = classify(samples, contract)
    except (Exception, KeyboardInterrupt):
        report = classify([], None)
        report["reason"] = "SAMPLING_FAILED"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["classification"] == "MEASURED_NOT_AUTHORIZED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
