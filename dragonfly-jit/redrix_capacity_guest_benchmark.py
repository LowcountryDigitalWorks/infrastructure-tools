#!/usr/bin/env python3
"""Offline REDRIX single-guest capacity experiment. Not a JIT or provider admission.

This draft does not spawn QEMU. ``main`` only prints a refusal. A future
admitted runtime must pass the fixed admission token and an injected process
port; this source does not start a guest. The protected controller is
read as text for its blob id and numeric contract. It is never imported.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

MARKER = "LDW_REDRIX_CAPACITY_GUEST_BENCHMARK"
SUCCESS_MARKER = "LDW_REDRIX_GUEST_BENCH_OK"
ADMISSION_TOKEN = "ORCH07-ONE-SHOT-ADMITTED"
EXPECTED_CONTROLLER_BLOB = "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a"
EXPECTED_BASE_SHA512 = (
    "3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538"
    "d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e"
)
GUEST_MIB = 2048
PRODUCTION_RESERVE_MIB = 8192
RESEARCH_RESERVE_MIB = 6144
RESEARCH_FLOOR_MIB = GUEST_MIB + RESEARCH_RESERVE_MIB
GUEST_CPUS = 2
WORKLOAD_MIB = 1024
TIMEOUT_SECONDS = 210
MIN_SAMPLES, MAX_SAMPLES = 3, 6
MIN_FREE_DISK_GIB = 16
MAX_LOAD_FRACTION = 0.70
GUEST_LOCK_NAME = "guest.lock"


def _closed(**fields: object) -> dict:
    report = {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reason": "HOLD",
        "launched": False,
        "physical_guest_executed": False,
        "jit_admission_authorized": False,
        "provider_admission_authorized": False,
        "production_policy_changed": False,
        "production_reserve_mib": PRODUCTION_RESERVE_MIB,
        "research_floor_mib": RESEARCH_FLOOR_MIB,
        "guest_mib": GUEST_MIB,
        "evidence_retained": False,
        "network": "none",
    }
    report.update(fields)
    for key in (
        "physical_guest_executed",
        "jit_admission_authorized",
        "provider_admission_authorized",
        "production_policy_changed",
    ):
        report[key] = False
    report["production_reserve_mib"] = PRODUCTION_RESERVE_MIB
    return report


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    return None


def parse_controller_text(text: str) -> dict | None:
    """Read numeric contract and base digest from source text. Do not execute it."""
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


def fixed_qemu_argv(overlay: str, serial_path: str) -> list[str] | None:
    if not overlay or not serial_path or "\x00" in overlay or "\x00" in serial_path:
        return None
    if overlay.startswith("-") or serial_path.startswith("-"):
        return None
    return [
        "qemu-system-x86_64",
        "-accel", "kvm",
        "-machine", "q35",
        "-cpu", "host",
        "-smp", str(GUEST_CPUS),
        "-m", f"{GUEST_MIB}M",
        "-nic", "none",
        "-display", "none",
        "-monitor", "none",
        "-serial", f"file:{serial_path}",
        "-no-reboot",
        "-drive", f"if=virtio,format=qcow2,file={overlay}",
    ]


def guest_workload_source() -> str:
    """Fixed in-guest script. It has no network and no host-side allocation."""
    return (
        "import time\n"
        f"chunks={WORKLOAD_MIB}\n"
        "buf=[]\n"
        "for _ in range(chunks):\n"
        "    buf.append(bytearray(1024*1024))\n"
        "open('/tmp/redrix-bench.bin','wb').write(b'x'*4096)\n"
        "time.sleep(20)\n"
        f"print({SUCCESS_MARKER!r})\n"
    )


def _first_problem(obs: dict) -> str | None:
    if obs.get("caller_path") or obs.get("extra_argv"):
        return "ARGV_OR_PATH_REFUSED"
    if obs.get("symlink"):
        return "SYMLINK_REFUSED"
    if obs.get("controller_blob") != EXPECTED_CONTROLLER_BLOB:
        return "CONTROLLER_BLOB_MISMATCH"
    if obs.get("base_sha512") != EXPECTED_BASE_SHA512:
        return "BASE_SHA512_MISMATCH"
    if obs.get("parsed_guest") != GUEST_MIB or obs.get("parsed_reserve") != PRODUCTION_RESERVE_MIB:
        return "CONTROLLER_CONTRACT_MISMATCH"
    if obs.get("duplicate_lock") or obs.get("lock_busy"):
        return "GUEST_LOCK_BUSY"
    if obs.get("qemu_present"):
        return "QEMU_ALREADY_PRESENT"
    if obs.get("controller_state") not in ("STOPPED", "AVAILABLE"):
        return "CONTROLLER_STATE_REFUSED"
    samples = obs.get("mem_available_mib")
    if not isinstance(samples, list) or not MIN_SAMPLES <= len(samples) <= MAX_SAMPLES:
        return "SAMPLE_COUNT_REFUSED"
    if any(type(item) is not int or item < RESEARCH_FLOOR_MIB for item in samples):
        return "RESEARCH_MEMORY_FLOOR"
    psi = obs.get("psi")
    if not isinstance(psi, list) or len(psi) != len(samples):
        return "PSI_UNAVAILABLE"
    if any(item != psi[0] or item[0] < 0 or item[1] < 0 for item in psi):
        return "PSI_UNSTABLE"
    balloon = obs.get("balloon_inflate")
    if not isinstance(balloon, list) or len(balloon) != len(samples):
        return "BALLOON_UNAVAILABLE"
    if balloon[-1] - balloon[0] != 0 or any(item != balloon[0] for item in balloon):
        return "BALLOON_INFLATION"
    if obs.get("oom_present") is not True:
        return "OOM_COUNTER_UNAVAILABLE"
    load = obs.get("load_fraction")
    if type(load) is not float or load < 0 or load > MAX_LOAD_FRACTION:
        return "CAPACITY_CPU"
    disk = obs.get("free_disk_gib")
    if type(disk) is not int or disk < MIN_FREE_DISK_GIB:
        return "CAPACITY_DISK"
    if obs.get("kvm_rw") is not True:
        return "KVM_NOT_READY"
    return None


def assess(obs: dict) -> dict:
    problem = _first_problem(obs)
    if problem is None:
        return _closed(classification="HOLD", reason="PREFLIGHT_OK")
    return _closed(reason=problem)


def decide(obs: dict, admission: str | None = None, outcome: dict | None = None) -> dict:
    """Gate a future one-shot. Injected outcomes never count as a physical guest."""
    report = assess(obs)
    if report["reason"] != "PREFLIGHT_OK":
        return report
    if admission != ADMISSION_TOKEN:
        return _closed(reason="RUNTIME_ADMISSION_REQUIRED")
    if outcome is None:
        return _closed(reason="LAUNCH_NOT_WIRED")
    if outcome.get("started") is not True:
        return _closed(reason="TIMEOUT_BEFORE_LAUNCH")
    report = _closed(launched=True)
    if outcome.get("owned") is not True or outcome.get("starttime_attested") is not True:
        report["reason"] = "CHILD_OWNERSHIP_UNCERTAIN"
        report["evidence_retained"] = True
        return report
    if outcome.get("timed_out") is True:
        report["reason"] = "GUEST_TIMEOUT"
        report["evidence_retained"] = True
        return report
    serial = outcome.get("serial")
    if type(serial) is not str or SUCCESS_MARKER not in serial:
        report["reason"] = "SERIAL_PARTIAL" if isinstance(serial, str) and serial.startswith("LDW_REDRIX") else "SUCCESS_MARKER_MISSING"
        report["evidence_retained"] = True
        return report
    if serial.strip() != SUCCESS_MARKER:
        report["reason"] = "SERIAL_MALFORMED"
        report["evidence_retained"] = True
        return report
    if outcome.get("poweroff_clean") is not True:
        report["reason"] = "POWEROFF_UNCERTAIN"
        report["evidence_retained"] = True
        return report
    report["classification"] = "MEASURED_NOT_AUTHORIZED"
    report["reason"] = "INJECTED_EVIDENCE_ONLY"
    report["launched"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    """Refuse every invocation. Launch stays unwired until a later admitted change."""
    del argv
    print(json.dumps(_closed(reason="CLI_NOT_ADMITTED"), sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
