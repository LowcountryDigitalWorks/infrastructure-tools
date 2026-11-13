#!/usr/bin/env python3
"""Join two owner-supplied REDRIX observer JSON captures without granting CI/JIT authority.

Pure standard-library, read-only, offline: no ChromeOS or Crostini host access.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat

MARKER = "LDW_REDRIX_HOST_GUEST_EVIDENCE_V1"
HOST_MARKER = "LDW_REDRIX_CHROMEOS_HOST_MEMORY_V1"
GUEST_MARKER = "LDW_REDRIX_CAPACITY_CALIBRATION"
MAX_BYTES = 32 * 1024
_MAX_HOST_MIB = 256 * 1024
_MAX_GUEST_MIB = 256 * 1024
_MIN_OVERLAP_MS = 1000
_UTC_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$")


class EvidenceError(ValueError):
    """Sanitized, enumerated, never contains source input."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceError(reason)


def _int(value: object, minimum: int, maximum: int, reason: str) -> int:
    _require(type(value) is int and minimum <= value <= maximum, reason)
    return value


def _false_flags(record: dict, keys: tuple[str, ...]) -> None:
    _require(all(record.get(key) is False for key in keys), "AUTHORITY_FLAGS_UNTRUSTED")


def _utc(value: object) -> datetime:
    _require(type(value) is str and _UTC_RE.fullmatch(value) is not None, "TIMESTAMP_INVALID")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("TIMESTAMP_INVALID") from exc
    _require(d.tzinfo == timezone.utc, "TIMESTAMP_INVALID")
    return d


def _elapsed_ms(start: datetime, end: datetime) -> int:
    # Inputs are microsecond-resolution at most. No floating-point estimation.
    span = end - start
    return (span.days * 86400000000 + span.seconds * 1000000 + span.microseconds) // 1000


def _window(record: dict, *, maximum_ms: int, minimum_ms: int, elapsed_tolerance_ms: int = 0) -> tuple[datetime, datetime]:
    start = _utc(record.get("capture_started_utc"))
    end = _utc(record.get("capture_finished_utc"))
    elapsed = _int(record.get("capture_elapsed_ms"), 0, maximum_ms, "ELAPSED_INVALID")
    _require(minimum_ms <= _elapsed_ms(start, end) <= maximum_ms, "CAPTURE_WINDOW_INVALID")
    _require(abs(_elapsed_ms(start, end) - elapsed) <= elapsed_tolerance_ms, "CAPTURE_ELAPSED_MISMATCH")
    return start, end


def inspect_host(record: object) -> dict:
    _require(type(record) is dict, "HOST_SCHEMA_INVALID")
    _require(record.get("marker") == HOST_MARKER and type(record.get("schema")) is int and record.get("schema") == 1
             and record.get("source") == "CHROME_SYSTEM_MEMORY_API"
             and record.get("mode") == "OBSERVE_ONLY"
             and record.get("classification") == "HOST_REPORTED_NOT_ATTESTED"
             and record.get("memory_sample_scope") == "CHROMEOS_BROWSER_HOST_PHYSICAL"
             and record.get("capture_clock_source") == "BROWSER_WALLCLOCK_UNATTESTED",
             "HOST_SCHEMA_INVALID")
    _false_flags(record, ("ci_dispatch_authorized", "jit_admission_authorized", "memory_policy_change_authorized"))
    _require(record.get("crostini_guest_corroboration") == "NOT_COLLECTED_BY_THIS_EXTENSION"
             and record.get("nested_guest_peak") == "UNMEASURED", "HOST_CLAIMS_INVALID")
    count = _int(record.get("sample_count"), 5, 5, "HOST_SAMPLES_INVALID")
    samples = record.get("samples")
    _require(type(samples) is list and len(samples) == count, "HOST_SAMPLES_INVALID")
    start, end = _window(record, maximum_ms=15000, minimum_ms=3000)
    total = None
    previous = None
    available = []
    for sample in samples:
        _require(type(sample) is dict, "HOST_SAMPLES_INVALID")
        when = _utc(sample.get("observed_at_utc"))
        capacity = _int(sample.get("host_total_mib"), 1, _MAX_HOST_MIB, "HOST_MEMORY_INVALID")
        free = _int(sample.get("host_available_mib"), 0, capacity, "HOST_MEMORY_INVALID")
        _require(total is None or capacity == total, "HOST_CAPACITY_CHANGED")
        _require(start <= when <= end and (previous is None or when > previous), "HOST_SAMPLE_CLOCK_INVALID")
        if previous is not None:
            _require(250 <= _elapsed_ms(previous, when) <= 6000, "HOST_SAMPLE_GAP_INVALID")
        total, previous = capacity, when
        available.append(free)
    _require(previous == end and
             _int(record.get("host_min_available_mib"), 0, total, "HOST_SUMMARY_MISMATCH") == min(available),
             "HOST_SUMMARY_MISMATCH")
    return {"started": start, "finished": end, "minimum_available_mib": min(available), "capacity_mib": total}


def inspect_guest(record: object) -> dict:
    _require(type(record) is dict, "GUEST_SCHEMA_INVALID")
    _require(record.get("marker") == GUEST_MARKER and type(record.get("schema")) is int and record.get("schema") == 1
             and record.get("mode") == "OBSERVE_ONLY"
             and record.get("classification") == "MEASURED_NOT_AUTHORIZED"
             and record.get("capture_clock_source") == "PENGUIN_UTC_WALLCLOCK_UNATTESTED"
             and record.get("memory_sample_scope") == "CROSTINI_GUEST_VISIBLE_ONLY"
             and record.get("chromeos_host_corroboration") == "UNVERIFIED",
             "GUEST_SCHEMA_INVALID")
    _false_flags(record, ("ci_dispatch_authorized", "jit_admission_authorized", "candidate_is_policy"))
    _int(record.get("sample_count"), 3, 6, "GUEST_SAMPLES_INVALID")
    # Guest producer truncates both UTC endpoints to milliseconds after computing
    # elapsed_ms from microsecond timestamps; the serialization can differ by 1ms.
    # This is a precision allowance ONLY, never device/clock attestation.
    start, end = _window(record, maximum_ms=60000, minimum_ms=1, elapsed_tolerance_ms=1)
    p = record.get("accepted_profile")
    _require(type(p) is dict and p.get("guest_mib") == 2048 and p.get("reserve_mib") == 8192
             and p.get("floor_mib") == 10240, "PRODUCTION_PROFILE_MISMATCH")
    low = _int(record.get("minimum_memavailable_mib"), 0, _MAX_GUEST_MIB, "GUEST_MEMORY_INVALID")
    claimed = record.get("accepted_memory_floor_met_all_samples")
    _require(type(claimed) is bool and claimed == (low >= 10240), "GUEST_FLOOR_MISMATCH")
    disposition = "GUEST_FLOOR_OBSERVED_NOT_AUTHORIZED" if claimed else "GUEST_FLOOR_BELOW_POLICY_NOT_HOST_EXHAUSTION"
    _require(record.get("guest_idle_memory_floor_disposition") == disposition, "GUEST_DISPOSITION_INVALID")
    return {"started": start, "finished": end, "minimum_available_mib": low, "floor_met": claimed}


def correlate(host: object, guest: object) -> dict:
    """Never attests clocks, authority, host identity, physical provenance or JIT readiness."""
    base = {
        "schema": 1, "marker": MARKER, "mode": "READ_ONLY_OFFLINE",
        "classification": "HOLD", "reason": "INPUT_INVALID",
        "cross_device_clock_attestation": "UNVERIFIED",
        "chromeos_host_identity_attestation": "UNVERIFIED",
        "host_guest_causal_memory_attribution": "NOT_ESTABLISHED",
        "ci_dispatch_authorized": False, "jit_admission_authorized": False,
        "memory_policy_change_authorized": False,
    }
    try:
        h = inspect_host(host)
        g = inspect_guest(guest)
    except EvidenceError as exc:
        base["reason"] = str(exc)
        return base
    overlap_start = max(h["started"], g["started"])
    overlap_end = min(h["finished"], g["finished"])
    overlap = max(0, _elapsed_ms(overlap_start, overlap_end))
    base.update({
        "host_reported_total_mib": h["capacity_mib"],
        "host_reported_min_available_mib": h["minimum_available_mib"],
        "guest_reported_min_available_mib": g["minimum_available_mib"],
        "accepted_guest_floor_mib": 10240,
        "accepted_guest_idle_floor_met": g["floor_met"],
        "observed_wallclock_window_overlap_ms": overlap,
    })
    if overlap < _MIN_OVERLAP_MS:
        base.update({"classification": "HOLD", "reason": "NO_SUFFICIENT_WALLCLOCK_OVERLAP"})
    else:
        base.update({
            "classification": "WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED",
            "reason": "TIME_AND_DEVICE_IDENTITY_UNATTESTED",
        })
    return base


def _no_duplicate_keys(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise EvidenceError("INPUT_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_unbounded_json_tokens(data: bytes) -> None:
    """Reject excessive nesting and integer tokens before Python's version-dependent decoder.

    A byte-level scan ignores quoted braces/brackets (including escaped quotes).
    The standard JSON decoder still checks full syntax, characters and numbers.
    """
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:  # Backslash
                escaped = True
            elif byte == 34:  # Double quote
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):  # [ or {
            depth += 1
            _require(depth <= 64, "INPUT_JSON_DEPTH_EXCEEDED")
        elif byte in (93, 125):  # ] or }
            depth -= 1
            _require(depth >= 0, "INPUT_JSON_STRUCTURE_INVALID")
    _require(not quoted and depth == 0, "INPUT_JSON_STRUCTURE_INVALID")


def _bounded_json_int(text: str) -> int:
    _require(len(text) <= 40, "INPUT_INT_TOKEN_TOO_LONG")
    return int(text)


def _bounded_json_float(text: str) -> float:
    _require(len(text) <= 40, "INPUT_FLOAT_TOKEN_TOO_LONG")
    value = float(text)
    _require(math.isfinite(value), "INPUT_NONFINITE_NUMBER")
    return value


def _read_json(path: Path) -> object:
    # No symlinks, devices, pipes, giant input, content reflection or arbitrary writes.
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES, "INPUT_FILE_INVALID")
        data = os.read(fd, MAX_BYTES + 1)
        _require(len(data) <= MAX_BYTES, "INPUT_SIZE_INVALID")
        _reject_unbounded_json_tokens(data)
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                          parse_int=_bounded_json_int, parse_float=_bounded_json_float,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("INPUT_NONFINITE_NUMBER")))
    except EvidenceError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise EvidenceError("INPUT_FILE_INVALID") from exc
    finally:
        if fd is not None:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True, help="Read-only Chrome extension JSON export")
    parser.add_argument("--guest", type=Path, required=True, help="Read-only Crostini calibration JSON export")
    args = parser.parse_args(argv)
    try:
        result = correlate(_read_json(args.host), _read_json(args.guest))
    except EvidenceError as exc:
        result = correlate(None, None)
        result["reason"] = str(exc)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["classification"] == "WALLCLOCK_OVERLAP_OBSERVED_NOT_ATTESTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
