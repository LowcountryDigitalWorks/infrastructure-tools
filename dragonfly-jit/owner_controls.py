#!/usr/bin/env python3
"""Owner-facing local controls for CI-RUNNER-DRAGONFLY-JIT-001.

This presentation layer only invokes the co-installed local controller. It does not
poll a provider, register a runner, recover state automatically, or manage credentials.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
COMMANDS = {"start", "drain", "status"}
MAX_LINGER_SECONDS = 30
_ERROR_RE = re.compile(r"^ERROR:[A-Z0-9_]+$")


def _controller_path() -> Path:
    return Path(__file__).resolve().with_name("dragonfly_jit.py")


def _bounded_error(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if lines and _ERROR_RE.fullmatch(lines[-1]):
        return lines[-1]
    return "ERROR:CONTROLLER_FAILED"


def run_controller(command: str, *, controller: Path | None = None) -> tuple[int, dict | None, str | None]:
    if command not in COMMANDS:
        return 2, None, "ERROR:CONTROL_INVALID"
    candidate = (controller or _controller_path()).expanduser().absolute()
    if candidate.is_symlink() or not candidate.is_file():
        return 2, None, "ERROR:CONTROLLER_MISSING"
    target = candidate.resolve()

    completed = subprocess.run(
        [sys.executable, str(target), command],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return completed.returncode, None, _bounded_error(completed.stderr)

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return 2, None, "ERROR:CONTROLLER_OUTPUT_INVALID"
    if not isinstance(payload, dict) or payload.get("marker") != MARKER:
        return 2, None, "ERROR:CONTROLLER_OUTPUT_INVALID"
    return 0, payload, None


def format_result(command: str, payload: dict) -> str:
    state = str(payload.get("state", "UNKNOWN"))
    lines = [f"LDW Runner: {state}"]

    reason = payload.get("reason")
    if isinstance(reason, str) and reason:
        lines.append(f"Reason: {reason}")

    if command == "status":
        fields = (
            ("visible_cpus", "Visible CPUs"),
            ("mem_available_mib", "Memory available MiB"),
            ("free_disk_gib", "Free disk GiB"),
            ("load_fraction", "Load fraction"),
            ("residue_count", "Run residue count"),
        )
        for key, label in fields:
            value = payload.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                lines.append(f"{label}: {value}")
        base_present = payload.get("base_present")
        if isinstance(base_present, bool):
            lines.append(f"Pinned base present: {'yes' if base_present else 'no'}")

    if state == "DRAINING":
        lines.append("Current accepted work may finish; no new Dragonfly work should start.")
    elif state in {"HOLD", "FAILED"}:
        lines.append("Recovery is required before Start can make capacity available again.")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LDW Dragonfly owner control")
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--linger-seconds", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0 <= args.linger_seconds <= MAX_LINGER_SECONDS:
        print("ERROR:LINGER_RANGE", file=sys.stderr)
        return 2

    rc, payload, error = run_controller(args.command)
    if rc != 0 or payload is None:
        print(error or "ERROR:CONTROLLER_FAILED", file=sys.stderr)
        if args.linger_seconds:
            time.sleep(args.linger_seconds)
        return 2

    print(format_result(args.command, payload))
    if args.linger_seconds:
        time.sleep(args.linger_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
