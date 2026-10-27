#!/usr/bin/env python3
"""Closed local adapter for DRAGONFLY-BRIDGE-001.

The runtime CLI accepts exactly one bounded JSON request on stdin and invokes
only the already-reviewed Dragonfly controller operations: status, start, drain.
It contains no network/provider/credential logic and never exposes arbitrary
command, path, environment, or shell execution.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
from typing import Callable

MARKER = "DRAGONFLY-BRIDGE-001"
CONTROLLER_MARKER = "CI-RUNNER-DRAGONFLY-JIT-001"
EXPECTED_CONTROLLER_BLOB = "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a"
PYTHON_PATH = Path("/usr/bin/python3")
INSTALL_RELATIVE = Path(".local/lib/ldw-dragonfly-jit/dragonfly_jit.py")
MAX_REQUEST_BYTES = 4096
CONTROLLER_TIMEOUT_SECONDS = 10
ALLOWED_STATES = {"STOPPED", "AVAILABLE", "RUNNING", "DRAINING", "HOLD", "FAILED"}
OPERATIONS = {
    "dragonfly.runner.status": "status",
    "dragonfly.runner.start": "start",
    "dragonfly.runner.drain": "drain",
}
_REASON_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_ERROR_RE = re.compile(r"^ERROR:([A-Z0-9_]{1,64})$")


class AdapterError(RuntimeError):
    pass


def _owner_home() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir).absolute()


def _controller_path() -> Path:
    return _owner_home() / INSTALL_RELATIVE


def _assert_no_symlink(path: Path) -> None:
    path = path.expanduser().absolute()
    cursor = Path(path.anchor)
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        cursor = cursor / part
        try:
            mode = os.lstat(cursor).st_mode
        except FileNotFoundError as exc:
            raise AdapterError("CONTROLLER_MISSING") from exc
        if stat.S_ISLNK(mode):
            raise AdapterError("CONTROLLER_PATH_SYMLINK")


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _verify_controller(path: Path) -> None:
    _assert_no_symlink(path)
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError as exc:
        raise AdapterError("CONTROLLER_MISSING") from exc
    if not stat.S_ISREG(mode):
        raise AdapterError("CONTROLLER_NOT_REGULAR")
    try:
        actual = _git_blob_sha(path)
    except OSError as exc:
        raise AdapterError("CONTROLLER_READ_FAILED") from exc
    if actual != EXPECTED_CONTROLLER_BLOB:
        raise AdapterError("CONTROLLER_IDENTITY_MISMATCH")


def read_request(stream) -> dict:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise AdapterError("REQUEST_TOO_LARGE")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AdapterError("REQUEST_UTF8_INVALID") from exc
    except json.JSONDecodeError as exc:
        raise AdapterError("REQUEST_JSON_INVALID") from exc
    if not isinstance(payload, dict) or set(payload) != {"operation", "arguments"}:
        raise AdapterError("REQUEST_FIELDS_INVALID")
    operation = payload["operation"]
    arguments = payload["arguments"]
    if operation not in OPERATIONS:
        raise AdapterError("OPERATION_INVALID")
    if not isinstance(arguments, dict) or arguments:
        raise AdapterError("ARGUMENTS_INVALID")
    return {"operation": operation, "arguments": {}}


def _bounded_reason(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _REASON_RE.fullmatch(value):
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    return value


def _bounded_int(value: object, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    minimum = 0 if allow_zero else 1
    if value < minimum or value > 1_000_000_000:
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    return value


def _bounded_number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    number = float(value)
    if number < 0 or number > 1_000_000:
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    return number


def _parse_controller_json(stdout: str) -> dict:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AdapterError("CONTROLLER_OUTPUT_INVALID") from exc
    if not isinstance(value, dict):
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    return value


def _project(operation: str, payload: dict) -> dict:
    if payload.get("marker") != CONTROLLER_MARKER:
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    state = payload.get("state")
    if state not in ALLOWED_STATES:
        raise AdapterError("CONTROLLER_OUTPUT_INVALID")
    result = {
        "marker": MARKER,
        "operation": operation,
        "state": state,
        "reason": _bounded_reason(payload.get("reason")),
    }
    if operation == "dragonfly.runner.status":
        base_present = payload.get("base_present")
        if type(base_present) is not bool:
            raise AdapterError("CONTROLLER_OUTPUT_INVALID")
        result.update(
            {
                "visible_cpus": _bounded_int(payload.get("visible_cpus")),
                "mem_available_mib": _bounded_int(payload.get("mem_available_mib"), allow_zero=True),
                "free_disk_gib": _bounded_int(payload.get("free_disk_gib"), allow_zero=True),
                "load_fraction": _bounded_number(payload.get("load_fraction")),
                "residue_count": _bounded_int(payload.get("residue_count"), allow_zero=True),
                "base_present": base_present,
            }
        )
    return result


def _controller_error(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if len(lines) == 1:
        match = _ERROR_RE.fullmatch(lines[0])
        if match:
            return match.group(1)
    return "CONTROLLER_FAILED"


def invoke(
    request: dict,
    *,
    controller_path: Path | None = None,
    python_path: Path = PYTHON_PATH,
    home: Path | None = None,
    runner: Callable = subprocess.run,
) -> dict:
    operation = request["operation"]
    command = OPERATIONS[operation]
    controller = (controller_path or _controller_path()).absolute()
    owner_home = (home or _owner_home()).absolute()
    _verify_controller(controller)
    env = {
        "HOME": str(owner_home),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        completed = runner(
            [str(python_path), str(controller), command],
            cwd=str(owner_home),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CONTROLLER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError("CONTROLLER_TIMEOUT") from exc
    except OSError as exc:
        raise AdapterError("CONTROLLER_EXEC_FAILED") from exc
    if completed.returncode != 0:
        raise AdapterError(_controller_error(completed.stderr))
    return _project(operation, _parse_controller_json(completed.stdout))


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def main() -> int:
    try:
        request = read_request(sys.stdin.buffer)
        _emit(invoke(request))
        return 0
    except AdapterError as exc:
        _emit({"marker": MARKER, "result": "FAILED", "reason": str(exc)})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
