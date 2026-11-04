"""LDW Commander local user-mode Gate-B proof: real fixture file + fixed process.

This is intentionally NOT a remote, general shell, privileged service or isolation
boundary. Actual OS work is restricted to a disposable trusted fixture root.
No model-facing API, network listener or ambient Administrator/root authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from threading import RLock

from session import MAX_COMMANDS, SessionRefused, SyntheticAgent, uid

FILE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}\.txt$")
MAX_FILE = 1024
# Fixed, harmless probe. The final Commander will need independently reviewed
# general process execution with explicit host admission and sensitive-output gates.
PROBE_CODE = "print('LDW_LOCAL_PROCESS_PROOF')"


class LocalUserModeProbe(SyntheticAgent):
    """Real filesystem/process proof, admitted only by an existing signed session."""

    def __init__(self, public_key, policy, host: str, fixture_root: Path, **kwargs):
        super().__init__(public_key, policy, host, **kwargs)
        candidate = Path(fixture_root)
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("FIXTURE_ROOT_NOT_A_DIRECTORY")
        # This owner-supplied root is NOT a security sandbox for child processes.
        self._root = candidate.resolve(strict=True)

    def _file(self, name: str) -> Path:
        if not isinstance(name, str) or not FILE_NAME.fullmatch(name):
            raise SessionRefused("INVALID_FIXTURE_FILE")
        path = self._root / name
        if path.is_symlink():
            raise SessionRefused("SYMLINK_REFUSED")
        # No nested names or path traversal; root is a trusted fixture directory.
        return path

    def execute(self, token: str, operator: str, command_id: str, op: str,
                name: str | None = None, value: str | None = None) -> dict:
        if op not in ("file_create", "file_read", "fixed_process"):
            raise SessionRefused("UNSUPPORTED_PROBE_OPERATION")
        if op == "fixed_process" and (name is not None or value is not None):
            raise SessionRefused("INVALID_PROBE_ARGUMENTS")
        if op in ("file_create", "file_read"):
            path = self._file(name)
            if op == "file_create" and (
                not isinstance(value, str) or len(value.encode("utf-8")) > MAX_FILE
            ):
                raise SessionRefused("INVALID_FIXTURE_VALUE")
            if op == "file_read" and value is not None:
                raise SessionRefused("INVALID_PROBE_ARGUMENTS")
        request = json.dumps({"op": op, "name": name, "value": value},
                             separators=(",", ":"), sort_keys=True)
        cid = uid(command_id)
        with self._lock:
            grant = self._decode(token)
            sid = self._check(grant, operator)
            if sid in self._revoked:
                raise SessionRefused("REVOKED_SESSION")
            state = self._active.get(sid)
            if state is None or state["grant"] != grant:
                raise SessionRefused("SESSION_NOT_OPEN")
            ledger = state["commands"]
            if cid in ledger:
                previous_request, previous_response = ledger[cid]
                if previous_request != request:
                    raise SessionRefused("COMMAND_ID_CONFLICT")
                return {**previous_response, "duplicate": True}
            if len(ledger) >= MAX_COMMANDS:
                raise SessionRefused("COMMAND_BUDGET_EXHAUSTED")

            # This entire section is deliberately synchronous and bounded.
            # It must NOT be used as a protected service/session implementation.
            if op == "file_create":
                try:
                    with path.open("x", encoding="utf-8") as output:
                        output.write(value)
                except FileExistsError:
                    raise SessionRefused("FIXTURE_FILE_EXISTS") from None
                result = {"size": len(value.encode("utf-8")),
                          "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
            elif op == "file_read":
                try:
                    content = path.read_bytes()
                except FileNotFoundError:
                    raise SessionRefused("FIXTURE_FILE_MISSING") from None
                if len(content) > MAX_FILE:
                    raise SessionRefused("FIXTURE_FILE_TOO_LARGE")
                result = {"size": len(content),
                          "sha256": hashlib.sha256(content).hexdigest(),
                          "text": content.decode("utf-8", errors="replace")}
            else:
                # NO shell=True, arbitrary argv, environment secrets or owner data.
                # Minimal Windows Python startup requires SystemRoot. Do not
                # forward the rest of the owner's environment/credentials.
                process_env = {"PYTHONNOUSERSITE": "1"}
                if os.name == "nt":
                    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
                    if not system_root:
                        raise SessionRefused("PROCESS_STARTUP_ENV_MISSING")
                    process_env["SystemRoot"] = system_root
                try:
                    completed = subprocess.run(
                        [sys.executable, "-I", "-c", PROBE_CODE],
                        cwd=str(self._root),
                        env=process_env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        timeout=3, check=False,
                    )
                except subprocess.TimeoutExpired:
                    raise SessionRefused("PROCESS_TIMEOUT_AMBIGUOUS") from None
                # Windows stdout uses CRLF. Accept only this exact fixed output.
                expected = (b"LDW_LOCAL_PROCESS_PROOF\n",
                            b"LDW_LOCAL_PROCESS_PROOF\r\n")
                if completed.returncode != 0 or completed.stdout not in expected:
                    raise SessionRefused("FIXED_PROCESS_FAILED")
                result = {"exit_code": 0, "output": "LDW_LOCAL_PROCESS_PROOF"}
            response = {
                "session_id": sid, "command_id": cid, "state": "LOCAL_USER_MODE_PROOF",
                "op": op, "result": result, "duplicate": False,
            }
            ledger[cid] = (request, response)
            return response
