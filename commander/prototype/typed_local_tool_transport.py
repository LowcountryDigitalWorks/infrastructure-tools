"""Typed local tool dispatcher for Gate B normal-user Commander preflight (#209).

In-process, loopback-only. Tool names are a closed set. Host and operator
identity come from a trusted owner binding supplied at harness construction,
never from model-supplied tool arguments, grant text or signed approvals.

This is NOT a network listener, ChatGPT connector, MCP plugin or admin shell.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from host_session_journal import HostJournalError, HostSessionJournal
from local_user_mode import FILE_NAME, LocalUserModeProbe
from session import SessionRefused, SyntheticAgent, uid

ALLOWED_TOOLS = frozenset({
    "hosts_list",
    "session_open",
    "session_close",
    "fs_read",
    "fs_write",
    "run_fixed_canary",
    "process_read",
})

FORBIDDEN_ARG_KEYS = frozenset({
    "grant",
    "operator",
    "host",
    "privilege",
    "owner_decision",
    "approval",
    "shell",
    "argv",
    "command",
    "path",
})

MAX_TOOL_JSON_BYTES = 4096
MAX_PROCESS_OUTPUT = 256
IDENTITY_INJECTION = "IDENTITY_INJECTION_REFUSED"


class TypedLocalToolRefused(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TrustedTransportBinding:
    """Independently configured owner/host identity for one disposable harness."""

    policy_id: str
    operator: str
    host: str


class JournalBoundLocalUserModeProbe(LocalUserModeProbe):
    """Local user-mode probe with host journal tombstone on open (synthetic only)."""

    def __init__(self, public_key, policy, host: str, fixture_root: Path,
                 *, host_journal: HostSessionJournal, **kwargs):
        if not isinstance(host_journal, HostSessionJournal):
            raise ValueError("HOST_JOURNAL_REQUIRED")
        super().__init__(public_key, policy, host, fixture_root, **kwargs)
        self._host_journal = host_journal

    def open(self, token: str, operator: str) -> dict:
        with self._lock:
            grant = self._decode(token)
            sid = self._check(grant, operator)
            if sid in self._active:
                return super().open(token, operator)
            try:
                self._host_journal.reserve(sid, token)
            except HostJournalError:
                raise SessionRefused("HOST_JOURNAL_UNAVAILABLE") from None
            result = super().open(token, operator)
            self._active[sid]["token"] = token
            return result

    def revoke(self, session_id: str) -> dict:
        with self._lock:
            sid = uid(session_id)
            state = self._active.get(sid)
            if state is None:
                raise SessionRefused("SESSION_NOT_OPEN")
            token = state.get("token")
            if not token:
                raise SessionRefused("HOST_JOURNAL_UNAVAILABLE")
            result = super().revoke(sid)
            try:
                self._host_journal.synthetic_revoke_verified(sid, token)
            except HostJournalError:
                raise SessionRefused("HOST_QUARANTINED") from None
            return result


def _reject_identity_injection(arguments: dict[str, Any] | None) -> dict[str, Any]:
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
    extra = set(arguments) & FORBIDDEN_ARG_KEYS
    if extra:
        raise TypedLocalToolRefused(IDENTITY_INJECTION)
    return arguments


def sanitize_tool_payload(payload: object) -> dict[str, object]:
    """Bound JSON size for model-visible transport summaries."""
    try:
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise TypedLocalToolRefused("MALFORMED_RESULT") from None
    if len(text.encode("utf-8")) > MAX_TOOL_JSON_BYTES:
        raise TypedLocalToolRefused("OUTPUT_OVERSIZE")
    if not isinstance(payload, dict):
        return {"state": "SANITIZED", "value": text[:MAX_TOOL_JSON_BYTES]}
    return payload


class TypedLocalToolDispatcher:
    """Maps closed tool names to LocalUserModeProbe operations under one binding."""

    def __init__(
        self,
        probe: LocalUserModeProbe | SyntheticAgent,
        binding: TrustedTransportBinding,
        *,
        active_grant: str | None = None,
    ):
        if not isinstance(binding, TrustedTransportBinding):
            raise ValueError("TRUSTED_BINDING_REQUIRED")
        self._probe = probe
        self._binding = binding
        self._grant = active_grant
        self._session_id: str | None = None
        self._last_process: dict[str, object] | None = None

    @property
    def session_id(self) -> str | None:
        return self._session_id

    def bind_grant(self, grant: str) -> None:
        if not isinstance(grant, str) or not grant:
            raise TypedLocalToolRefused("GRANT_UNAVAILABLE")
        self._grant = grant

    def dispatch(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, object]:
        if tool not in ALLOWED_TOOLS:
            raise TypedLocalToolRefused("UNKNOWN_TOOL")
        args = _reject_identity_injection(arguments)
        if tool == "hosts_list":
            result = {
                "state": "HOSTS_ENUMERATED",
                "hosts": [self._binding.host],
                "policy_id": self._binding.policy_id,
            }
            return sanitize_tool_payload(result)

        if tool == "session_open":
            if args:
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            if self._grant is None:
                raise TypedLocalToolRefused("GRANT_UNAVAILABLE")
            opened = self._probe.open(self._grant, self._binding.operator)
            self._session_id = opened["session_id"]
            result = {
                "state": "SESSION_OPEN",
                "session_id": self._session_id,
                "host": self._binding.host,
                "operator": self._binding.operator,
            }
            return sanitize_tool_payload(result)

        if tool == "session_close":
            sid = args.get("session_id")
            if sid is None:
                if self._session_id is None:
                    raise TypedLocalToolRefused("SESSION_NOT_OPEN")
                sid = self._session_id
            if not isinstance(sid, str):
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            closed = self._probe.revoke(sid)
            if self._session_id == sid:
                self._session_id = None
                self._last_process = None
            result = {"state": "SESSION_CLOSED", **closed}
            return sanitize_tool_payload(result)

        self._require_open_session()
        assert self._grant is not None

        if tool == "fs_write":
            command_id = args.get("command_id")
            name = args.get("name")
            value = args.get("value")
            if not all(isinstance(item, str) for item in (command_id, name, value)):
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            if not FILE_NAME.fullmatch(name):
                raise TypedLocalToolRefused("INVALID_FIXTURE_FILE")
            response = self._probe.execute(
                self._grant, self._binding.operator, command_id,
                "file_create", name=name, value=value,
            )
            return sanitize_tool_payload(response)

        if tool == "fs_read":
            command_id = args.get("command_id")
            name = args.get("name")
            if not isinstance(command_id, str) or not isinstance(name, str):
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            response = self._probe.execute(
                self._grant, self._binding.operator, command_id,
                "file_read", name=name,
            )
            return sanitize_tool_payload(response)

        if tool == "run_fixed_canary":
            command_id = args.get("command_id")
            if not isinstance(command_id, str):
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            response = self._probe.execute(
                self._grant, self._binding.operator, command_id, "fixed_process",
            )
            proc = response.get("result")
            if isinstance(proc, dict):
                output = str(proc.get("output", ""))[:MAX_PROCESS_OUTPUT]
                self._last_process = {"exit_code": proc.get("exit_code"), "output": output}
            result = {**response, "process_preview": self._last_process}
            return sanitize_tool_payload(result)

        if tool == "process_read":
            if args:
                raise TypedLocalToolRefused("MALFORMED_ARGUMENTS")
            if self._last_process is None:
                raise TypedLocalToolRefused("PROCESS_NOT_RUN")
            result = {
                "state": "PROCESS_READ",
                "session_id": self._session_id,
                "process": self._last_process,
            }
            return sanitize_tool_payload(result)

        raise TypedLocalToolRefused("UNKNOWN_TOOL")

    def _require_open_session(self) -> None:
        if self._session_id is None:
            raise TypedLocalToolRefused("SESSION_NOT_OPEN")
        if self._grant is None:
            raise TypedLocalToolRefused("GRANT_UNAVAILABLE")


def offline_denial() -> dict[str, str]:
    """Fixed projection when the trusted harness is unavailable."""
    return {"state": "TRANSPORT_OFFLINE", "status": "DENIED"}


_ARG_INJECTION = re.compile(r"(?i)(?:\.\./|/etc/|\\\\|cmd\.exe|powershell)")
