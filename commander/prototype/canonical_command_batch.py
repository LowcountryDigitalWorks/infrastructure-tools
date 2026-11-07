"""Gate A LOW-1 synthetic canonical command/batch envelope.

This module only checks bytes. It does not sign, store keys, spawn a process,
touch the filesystem, or authorize Administrator/root execution. Owner presence
and protected pre-spawn enforcement remain outside this proof.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid

ENVELOPE_VERSION = "ldw.commander.command-batch.v1"
PRIVILEGE_MODE = "SYNTHETIC_BATCH_IDENTITY_ONLY"
MAX_DOCUMENT_BYTES = 8192
MAX_COMMANDS = 4
MAX_ARGV = 8
MAX_ARG_BYTES = 256
MAX_ENV = 8
MAX_INTENT_CHARS = 160
MAX_TTL_SECONDS = 300

_ENVELOPE_FIELDS = frozenset({
    "version", "host_id", "signer_key_id", "decision_id", "session_id",
    "privilege_mode", "batch_id", "generation", "issued_unix", "expires_unix",
    "max_commands", "intent_text", "commands",
})
_COMMAND_FIELDS = frozenset({
    "command_id", "payload_sha256", "argv", "stdin_sha256", "env_allowlist",
    "cwd_identity",
})
_ENV_FIELDS = frozenset({"name", "value_sha256"})
_HOST_ID = re.compile(r"^host:[a-z0-9](?:[a-z0-9-]{0,62})$")
_SIGNER_ID = re.compile(r"^signer-key:[a-z0-9](?:[a-z0-9-]{0,62})$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,31}$")
_ARGV = re.compile(r"^[A-Za-z0-9._:@/+-]{1,256}$")
_CWD = re.compile(r"^(posix|windows):[A-Za-z0-9._/-]{1,200}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Closed identity. A path, alias, or unlisted name is a different executable.
_ALLOWED_ARGV0 = frozenset({"ldw-canary"})
_SHELL_OR_FETCH = re.compile(r"""[\s$`|&;<>\\'"]|://""")


class BatchRefused(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    names = [name for name, _value in pairs]
    if len(names) != len(set(names)):
        raise BatchRefused("DUPLICATE_FIELD")
    return dict(pairs)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _text(value: object, *, limit: int) -> str:
    if type(value) is not str or not value or len(value) > limit:
        raise BatchRefused("SCHEMA_MISMATCH")
    if unicodedata.normalize("NFC", value) != value:
        raise BatchRefused("UNSAFE_UNICODE")
    for char in value:
        category = unicodedata.category(char)
        if category[0] == "C":
            raise BatchRefused("UNSAFE_UNICODE")
    return value


def _uuid_text(value: object) -> str:
    text = _text(value, limit=36)
    try:
        parsed = str(uuid.UUID(text))
    except (ValueError, TypeError, AttributeError):
        raise BatchRefused("SCHEMA_MISMATCH") from None
    if parsed != text:
        raise BatchRefused("SCHEMA_MISMATCH")
    return text


def _digest(value: object) -> str:
    text = _text(value, limit=64)
    if not _HEX64.fullmatch(text):
        raise BatchRefused("SCHEMA_MISMATCH")
    return text


def _integer(value: object, *, low: int, high: int) -> int:
    if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
        raise BatchRefused("SCHEMA_MISMATCH")
    return value


def _cwd(value: object) -> str:
    text = _text(value, limit=220)
    prefix, separator, body = text.partition(":")
    # posix: and windows: are opaque synthetic labels, not OS path resolution.
    if separator != ":" or prefix not in {"posix", "windows"} or not body.startswith("/"):
        raise BatchRefused("PATH_ALIAS")
    parts = body.split("/")
    if parts[0] != "" or any(part == "" or part in {".", ".."} for part in parts[1:]):
        raise BatchRefused("PATH_ALIAS")
    if not _CWD.fullmatch(text):
        raise BatchRefused("PATH_ALIAS")
    return text


def _command(value: object) -> dict:
    if type(value) is not dict or set(value) != _COMMAND_FIELDS:
        raise BatchRefused("SCHEMA_MISMATCH")
    argv = value["argv"]
    if type(argv) is not list or not 1 <= len(argv) <= MAX_ARGV:
        raise BatchRefused("SCHEMA_MISMATCH")
    checked_argv = []
    for item in argv:
        argument = _text(item, limit=MAX_ARG_BYTES)
        if len(argument.encode("utf-8")) > MAX_ARG_BYTES or not _ARGV.fullmatch(argument):
            raise BatchRefused("SCHEMA_MISMATCH")
        if _SHELL_OR_FETCH.search(argument):
            raise BatchRefused("DYNAMIC_EXECUTION_REFUSED")
        checked_argv.append(argument)
    if checked_argv[0] not in _ALLOWED_ARGV0:
        raise BatchRefused("EXECUTABLE_NOT_ALLOWED")
    env = value["env_allowlist"]
    if type(env) is not list or len(env) > MAX_ENV:
        raise BatchRefused("SCHEMA_MISMATCH")
    names = []
    checked_env = []
    for item in env:
        if type(item) is not dict or set(item) != _ENV_FIELDS:
            raise BatchRefused("SCHEMA_MISMATCH")
        name = _text(item["name"], limit=32)
        if not _ENV_NAME.fullmatch(name):
            raise BatchRefused("SCHEMA_MISMATCH")
        names.append(name)
        checked_env.append({"name": name, "value_sha256": _digest(item["value_sha256"])})
    if names != sorted(names) or len(names) != len(set(names)):
        raise BatchRefused("NONCANONICAL_ENCODING")
    return {
        "command_id": _uuid_text(value["command_id"]),
        "payload_sha256": _digest(value["payload_sha256"]),
        "argv": checked_argv,
        "stdin_sha256": _digest(value["stdin_sha256"]),
        "env_allowlist": checked_env,
        "cwd_identity": _cwd(value["cwd_identity"]),
    }


def _structure(data: object) -> dict:
    if type(data) is not dict or set(data) != _ENVELOPE_FIELDS:
        raise BatchRefused("SCHEMA_MISMATCH")
    if data["version"] != ENVELOPE_VERSION:
        raise BatchRefused("SCHEMA_MISMATCH")
    host_id = _text(data["host_id"], limit=80)
    signer = _text(data["signer_key_id"], limit=80)
    if not _HOST_ID.fullmatch(host_id) or not _SIGNER_ID.fullmatch(signer):
        raise BatchRefused("SCHEMA_MISMATCH")
    commands = data["commands"]
    if type(commands) is not list or not commands or len(commands) > MAX_COMMANDS:
        raise BatchRefused("SCHEMA_MISMATCH")
    checked = [_command(item) for item in commands]
    ids = [item["command_id"] for item in checked]
    if len(ids) != len(set(ids)):
        raise BatchRefused("REPLAY_MARKER_COLLISION")
    max_commands = _integer(data["max_commands"], low=1, high=MAX_COMMANDS)
    if max_commands != len(checked):
        raise BatchRefused("SCHEMA_MISMATCH")
    return {
        "version": ENVELOPE_VERSION,
        "host_id": host_id,
        "signer_key_id": signer,
        "decision_id": _uuid_text(data["decision_id"]),
        "session_id": _uuid_text(data["session_id"]),
        "privilege_mode": _text(data["privilege_mode"], limit=80),
        "batch_id": _uuid_text(data["batch_id"]),
        "generation": _integer(data["generation"], low=1, high=2**31 - 1),
        "issued_unix": _integer(data["issued_unix"], low=0, high=2**31 - 1),
        "expires_unix": _integer(data["expires_unix"], low=0, high=2**31 - 1),
        "max_commands": max_commands,
        "intent_text": _text(data["intent_text"], limit=MAX_INTENT_CHARS),
        "commands": checked,
    }


def parse_canonical_batch(
    raw: bytes, *, host_id: str, privilege_mode: str, generation: int, now_unix: int,
) -> dict:
    """Refuse before any admission side effect. No process is started."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise BatchRefused("SCHEMA_MISMATCH")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise BatchRefused("INVALID_UTF8") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs)
    except BatchRefused:
        raise
    except (json.JSONDecodeError, ValueError, TypeError):
        raise BatchRefused("SCHEMA_MISMATCH") from None
    document = _structure(parsed)
    if _canonical_json(document) != raw:
        raise BatchRefused("NONCANONICAL_ENCODING")
    if document["host_id"] != host_id:
        raise BatchRefused("WRONG_HOST")
    if document["privilege_mode"] != privilege_mode or privilege_mode != PRIVILEGE_MODE:
        raise BatchRefused("WRONG_MODE")
    if document["generation"] != generation:
        raise BatchRefused("STALE_GENERATION")
    issued, expires = document["issued_unix"], document["expires_unix"]
    if issued > now_unix or now_unix >= expires or expires - issued > MAX_TTL_SECONDS:
        raise BatchRefused("EXPIRED_OR_AMBIGUOUS_TTL")
    return document


def payload_matches(document: dict, command_id: str, payload: bytes) -> None:
    """Compare supplied bytes with the closed digest. Does not execute them."""
    if type(payload) is not bytes:
        raise BatchRefused("HASH_MISMATCH")
    match = next((item for item in document["commands"] if item["command_id"] == command_id), None)
    if match is None or hashlib.sha256(payload).hexdigest() != match["payload_sha256"]:
        raise BatchRefused("HASH_MISMATCH")


def canonical_batch_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
