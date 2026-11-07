"""Non-authorizing privileged channel request/response contract for REDRIX Gate A4 (#139).

DATA-ONLY: no sudo, sockets, listeners, filesystem writes, subprocesses, or runtime
A4 PASS. Caller-supplied JSON is untrusted data; this module never mints authentication
evidence and never sets privilegedChannelAuthenticated true.

Replay, TTL, freshness binding, and nonce uniqueness are **not** proven by this stateless
parser. Matching oracle nonce/correlation only means the envelope shape fits; a protected
producer must authenticate observations and refuse reuse in a future accepted channel.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

MARKER = "DRAGONFLY_GATE_A4_CHANNEL_CONTRACT_V1"
OPERATION = "REDRIX_A4_FD_READONLY_V1"
SCHEMA_VERSION = 1
UID_POLICY = 1000
MAX_INPUT_BYTES = 262_144
MAX_JSON_DEPTH = 24
MAX_CORRELATION_LEN = 128
MAX_COUNT = 1_000_000
NONCE_HEX_LEN = 64  # 256-bit test oracle nonce, hex-encoded

REQUEST_KEYS = frozenset({"schemaVersion", "operation", "arguments"})
RESPONSE_KEYS = frozenset(
    {"schemaVersion", "operation", "correlation", "nonce", "uidPolicy", "snapshots"}
)
SNAPSHOT_KEYS = frozenset(
    {
        "sequence",
        "observedAtMonotonicMs",
        "processCount",
        "qemuProcessCount",
        "kvmFdProcessCount",
    }
)
FORBIDDEN_RESPONSE_KEYS = frozenset(
    {
        "privilegedChannelAuthenticated",
        "runtimeAuthority",
        "a4Pass",
        "root",
        "signature",
        "signatureValid",
        "path",
        "executable",
        "command",
        "pidList",
        "fdList",
        "token",
    }
)
_SENSITIVE_SUBSTR = re.compile(r"@|/proc/|mailto:|ssh://|\\\\", re.I)


class ChannelContractError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def _sanitize_reason(reason: str) -> str:
    if re.fullmatch(r"A4_CH_[A-Z0-9_]+", reason):
        return reason
    return "A4_CH_MALFORMED_RESPONSE"


def hold(reason: str) -> dict[str, object]:
    reason = _sanitize_reason(reason)
    return {
        "schema": SCHEMA_VERSION,
        "marker": MARKER,
        "classification": "HOLD",
        "reasonCode": reason,
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "complementaryA0QemuEnumerationRequired": True,
    }


def _data_only() -> dict[str, object]:
    return {
        "schema": SCHEMA_VERSION,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED",
        "reasonCode": "EXTERNAL_TRUST_GATES_REQUIRED",
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "complementaryA0QemuEnumerationRequired": True,
        "uidPolicy": UID_POLICY,
        "snapshotCount": 2,
    }


def _ensure_bytes(data: Any) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise ChannelContractError("A4_CH_INVALID_INPUT_TYPE")


def _decode_text(data: Any) -> str:
    payload = _ensure_bytes(data)
    if len(payload) > MAX_INPUT_BYTES:
        raise ChannelContractError("A4_CH_INPUT_TOO_LARGE")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChannelContractError("A4_CH_MALFORMED_UTF8") from exc


def _object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ChannelContractError("A4_CH_DUPLICATE_KEY")
        obj[key] = value
    return obj


def _depth(value: Any, limit: int = MAX_JSON_DEPTH) -> int:
    if limit <= 0:
        raise ChannelContractError("A4_CH_JSON_TOO_DEEP")

    def walk(node: Any, depth: int) -> None:
        if depth > limit:
            raise ChannelContractError("A4_CH_JSON_TOO_DEEP")
        if isinstance(node, dict):
            for item in node.values():
                walk(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(value, 1)
    return 1


def _parse_json_bytes(data: Any) -> dict[str, Any]:
    text = _decode_text(data)
    try:
        decoded = json.loads(text, object_pairs_hook=_object_pairs_hook)
    except json.JSONDecodeError as exc:
        raise ChannelContractError("A4_CH_MALFORMED_JSON") from exc
    except ChannelContractError:
        raise
    except Exception as exc:
        raise ChannelContractError("A4_CH_MALFORMED_JSON") from exc
    if not isinstance(decoded, dict):
        raise ChannelContractError("A4_CH_MALFORMED_JSON")
    _depth(decoded)
    return decoded


def _require_int(name: str, value: Any, *, minimum: int = 0, maximum: int = MAX_COUNT) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChannelContractError("A4_CH_TYPE_MISMATCH")
    if value < minimum or value > maximum:
        raise ChannelContractError("A4_CH_BOUND_VIOLATION")
    return value


def _require_text(name: str, value: Any, *, max_len: int = MAX_CORRELATION_LEN) -> str:
    if not isinstance(value, str):
        raise ChannelContractError("A4_CH_TYPE_MISMATCH")
    if not value or len(value) > max_len:
        raise ChannelContractError("A4_CH_BOUND_VIOLATION")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ChannelContractError("A4_CH_MALFORMED_TEXT")
    if not value.isprintable():
        raise ChannelContractError("A4_CH_MALFORMED_TEXT")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ChannelContractError("A4_CH_MALFORMED_TEXT")
    if _SENSITIVE_SUBSTR.search(value):
        raise ChannelContractError("A4_CH_FORBIDDEN_CONTENT")
    return value


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ChannelContractError("A4_CH_NON_FINITE_NUMBER")
        raise ChannelContractError("A4_CH_TYPE_MISMATCH")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def _validate_closed_request(obj: dict[str, Any]) -> None:
    extra = set(obj) - REQUEST_KEYS
    if extra:
        raise ChannelContractError("A4_CH_UNEXPECTED_FIELD")
    schema = obj.get("schemaVersion")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SCHEMA_VERSION:
        raise ChannelContractError("A4_CH_UNEXPECTED_SCHEMA")
    if obj.get("operation") != OPERATION:
        raise ChannelContractError("A4_CH_UNEXPECTED_OPERATION")
    args = obj.get("arguments")
    if not isinstance(args, list) or args:
        raise ChannelContractError("A4_CH_UNEXPECTED_ARGUMENTS")


def _validate_snapshot(entry: Any) -> dict[str, int]:
    if not isinstance(entry, dict):
        raise ChannelContractError("A4_CH_MALFORMED_SNAPSHOT")
    extra = set(entry) - SNAPSHOT_KEYS
    if extra:
        raise ChannelContractError("A4_CH_UNEXPECTED_FIELD")
    sequence = _require_int("sequence", entry.get("sequence"), minimum=1, maximum=MAX_COUNT)
    observed = _require_int(
        "observedAtMonotonicMs",
        entry.get("observedAtMonotonicMs"),
        minimum=0,
        maximum=2**62 - 1,
    )
    process_count = _require_int("processCount", entry.get("processCount"))
    qemu_count = _require_int("qemuProcessCount", entry.get("qemuProcessCount"))
    kvm_count = _require_int("kvmFdProcessCount", entry.get("kvmFdProcessCount"))
    if qemu_count > 0:
        raise ChannelContractError("A4_CH_QEMU_PRESENT")
    if kvm_count > 0:
        raise ChannelContractError("A4_CH_KVM_FD_PRESENT")
    return {
        "sequence": sequence,
        "observedAtMonotonicMs": observed,
        "processCount": process_count,
        "qemuProcessCount": qemu_count,
        "kvmFdProcessCount": kvm_count,
    }


def _validate_closed_response(
    obj: dict[str, Any],
    *,
    expected_nonce: str,
    expected_correlation: str,
) -> None:
    for forbidden in FORBIDDEN_RESPONSE_KEYS:
        if forbidden in obj:
            raise ChannelContractError("A4_CH_FORBIDDEN_AUTH_CLAIM")
    extra = set(obj) - RESPONSE_KEYS
    if extra:
        raise ChannelContractError("A4_CH_UNEXPECTED_FIELD")
    schema = obj.get("schemaVersion")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SCHEMA_VERSION:
        raise ChannelContractError("A4_CH_UNEXPECTED_SCHEMA")
    if obj.get("operation") != OPERATION:
        raise ChannelContractError("A4_CH_UNEXPECTED_OPERATION")
    correlation = _require_text("correlation", obj.get("correlation"))
    if correlation != expected_correlation:
        raise ChannelContractError("A4_CH_CORRELATION_MISMATCH")
    nonce = _require_text("nonce", obj.get("nonce"), max_len=NONCE_HEX_LEN)
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ChannelContractError("A4_CH_MALFORMED_NONCE")
    if nonce != expected_nonce:
        raise ChannelContractError("A4_CH_NONCE_MISMATCH")
    uid_policy = obj.get("uidPolicy")
    if isinstance(uid_policy, bool) or not isinstance(uid_policy, int):
        raise ChannelContractError("A4_CH_TYPE_MISMATCH")
    if uid_policy != UID_POLICY:
        raise ChannelContractError("A4_CH_UID_POLICY_DRIFT")
    snapshots_raw = obj.get("snapshots")
    if not isinstance(snapshots_raw, list) or len(snapshots_raw) != 2:
        raise ChannelContractError("A4_CH_SNAPSHOT_COUNT")
    first = _validate_snapshot(snapshots_raw[0])
    second = _validate_snapshot(snapshots_raw[1])
    if first["sequence"] == second["sequence"]:
        raise ChannelContractError("A4_CH_SNAPSHOT_DUPLICATE_SEQUENCE")
    if second["sequence"] <= first["sequence"]:
        raise ChannelContractError("A4_CH_SNAPSHOT_NONMONOTONIC")
    if first["observedAtMonotonicMs"] >= second["observedAtMonotonicMs"]:
        raise ChannelContractError("A4_CH_SNAPSHOT_NONMONOTONIC")


def evaluate_privileged_channel_exchange(
    request_bytes: Any,
    response_bytes: Any,
    *,
    expected_nonce: str,
    expected_correlation: str,
) -> dict[str, object]:
    """Parse and validate one closed-channel exchange. Never returns runtime A4 PASS."""
    if not isinstance(expected_nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_nonce):
        return hold("A4_CH_TRUSTED_NONCE_INVALID")
    try:
        expected_correlation = _require_text("correlation", expected_correlation)
    except ChannelContractError as exc:
        return hold(exc.reason_code)
    try:
        _ensure_bytes(request_bytes)
        _ensure_bytes(response_bytes)
        request = _parse_json_bytes(request_bytes)
        response = _parse_json_bytes(response_bytes)
        _reject_floats(request)
        _reject_floats(response)
        _validate_closed_request(request)
        _validate_closed_response(
            response,
            expected_nonce=expected_nonce,
            expected_correlation=expected_correlation,
        )
    except ChannelContractError as exc:
        return hold(exc.reason_code)
    result = _data_only()
    assert not result["a4Pass"]
    assert not result["privilegedChannelAuthenticated"]
    assert not result["runtimeAuthority"]
    return result


def build_closed_request_json() -> bytes:
    """Test helper: canonical closed request bytes (not evidence)."""
    return json.dumps(
        {"schemaVersion": SCHEMA_VERSION, "operation": OPERATION, "arguments": []},
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
