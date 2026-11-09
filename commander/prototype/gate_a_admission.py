"""Gate A synthetic admission — verifier only (infrastructure-tools #209).

Composes canonical batch parsing and signed-batch binding. A passing admission
means schema/signature/batch identity checks succeeded under SYNTHETIC_NO_EXECUTION.
It does not execute argv, open sockets, call the Admin Broker, or prove owner
physical presence. Software test keys are fixture-only trust roots.
"""
from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass
from typing import Callable

from canonical_command_batch import (
    MAX_DOCUMENT_BYTES,
    PRIVILEGE_MODE,
    BatchRefused,
    parse_canonical_batch,
    payload_matches,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from model_output_boundary import project_model_output
from signed_batch_binding import (
    BatchDecisionRefused,
    SyntheticNonceLedger,
    verify_signed_batch,
)

ADMISSION_CONTRACT = "ldw.commander.gate-a-admission.v1"
ADMISSION_MODE = "SYNTHETIC_NO_EXECUTION"
ADMITTED_STATUS = "ADMITTED_SYNTHETIC_NO_EXECUTION"
FORBIDDEN_BROKER_OPERATION = "ELEVATED_IDENTITY_PROOF"
_EXPECTED_REQUEST_FIELDS = frozenset({
    "contract",
    "execute",
    "privilege_mode",
    "batch_raw",
    "decision_token",
    "command_id",
    "payload",
})
_UNTRUSTED_TEXT = re.compile(
    r"(bind_port|listen_endpoint|\bendpoint\b|https?://|wss://|"
    r"approved\s*=\s*true|Eddie approved|owner approved via chat|browser consent)",
    re.IGNORECASE,
)
_FORBIDDEN_MODES = frozenset({
    "FULL_ADMIN-UNRESTRICTED",
    "FULL_ADMIN-CONFINED",
    "FULL_ADMIN",
    "UNKNOWN",
})
MAX_PAYLOAD_BYTES = MAX_DOCUMENT_BYTES
MAX_DECISION_TOKEN_CHARS = 16000
MAX_SHORT_TEXT_CHARS = 128


class GateARefused(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class TrustedContext:
    """Independent fixture trust root. Not populated from an untrusted request."""

    host_id: str
    operator: str
    signer_key_id: str
    signer_generation: int
    batch_generation: int
    signer_public_key: Ed25519PublicKey
    nonce_ledger: SyntheticNonceLedger


class SplitBrainRegistry:
    """Tracks one batch digest per decision_id within this process."""

    def __init__(self) -> None:
        self._bindings: dict[str, str] = {}
        self._lock = threading.Lock()

    def record(self, decision_id: str, batch_sha256: str) -> None:
        with self._lock:
            existing = self._bindings.get(decision_id)
            if existing is not None and existing != batch_sha256:
                raise GateARefused("SPLIT_BRAIN")
            self._bindings[decision_id] = batch_sha256


def _uuid_text(value: object) -> str:
    if type(value) is not str or len(value) != 36:
        raise GateARefused("SCHEMA_MISMATCH")
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise GateARefused("SCHEMA_MISMATCH") from None
    if parsed != value:
        raise GateARefused("SCHEMA_MISMATCH")
    return value


def _reject_untrusted_markers(value: object) -> None:
    if type(value) is not str:
        return
    if _UNTRUSTED_TEXT.search(value):
        raise GateARefused("UNTRUSTED_CONSENT_OR_TRANSPORT")
    for forbidden in _FORBIDDEN_MODES:
        if forbidden in value:
            raise GateARefused("MODE_NOT_AUTHORIZED")


def _bounded_short_text(value: object, *, field: str) -> str:
    if type(value) is not str or not value or len(value) > MAX_SHORT_TEXT_CHARS:
        raise GateARefused("SCHEMA_MISMATCH")
    _reject_untrusted_markers(value)
    return value


def _bounded_bytes(value: object, *, limit: int, too_large_reason: str) -> bytes:
    if type(value) is not bytes or not value:
        raise GateARefused("SCHEMA_MISMATCH")
    if len(value) > limit:
        raise GateARefused(too_large_reason)
    return value


def _bounded_token(value: object) -> str:
    if type(value) is not str or not value or len(value) > MAX_DECISION_TOKEN_CHARS:
        raise GateARefused("SCHEMA_MISMATCH")
    return value


def _scan_bounded_request_strings(contract: str, privilege_mode: str, command_id: str) -> None:
    """Scan only closed short string fields; never walk batch bytes or payloads."""
    for text in (contract, privilege_mode, command_id):
        _reject_untrusted_markers(text)


class GateAAdmission:
    """Fail-closed synthetic Gate A admission. Never spawns a process."""

    def __init__(
        self,
        context: TrustedContext,
        *,
        clock: Callable[[], int],
        split_brain: SplitBrainRegistry | None = None,
    ):
        if not isinstance(context.signer_public_key, Ed25519PublicKey):
            raise ValueError("TRUSTED_SIGNER_PUBLIC_KEY_REQUIRED")
        if type(context.signer_generation) is not int or isinstance(context.signer_generation, bool):
            raise ValueError("TRUSTED_SIGNER_GENERATION_REQUIRED")
        self._context = context
        self._clock = clock
        self._split_brain = split_brain if split_brain is not None else SplitBrainRegistry()

    def admit(self, proposed: object) -> dict[str, object]:
        if (
            type(proposed) is not dict
            or len(proposed) != len(_EXPECTED_REQUEST_FIELDS)
            or set(proposed) != _EXPECTED_REQUEST_FIELDS
        ):
            raise GateARefused("SCHEMA_MISMATCH")
        contract = _bounded_short_text(proposed["contract"], field="contract")
        if contract != ADMISSION_CONTRACT:
            raise GateARefused("WRONG_CONTRACT")
        execute = proposed["execute"]
        if type(execute) is not bool or execute is not False:
            raise GateARefused("EXECUTE_FORBIDDEN")
        privilege_mode = _bounded_short_text(proposed["privilege_mode"], field="privilege_mode")
        if privilege_mode != ADMISSION_MODE:
            raise GateARefused("MODE_NOT_AUTHORIZED")
        batch_raw = _bounded_bytes(
            proposed["batch_raw"], limit=MAX_DOCUMENT_BYTES, too_large_reason="SCHEMA_MISMATCH",
        )
        decision_token = _bounded_token(proposed["decision_token"])
        command_id = _uuid_text(proposed["command_id"])
        payload = _bounded_bytes(
            proposed["payload"], limit=MAX_PAYLOAD_BYTES, too_large_reason="PAYLOAD_TOO_LARGE",
        )
        _scan_bounded_request_strings(contract, privilege_mode, command_id)
        if FORBIDDEN_BROKER_OPERATION.encode("ascii") in payload:
            raise GateARefused("BROKER_OPERATION_REFUSED")
        now_unix = int(self._clock())
        context = self._context
        try:
            batch = parse_canonical_batch(
                batch_raw,
                host_id=context.host_id,
                privilege_mode=PRIVILEGE_MODE,
                generation=context.batch_generation,
                now_unix=now_unix,
            )
        except BatchRefused as refused:
            if refused.reason in {"EXPIRED_OR_AMBIGUOUS_TTL", "STALE_GENERATION", "WRONG_HOST", "WRONG_MODE"}:
                raise GateARefused(refused.reason) from refused
            raise GateARefused("BATCH_NOT_BOUND") from refused
        command_ids = [item["command_id"] for item in batch["commands"]]
        if command_id not in command_ids:
            raise GateARefused("COMMAND_NOT_IN_BATCH")
        try:
            payload_matches(batch, command_id, payload)
        except BatchRefused as refused:
            raise GateARefused("HASH_MISMATCH") from refused
        if any(item["argv"][0] != "ldw-canary" for item in batch["commands"]):
            raise GateARefused("EXECUTABLE_NOT_ALLOWED")
        try:
            bound = verify_signed_batch(
                decision_token,
                context.signer_public_key,
                batch_raw,
                host_id=context.host_id,
                operator=context.operator,
                signer_key_id=context.signer_key_id,
                signer_generation=context.signer_generation,
                generation=context.batch_generation,
                now_unix=now_unix,
                ledger=context.nonce_ledger,
            )
        except BatchDecisionRefused as refused:
            reason = refused.reason
            if reason in {"STALE_GENERATION", "WRONG_SIGNER"}:
                raise GateARefused("STALE_SIGNER_OR_GENERATION") from refused
            if reason == "BATCH_REPLAY":
                raise GateARefused("REPLAY") from refused
            raise GateARefused(reason) from refused
        self._split_brain.record(bound["decision_id"], bound["batch_sha256"])
        if command_id not in bound["command_ids"]:
            raise GateARefused("COMMAND_NOT_IN_BATCH")
        model_projection = project_model_output(payload)
        return {
            "status": ADMITTED_STATUS,
            "execute": False,
            "privilege_mode": ADMISSION_MODE,
            "contract": ADMISSION_CONTRACT,
            "argv0": "ldw-canary",
            "command_id": command_id,
            "model_visible": model_projection,
        }
