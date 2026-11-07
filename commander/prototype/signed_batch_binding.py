"""Synthetic signed-batch binding. Verifier only.

A passing result means one Ed25519 signature matches one canonical batch
digest. It is not owner presence, a protected signer, or permission to spawn.
The in-memory nonce ledger is process-local test state, not OS-protected replay
storage. owner_decision.py v1 signatures are a different schema and are refused.
"""
from __future__ import annotations

import base64
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from canonical_command_batch import (
    PRIVILEGE_MODE, BatchRefused, canonical_batch_sha256, parse_canonical_batch,
)

DECISION_VERSION = "ldw.commander.signed-batch-decision.v1"
RISK_CLASS = "SYNTHETIC_BATCH_CRITICAL_RISK_ACKNOWLEDGED"
_FIELDS = frozenset({
    "version", "decision_id", "batch_id", "session_id", "host_id", "operator",
    "signer_key_id", "signer_generation", "privilege_mode", "batch_sha256",
    "intent_sha256", "issued_unix", "expires_unix", "generation",
    "max_commands", "risk_class", "nonce",
})


class BatchDecisionRefused(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SyntheticNonceLedger:
    """One-use nonce set for this process only. Not durable or OS-protected."""

    def __init__(self):
        self._used: set[str] = set()

    def consume(self, nonce: str) -> None:
        if nonce in self._used:
            raise BatchDecisionRefused("BATCH_REPLAY")
        self._used.add(nonce)


def _b64decode(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded or len(encoded) > 12000:
        raise BatchDecisionRefused("SIGNATURE_INVALID")
    try:
        return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (TypeError, ValueError):
        raise BatchDecisionRefused("SIGNATURE_INVALID") from None


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    names = [name for name, _value in pairs]
    if len(names) != len(set(names)):
        raise BatchDecisionRefused("NONCANONICAL_ENCODING")
    return dict(pairs)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def verify_signed_batch(
    token: str,
    public_key: Ed25519PublicKey,
    batch_raw: bytes,
    *,
    host_id: str,
    operator: str,
    signer_key_id: str,
    signer_generation: int,
    generation: int,
    now_unix: int,
    ledger: SyntheticNonceLedger,
) -> dict:
    """Check the signature and exact batch bytes. Does not execute a command."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise BatchDecisionRefused("SIGNATURE_INVALID")
    if not isinstance(ledger, SyntheticNonceLedger):
        raise BatchDecisionRefused("REPLAY_STATE_REQUIRED")
    if not isinstance(token, str) or token.count(".") != 1 or len(token) > 16000:
        raise BatchDecisionRefused("SIGNATURE_INVALID")
    encoded, encoded_sig = token.split(".")
    raw, signature = _b64decode(encoded), _b64decode(encoded_sig)
    try:
        public_key.verify(signature, raw)
    except InvalidSignature:
        raise BatchDecisionRefused("WRONG_KEY") from None
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except BatchDecisionRefused:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise BatchDecisionRefused("SCHEMA_MISMATCH") from None
    if type(parsed) is not dict or set(parsed) != _FIELDS or _canonical(parsed) != raw:
        raise BatchDecisionRefused("NONCANONICAL_ENCODING")
    if parsed["version"] != DECISION_VERSION or parsed["risk_class"] != RISK_CLASS:
        raise BatchDecisionRefused("NOT_BATCH_DECISION")
    if parsed["host_id"] != host_id:
        raise BatchDecisionRefused("WRONG_HOST")
    if parsed["operator"] != operator:
        raise BatchDecisionRefused("WRONG_OPERATOR")
    if parsed["signer_key_id"] != signer_key_id or parsed["signer_generation"] != signer_generation:
        raise BatchDecisionRefused("WRONG_SIGNER")
    if parsed["privilege_mode"] != PRIVILEGE_MODE:
        raise BatchDecisionRefused("WRONG_MODE")
    if parsed["generation"] != generation:
        raise BatchDecisionRefused("STALE_GENERATION")
    if type(batch_raw) is not bytes or canonical_batch_sha256(batch_raw) != parsed["batch_sha256"]:
        raise BatchDecisionRefused("BATCH_NOT_BOUND")
    try:
        batch = parse_canonical_batch(
            batch_raw, host_id=host_id, privilege_mode=PRIVILEGE_MODE,
            generation=generation, now_unix=now_unix,
        )
    except BatchRefused as refused:
        raise BatchDecisionRefused("BATCH_NOT_BOUND") from refused
    intent_hash = hashlib.sha256(batch["intent_text"].encode("utf-8")).hexdigest()
    if (
        parsed["intent_sha256"] != intent_hash or
        parsed["decision_id"] != batch["decision_id"] or
        parsed["batch_id"] != batch["batch_id"] or
        parsed["session_id"] != batch["session_id"] or
        parsed["signer_key_id"] != batch["signer_key_id"] or
        parsed["issued_unix"] != batch["issued_unix"] or
        parsed["expires_unix"] != batch["expires_unix"] or
        parsed["max_commands"] != batch["max_commands"] or
        any(item["argv"][0] != "ldw-canary" for item in batch["commands"])
    ):
        raise BatchDecisionRefused("BATCH_NOT_BOUND")
    ledger.consume(parsed["nonce"])
    return {
        "decision_id": parsed["decision_id"],
        "batch_id": parsed["batch_id"],
        "batch_sha256": parsed["batch_sha256"],
        "command_ids": [item["command_id"] for item in batch["commands"]],
    }
