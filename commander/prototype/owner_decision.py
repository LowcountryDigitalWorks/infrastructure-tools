"""Gate A1 synthetic *cryptographic* owner-decision evidence.

This deliberately does NOT authenticate a human. A trusted UI/device-bound
owner authenticator is not implemented. Synthetic signer may ONLY be used in
tests; never expose it through a model tool or deploy it as host authority.

One-time FULL_ADMIN decisions are separate from the session issuer key. The
privileged host verifier needs only the separate owner public key.
"""
from __future__ import annotations

import base64
import json
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DECISION_VERSION = "ldw-owner-decision-synthetic-v1"
FULL_ADMIN_RISK = "FULL_ADMIN_HOST_SECRETS_AND_EGRESS_RISK_ACCEPTED"
SCOPE = "SYNTHETIC_CANARY_ONLY"
MAX_DECISION_AGE = 120
FIELDS = frozenset({
    "version", "decision_id", "policy", "host", "operator", "privilege",
    "scope", "risk", "issued", "expires", "epoch", "max_session_seconds"
})


class OwnerDecisionRefused(ValueError):
    def __init__(self):
        super().__init__("OWNER_AUTH_NOT_PROVEN")
        self.reason = "OWNER_AUTH_NOT_PROVEN"


def _enc(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def _dec(encoded: str) -> bytes:
    if not isinstance(encoded, str) or len(encoded) > 4096:
        raise OwnerDecisionRefused()
    try:
        return base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                                altchars=b"-_", validate=True)
    except (TypeError, ValueError):
        raise OwnerDecisionRefused() from None


def parse_and_verify(token: str, owner_public_key: Ed25519PublicKey) -> dict:
    if not isinstance(owner_public_key, Ed25519PublicKey):
        raise OwnerDecisionRefused()
    if not isinstance(token, str) or len(token) > 2048:
        raise OwnerDecisionRefused()
    try:
        text, sig = token.split(".")
        raw, signature = _dec(text), _dec(sig)
        owner_public_key.verify(signature, raw)
        data = json.loads(raw)
    except (ValueError, TypeError, InvalidSignature):
        raise OwnerDecisionRefused() from None
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise OwnerDecisionRefused()
    return data


def verify_decision(token: str, owner_public_key: Ed25519PublicKey, *,
                    policy: str, host: str, operator: str, epoch: int,
                    requested_ttl: int, now: int) -> dict:
    data = parse_and_verify(token, owner_public_key)
    try:
        if (data["version"] != DECISION_VERSION or
            data["policy"] != policy or data["host"] != host or
            data["operator"] != operator or data["privilege"] != "FULL_ADMIN" or
            data["scope"] != SCOPE or data["risk"] != FULL_ADMIN_RISK or
            data["epoch"] != epoch or
            not isinstance(data["issued"], int) or
            not isinstance(data["expires"], int) or
            not isinstance(data["max_session_seconds"], int) or
            data["issued"] > now or now >= data["expires"] or
            not 0 < data["expires"] - data["issued"] <= MAX_DECISION_AGE or
            not 0 < requested_ttl <= data["max_session_seconds"] or
            data["max_session_seconds"] > MAX_DECISION_AGE or
            str(uuid.UUID(data["decision_id"])) != data["decision_id"]):
            raise OwnerDecisionRefused()
    except (ValueError, TypeError, KeyError):
        raise OwnerDecisionRefused() from None
    return data


class SyntheticOwnerDecisionSigner:
    """Disposable test-only signer. NOT an owner authentication mechanism."""
    def __init__(self, owner_private_key: Ed25519PrivateKey):
        if not isinstance(owner_private_key, Ed25519PrivateKey):
            raise ValueError("SYNTHETIC_SIGNER_KEY_REQUIRED")
        self._private_key = owner_private_key

    def sign(self, *, policy: str, host: str, operator: str,
             issued: int, duration: int, max_session_seconds: int,
             epoch: int = 1, scope: str = SCOPE,
             risk: str = FULL_ADMIN_RISK) -> str:
        data = {
            "version": DECISION_VERSION,
            "decision_id": str(uuid.uuid4()),
            "policy": policy,
            "host": host,
            "operator": operator,
            "privilege": "FULL_ADMIN",
            "scope": scope,
            "risk": risk,
            "issued": issued,
            "expires": issued + duration,
            "epoch": epoch,
            "max_session_seconds": max_session_seconds,
        }
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        return _enc(payload) + "." + _enc(self._private_key.sign(payload))
