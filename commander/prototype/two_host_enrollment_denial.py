"""Compose-only two-host enrollment binding (#209).

Uses existing batch, signed-batch, Gate A, and session trust structures.
No network, shell, filesystem writes, or execute:true admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from canonical_command_batch import PRIVILEGE_MODE
from gate_a_admission import (
    ADMISSION_CONTRACT,
    ADMISSION_MODE,
    ADMITTED_STATUS,
    GateAAdmission,
    GateARefused,
    SplitBrainRegistry,
    TrustedContext,
)
from session import OwnerPolicy, SessionIssuer, SessionRefused, SyntheticAgent
from signed_batch_binding import (
    DECISION_VERSION,
    RISK_CLASS,
    BatchDecisionRefused,
    SyntheticNonceLedger,
    verify_signed_batch,
)

HOST_A = "host:synthetic-a"
HOST_B = "host:synthetic-b"
OPERATOR = "owner-synthetic"
SIGNER_KEY_ID = "signer-key:public-ref-1"
SIGNER_GENERATION = 2
BATCH_GENERATION = 3
NOW_UNIX = 1_700_000_000


def _b64(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SyntheticHostEnrollment:
    """Disposable enrollment record. Not live host pairing or TPM state."""

    host_id: str
    issuer_public_key: Ed25519PublicKey
    signer_epoch: int = 1
    revoked: bool = False


@dataclass(frozen=True)
class SignedBatchArtifacts:
    batch_raw: bytes
    batch: dict
    decision_token: str
    nonce: str


class TwoHostEnrollmentDenialProbe:
    """Wires two independent synthetic host enrollments to shared signer fixtures."""

    def __init__(
        self,
        *,
        signer_private: Ed25519PrivateKey,
        issuer_private: Ed25519PrivateKey,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._signer_private = signer_private
        self._signer_public = signer_private.public_key()
        self._issuer_private = issuer_private
        self._issuer_public = issuer_private.public_key()
        self._clock = clock if clock is not None else (lambda: float(NOW_UNIX))
        self._nonce_ledger = SyntheticNonceLedger()
        self._split_brain = SplitBrainRegistry()
        self._host_a = SyntheticHostEnrollment(HOST_A, self._issuer_public, signer_epoch=1)
        self._host_b = SyntheticHostEnrollment(HOST_B, self._issuer_public, signer_epoch=1)
        self._policy_a = OwnerPolicy(
            policy_id="synthetic-two-host-policy-a",
            operator=OPERATOR,
            host=HOST_A,
            max_privilege="OBSERVE",
            max_ttl_seconds=60,
        )
        self._policy_b = OwnerPolicy(
            policy_id="synthetic-two-host-policy-b",
            operator=OPERATOR,
            host=HOST_B,
            max_privilege="OBSERVE",
            max_ttl_seconds=60,
        )
        self._issuer_a = SessionIssuer(
            self._issuer_private, self._policy_a, clock=self._clock, epoch=1,
        )
        self._issuer_b = SessionIssuer(
            self._issuer_private, self._policy_b, clock=self._clock, epoch=1,
        )
        self._agent_a = SyntheticAgent(
            self._issuer_public, self._policy_a, HOST_A,
            clock=self._clock, epoch=1,
        )
        self._agent_b = SyntheticAgent(
            self._issuer_public, self._policy_b, HOST_B,
            clock=self._clock, epoch=1,
        )

    @property
    def host_a(self) -> SyntheticHostEnrollment:
        return self._host_a

    @property
    def host_b(self) -> SyntheticHostEnrollment:
        return self._host_b

    def gate_for(self, host_id: str) -> GateAAdmission:
        return GateAAdmission(
            TrustedContext(
                host_id=host_id,
                operator=OPERATOR,
                signer_key_id=SIGNER_KEY_ID,
                signer_generation=SIGNER_GENERATION,
                batch_generation=BATCH_GENERATION,
                signer_public_key=self._signer_public,
                nonce_ledger=self._nonce_ledger,
            ),
            clock=lambda: NOW_UNIX,
            split_brain=self._split_brain,
        )

    def sign_batch_raw(
        self, host_id: str, batch_raw: bytes, parsed: dict, *, nonce: str | None = None,
    ) -> SignedBatchArtifacts:
        use_nonce = nonce or str(uuid.uuid4())
        document = {
            "version": DECISION_VERSION,
            "decision_id": parsed["decision_id"],
            "batch_id": parsed["batch_id"],
            "session_id": parsed["session_id"],
            "host_id": host_id,
            "operator": OPERATOR,
            "signer_key_id": SIGNER_KEY_ID,
            "signer_generation": SIGNER_GENERATION,
            "privilege_mode": PRIVILEGE_MODE,
            "batch_sha256": hashlib.sha256(batch_raw).hexdigest(),
            "intent_sha256": hashlib.sha256(parsed["intent_text"].encode("utf-8")).hexdigest(),
            "issued_unix": parsed["issued_unix"],
            "expires_unix": parsed["expires_unix"],
            "generation": parsed["generation"],
            "max_commands": parsed["max_commands"],
            "risk_class": RISK_CLASS,
            "nonce": use_nonce,
        }
        raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        token = _b64(raw) + "." + _b64(self._signer_private.sign(raw))
        return SignedBatchArtifacts(
            batch_raw=batch_raw, batch=parsed, decision_token=token, nonce=use_nonce,
        )

    def build_signed_batch(self, host_id: str, *, nonce: str | None = None) -> SignedBatchArtifacts:
        from test_canonical_command_batch import _document, _parse, _raw

        ids = {
            HOST_A: (
                "33333333-3333-4333-8333-33333333330a",
                "44444444-4444-4444-8444-44444444440a",
                "22222222-2222-4222-8222-22222222220a",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa0a",
            ),
            HOST_B: (
                "33333333-3333-4333-8333-33333333330b",
                "44444444-4444-4444-8444-44444444440b",
                "22222222-2222-4222-8222-22222222220b",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa0b",
            ),
        }
        decision_id, session_id, batch_id, default_nonce = ids[host_id]
        batch = _document(
            host_id=host_id,
            decision_id=decision_id,
            session_id=session_id,
            batch_id=batch_id,
        )
        batch_raw = _raw(batch)
        parsed = _parse(batch_raw, host_id=host_id)
        use_nonce = nonce or default_nonce
        return self.sign_batch_raw(host_id, batch_raw, parsed, nonce=use_nonce)

    def admit_synthetic(self, host_id: str, artifacts: SignedBatchArtifacts) -> dict:
        from test_canonical_command_batch import COMMAND_ID, PAYLOAD

        proposal = {
            "contract": ADMISSION_CONTRACT,
            "execute": False,
            "privilege_mode": ADMISSION_MODE,
            "batch_raw": artifacts.batch_raw,
            "decision_token": artifacts.decision_token,
            "command_id": COMMAND_ID,
            "payload": PAYLOAD,
        }
        return self.gate_for(host_id).admit(proposal)

    def verify_batch_binding(self, host_id: str, artifacts: SignedBatchArtifacts, **kwargs) -> dict:
        return verify_signed_batch(
            artifacts.decision_token,
            self._signer_public,
            artifacts.batch_raw,
            host_id=host_id,
            operator=OPERATOR,
            signer_key_id=SIGNER_KEY_ID,
            signer_generation=kwargs.get("signer_generation", SIGNER_GENERATION),
            generation=kwargs.get("generation", BATCH_GENERATION),
            now_unix=kwargs.get("now_unix", NOW_UNIX),
            ledger=self._nonce_ledger,
        )

    def issue_observe_session(self, host_id: str, ttl: int = 30) -> str:
        issuer = self._issuer_a if host_id == HOST_A else self._issuer_b
        return issuer.issue(OPERATOR, host_id, "OBSERVE", ttl)

    def open_session(self, host_id: str, token: str) -> dict:
        agent = self._agent_a if host_id == HOST_A else self._agent_b
        return agent.open(token, OPERATOR)

    def revoke_session(self, host_id: str, session_id: str) -> dict:
        agent = self._agent_a if host_id == HOST_A else self._agent_b
        return agent.revoke(session_id)

    def rotate_epoch(self, host_id: str, epoch: int) -> None:
        agent = self._agent_a if host_id == HOST_A else self._agent_b
        agent.set_epoch(epoch)

    @staticmethod
    def admitted_no_execution(admitted: dict) -> None:
        if admitted.get("status") != ADMITTED_STATUS:
            raise AssertionError("expected ADMITTED_SYNTHETIC_NO_EXECUTION")
        if admitted.get("execute") is not False:
            raise AssertionError("execute must remain false")


__all__ = [
    "BatchDecisionRefused",
    "GateARefused",
    "HOST_A",
    "HOST_B",
    "NOW_UNIX",
    "SessionRefused",
    "SignedBatchArtifacts",
    "SyntheticHostEnrollment",
    "TwoHostEnrollmentDenialProbe",
]
