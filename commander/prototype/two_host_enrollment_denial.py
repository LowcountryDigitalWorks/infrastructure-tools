"""Compose-only two-host enrollment binding (#209).

Uses existing batch, signed-batch, Gate A, and session trust structures.
No network, shell, filesystem writes, or execute:true admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, replace
from typing import Callable, Mapping

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
    SplitBrainRegistry,
    TrustedContext,
)
from session import OwnerPolicy, SessionIssuer, SessionRefused, SyntheticAgent
from signed_batch_binding import (
    DECISION_VERSION,
    RISK_CLASS,
    SyntheticNonceLedger,
    verify_signed_batch,
)

HOST_A = "host:synthetic-a"
HOST_B = "host:synthetic-b"
ENROLLED_HOST_IDS = frozenset({HOST_A, HOST_B})
OPERATOR = "owner-synthetic"
SIGNER_KEY_ID = "signer-key:public-ref-1"
BATCH_GENERATION = 3
NOW_UNIX = 1_700_000_000


class EnrollmentRefused(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SyntheticHostEnrollment:
    """Immutable enrolled-host record for the closed A/B synthetic fleet."""

    host_id: str
    issuer_public_key: Ed25519PublicKey
    owner_signer_generation: int = 2
    session_epoch: int = 1
    revoked: bool = False


@dataclass(frozen=True)
class SignedBatchArtifacts:
    batch_raw: bytes
    batch: dict
    decision_token: str
    nonce: str


class TwoHostEnrollmentDenialProbe:
    """Closed registry of exactly two synthetic host enrollments."""

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
        self._enrollments: dict[str, SyntheticHostEnrollment] = {
            HOST_A: SyntheticHostEnrollment(HOST_A, self._issuer_public),
            HOST_B: SyntheticHostEnrollment(HOST_B, self._issuer_public),
        }
        self._policies: dict[str, OwnerPolicy] = {}
        self._issuers: dict[str, SessionIssuer] = {}
        self._agents: dict[str, SyntheticAgent] = {}
        for host_id, record in self._enrollments.items():
            policy = OwnerPolicy(
                policy_id=f"synthetic-two-host-policy-{host_id[-1]}",
                operator=OPERATOR,
                host=host_id,
                max_privilege="OBSERVE",
                max_ttl_seconds=60,
            )
            self._policies[host_id] = policy
            self._issuers[host_id] = SessionIssuer(
                self._issuer_private,
                policy,
                clock=self._clock,
                epoch=record.session_epoch,
            )
            self._agents[host_id] = SyntheticAgent(
                self._issuer_public,
                policy,
                host_id,
                clock=self._clock,
                epoch=record.session_epoch,
            )

    @property
    def enrollments(self) -> Mapping[str, SyntheticHostEnrollment]:
        return self._enrollments

    @property
    def host_a(self) -> SyntheticHostEnrollment:
        return self._enrollments[HOST_A]

    @property
    def host_b(self) -> SyntheticHostEnrollment:
        return self._enrollments[HOST_B]

    def require_enrolled_host(self, host_id: str) -> SyntheticHostEnrollment:
        if host_id not in ENROLLED_HOST_IDS:
            raise EnrollmentRefused("ENROLLED_HOST_UNKNOWN")
        record = self._enrollments.get(host_id)
        if record is None:
            raise EnrollmentRefused("ENROLLED_HOST_UNKNOWN")
        if record.host_id != host_id:
            raise EnrollmentRefused("ENROLLED_HOST_UNKNOWN")
        if record.revoked:
            raise EnrollmentRefused("ENROLLMENT_REVOKED")
        return record

    def revoke_enrollment(self, host_id: str) -> SyntheticHostEnrollment:
        if host_id not in ENROLLED_HOST_IDS:
            raise EnrollmentRefused("ENROLLED_HOST_UNKNOWN")
        current = self._enrollments[host_id]
        updated = replace(current, revoked=True)
        self._enrollments[host_id] = updated
        return updated

    def gate_for(self, host_id: str) -> GateAAdmission:
        record = self.require_enrolled_host(host_id)
        return GateAAdmission(
            TrustedContext(
                host_id=record.host_id,
                operator=OPERATOR,
                signer_key_id=SIGNER_KEY_ID,
                signer_generation=record.owner_signer_generation,
                batch_generation=BATCH_GENERATION,
                signer_public_key=self._signer_public,
                nonce_ledger=self._nonce_ledger,
            ),
            clock=lambda: NOW_UNIX,
            split_brain=self._split_brain,
        )

    def sign_batch_raw(
        self,
        record: SyntheticHostEnrollment,
        batch_raw: bytes,
        parsed: dict,
        *,
        nonce: str | None = None,
    ) -> SignedBatchArtifacts:
        use_nonce = nonce or str(uuid.uuid4())
        document = {
            "version": DECISION_VERSION,
            "decision_id": parsed["decision_id"],
            "batch_id": parsed["batch_id"],
            "session_id": parsed["session_id"],
            "host_id": record.host_id,
            "operator": OPERATOR,
            "signer_key_id": SIGNER_KEY_ID,
            "signer_generation": record.owner_signer_generation,
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
        record = self.require_enrolled_host(host_id)
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
        if record.host_id not in ids:
            raise EnrollmentRefused("ENROLLED_HOST_UNKNOWN")
        decision_id, session_id, batch_id, default_nonce = ids[record.host_id]
        batch = _document(
            host_id=record.host_id,
            decision_id=decision_id,
            session_id=session_id,
            batch_id=batch_id,
        )
        batch_raw = _raw(batch)
        parsed = _parse(batch_raw, host_id=record.host_id)
        use_nonce = nonce or default_nonce
        return self.sign_batch_raw(record, batch_raw, parsed, nonce=use_nonce)

    def admit_synthetic(self, host_id: str, artifacts: SignedBatchArtifacts) -> dict:
        from test_canonical_command_batch import COMMAND_ID, PAYLOAD

        record = self.require_enrolled_host(host_id)
        proposal = {
            "contract": ADMISSION_CONTRACT,
            "execute": False,
            "privilege_mode": ADMISSION_MODE,
            "batch_raw": artifacts.batch_raw,
            "decision_token": artifacts.decision_token,
            "command_id": COMMAND_ID,
            "payload": PAYLOAD,
        }
        return self.gate_for(record.host_id).admit(proposal)

    def verify_batch_binding(self, host_id: str, artifacts: SignedBatchArtifacts, **kwargs) -> dict:
        record = self.require_enrolled_host(host_id)
        expected_generation = kwargs.get("signer_generation", record.owner_signer_generation)
        if expected_generation != record.owner_signer_generation:
            raise EnrollmentRefused("SIGNER_GENERATION_MISMATCH")
        return verify_signed_batch(
            artifacts.decision_token,
            self._signer_public,
            artifacts.batch_raw,
            host_id=record.host_id,
            operator=OPERATOR,
            signer_key_id=SIGNER_KEY_ID,
            signer_generation=record.owner_signer_generation,
            generation=kwargs.get("generation", BATCH_GENERATION),
            now_unix=kwargs.get("now_unix", NOW_UNIX),
            ledger=self._nonce_ledger,
        )

    def issue_observe_session(self, host_id: str, ttl: int = 30) -> str:
        record = self.require_enrolled_host(host_id)
        return self._issuers[record.host_id].issue(
            OPERATOR, record.host_id, "OBSERVE", ttl,
        )

    def open_session(self, host_id: str, token: str) -> dict:
        record = self.require_enrolled_host(host_id)
        return self._agents[record.host_id].open(token, OPERATOR)

    def revoke_session(self, host_id: str, session_id: str) -> dict:
        record = self.require_enrolled_host(host_id)
        return self._agents[record.host_id].revoke(session_id)

    def rotate_epoch(self, host_id: str, epoch: int) -> None:
        record = self.require_enrolled_host(host_id)
        self._agents[record.host_id].set_epoch(epoch)
        updated = replace(record, session_epoch=epoch)
        self._enrollments[record.host_id] = updated

    @staticmethod
    def admitted_no_execution(admitted: dict) -> None:
        if admitted.get("status") != ADMITTED_STATUS:
            raise AssertionError("expected ADMITTED_SYNTHETIC_NO_EXECUTION")
        if admitted.get("execute") is not False:
            raise AssertionError("execute must remain false")


__all__ = [
    "ENROLLED_HOST_IDS",
    "EnrollmentRefused",
    "HOST_A",
    "HOST_B",
    "NOW_UNIX",
    "SessionRefused",
    "SignedBatchArtifacts",
    "SyntheticHostEnrollment",
    "TwoHostEnrollmentDenialProbe",
]
