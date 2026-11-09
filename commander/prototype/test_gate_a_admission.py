"""Hostile negatives for Gate A synthetic admission (#209). Test keys only."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_canonical_command_batch as batch_fixture
from canonical_command_batch import ENVELOPE_VERSION, PRIVILEGE_MODE
from gate_a_admission import (
    ADMISSION_CONTRACT,
    ADMISSION_MODE,
    ADMITTED_STATUS,
    FORBIDDEN_BROKER_OPERATION,
    GateAAdmission,
    GateARefused,
    SplitBrainRegistry,
    TrustedContext,
)
from signed_batch_binding import DECISION_VERSION, RISK_CLASS, SyntheticNonceLedger

OPERATOR = "owner-synthetic"
SIGNER_GENERATION = 2
NOW = batch_fixture.NOW


def _b64(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def _decision(batch_raw: bytes, batch: dict, private: Ed25519PrivateKey, *, nonce: str | None = None) -> str:
    document = {
        "version": DECISION_VERSION,
        "decision_id": batch["decision_id"],
        "batch_id": batch["batch_id"],
        "session_id": batch["session_id"],
        "host_id": batch["host_id"],
        "operator": OPERATOR,
        "signer_key_id": batch["signer_key_id"],
        "signer_generation": SIGNER_GENERATION,
        "privilege_mode": PRIVILEGE_MODE,
        "batch_sha256": hashlib.sha256(batch_raw).hexdigest(),
        "intent_sha256": hashlib.sha256(batch["intent_text"].encode("utf-8")).hexdigest(),
        "issued_unix": batch["issued_unix"],
        "expires_unix": batch["expires_unix"],
        "generation": batch["generation"],
        "max_commands": batch["max_commands"],
        "risk_class": RISK_CLASS,
        "nonce": nonce or str(uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return _b64(raw) + "." + _b64(private.sign(raw))


def _context(public: Ed25519PrivateKey, ledger: SyntheticNonceLedger | None = None) -> TrustedContext:
    return TrustedContext(
        host_id=batch_fixture.HOST,
        operator=OPERATOR,
        signer_key_id=batch_fixture.SIGNER,
        signer_generation=SIGNER_GENERATION,
        batch_generation=3,
        signer_public_key=public.public_key(),
        nonce_ledger=ledger if ledger is not None else SyntheticNonceLedger(),
    )


def _proposal(token: str, batch_raw: bytes, **overrides) -> dict:
    base = {
        "contract": ADMISSION_CONTRACT,
        "execute": False,
        "privilege_mode": ADMISSION_MODE,
        "batch_raw": batch_raw,
        "decision_token": token,
        "command_id": batch_fixture.COMMAND_ID,
        "payload": batch_fixture.PAYLOAD,
    }
    base.update(overrides)
    return base


class GateAAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.batch_raw = batch_fixture._raw()
        self.batch = batch_fixture._parse(self.batch_raw)
        self.token = _decision(self.batch_raw, self.batch, self.private)
        self.admission = GateAAdmission(_context(self.private), clock=lambda: NOW)

    def test_admitted_synthetic_no_execution_fixed_argv0(self) -> None:
        admitted = self.admission.admit(_proposal(self.token, self.batch_raw))
        self.assertEqual(admitted["status"], ADMITTED_STATUS)
        self.assertIs(admitted["execute"], False)
        self.assertEqual(admitted["privilege_mode"], ADMISSION_MODE)
        self.assertEqual(admitted["argv0"], "ldw-canary")
        self.assertEqual(admitted["model_visible"], {"status": "MODEL_OUTPUT_BLOCKED"})
        self.assertNotIn("password", json.dumps(admitted))

    def test_wrong_enrolled_host_refused(self) -> None:
        other = GateAAdmission(
            TrustedContext(
                host_id=batch_fixture.OTHER_HOST,
                operator=OPERATOR,
                signer_key_id=batch_fixture.SIGNER,
                signer_generation=SIGNER_GENERATION,
                batch_generation=3,
                signer_public_key=self.private.public_key(),
                nonce_ledger=SyntheticNonceLedger(),
            ),
            clock=lambda: NOW,
        )
        with self.assertRaises(GateARefused) as refused:
            other.admit(_proposal(self.token, self.batch_raw))
        self.assertEqual(refused.exception.reason, "WRONG_HOST")

    def test_model_selected_bind_port_url_and_listen_refused(self) -> None:
        for marker in ("bind_port=8080", "wss://evil", "listen_endpoint", "https://leak"):
            with self.subTest(marker=marker):
                with self.assertRaises(GateARefused):
                    self.admission.admit(_proposal(self.token, self.batch_raw, payload=marker.encode()))

    def test_untrusted_pseudo_consent_refused(self) -> None:
        for marker in ("approved=true", "Eddie approved", "browser consent granted"):
            with self.subTest(marker=marker):
                with self.assertRaises(GateARefused):
                    self.admission.admit(_proposal(self.token, self.batch_raw, privilege_mode=marker))

    def test_full_admin_unrestricted_and_unknown_modes_refused(self) -> None:
        for mode in ("FULL_ADMIN-UNRESTRICTED", "FULL_ADMIN", "UNKNOWN"):
            with self.subTest(mode=mode):
                with self.assertRaises(GateARefused):
                    self.admission.admit(_proposal(self.token, self.batch_raw, privilege_mode=mode))

    def test_execute_true_refused(self) -> None:
        with self.assertRaises(GateARefused):
            self.admission.admit(_proposal(self.token, self.batch_raw, execute=True))

    def test_stale_signer_generation_refused(self) -> None:
        stale = GateAAdmission(
            TrustedContext(
                host_id=batch_fixture.HOST,
                operator=OPERATOR,
                signer_key_id=batch_fixture.SIGNER,
                signer_generation=99,
                batch_generation=3,
                signer_public_key=self.private.public_key(),
                nonce_ledger=SyntheticNonceLedger(),
            ),
            clock=lambda: NOW,
        )
        with self.assertRaises(GateARefused) as refused:
            stale.admit(_proposal(self.token, self.batch_raw))
        self.assertEqual(refused.exception.reason, "STALE_SIGNER_OR_GENERATION")

    def test_ttl_boundary_now_equals_expires_refused(self) -> None:
        doc = batch_fixture._document(issued_unix=NOW - 60, expires_unix=NOW)
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        token = _decision(raw, doc, self.private, nonce=str(uuid.uuid4()))
        gate = GateAAdmission(_context(self.private, SyntheticNonceLedger()), clock=lambda: NOW)
        with self.assertRaises(GateARefused) as refused:
            gate.admit(_proposal(token, raw))
        self.assertIn(
            refused.exception.reason,
            {"EXPIRED_OR_AMBIGUOUS_TTL", "BATCH_NOT_BOUND"},
        )

    def test_replay_nonce_refused(self) -> None:
        ledger = SyntheticNonceLedger()
        gate = GateAAdmission(_context(self.private, ledger), clock=lambda: NOW)
        gate.admit(_proposal(self.token, self.batch_raw))
        with self.assertRaises(GateARefused) as refused:
            gate.admit(_proposal(self.token, self.batch_raw))
        self.assertEqual(refused.exception.reason, "REPLAY")

    def test_split_brain_same_decision_different_batch_refused(self) -> None:
        split = SplitBrainRegistry()
        gate = GateAAdmission(_context(self.private, SyntheticNonceLedger()), clock=lambda: NOW, split_brain=split)
        gate.admit(_proposal(self.token, self.batch_raw))
        alt_raw = batch_fixture._raw(batch_fixture._document(intent_text="Different intent only."))
        alt = batch_fixture._parse(alt_raw)
        alt_token = _decision(alt_raw, alt, self.private, nonce=str(uuid.uuid4()))
        with self.assertRaises(GateARefused) as refused:
            gate.admit(_proposal(alt_token, alt_raw))
        self.assertEqual(refused.exception.reason, "SPLIT_BRAIN")

    def test_command_outside_signed_batch_refused(self) -> None:
        other_id = "99999999-9999-4999-8999-999999999999"
        with self.assertRaises(GateARefused):
            self.admission.admit(_proposal(self.token, self.batch_raw, command_id=other_id))

    def test_payload_sha256_mismatch_refused(self) -> None:
        with self.assertRaises(GateARefused) as refused:
            self.admission.admit(_proposal(self.token, self.batch_raw, payload=b"tampered"))
        self.assertEqual(refused.exception.reason, "HASH_MISMATCH")

    def test_broker_elevated_identity_proof_injection_refused(self) -> None:
        payload = FORBIDDEN_BROKER_OPERATION.encode("ascii") + b":attempt"
        with self.assertRaises(GateARefused) as refused:
            self.admission.admit(_proposal(self.token, self.batch_raw, payload=payload))
        self.assertEqual(refused.exception.reason, "BROKER_OPERATION_REFUSED")

    def test_stdout_secret_candidate_never_model_visible(self) -> None:
        admitted = self.admission.admit(_proposal(self.token, self.batch_raw))
        self.assertEqual(admitted["model_visible"]["status"], "MODEL_OUTPUT_BLOCKED")
        blob = json.dumps(admitted)
        self.assertNotIn(batch_fixture.PAYLOAD.decode(), blob)
        self.assertNotIn("supersecret", blob)

    def test_synthetic_fixture_is_not_execution_authority(self) -> None:
        admitted = self.admission.admit(_proposal(self.token, self.batch_raw))
        self.assertNotIn("spawn", admitted)
        self.assertNotIn("admin", admitted)
        self.assertNotIn("OWNER_PRESENCE_PROVEN", admitted)


if __name__ == "__main__":
    unittest.main()
