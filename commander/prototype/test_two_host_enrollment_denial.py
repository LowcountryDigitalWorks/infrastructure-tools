"""Deterministic two-host enrollment / revocation denial matrix (#209)."""
from __future__ import annotations

import unittest
import uuid
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate_a_admission import GateARefused
from session import SessionRefused
from signed_batch_binding import BatchDecisionRefused, SyntheticNonceLedger, verify_signed_batch
import test_canonical_command_batch as batch_fixture
from two_host_enrollment_denial import (
    HOST_A,
    HOST_B,
    NOW_UNIX,
    EnrollmentRefused,
    TwoHostEnrollmentDenialProbe,
)

PINNED_DECISION_A = "33333333-3333-4333-8333-33333333330a"
UNKNOWN_HOST = "host:synthetic-unknown"


def _distinct_probe() -> TwoHostEnrollmentDenialProbe:
    return TwoHostEnrollmentDenialProbe(
        signer_private_a=Ed25519PrivateKey.generate(),
        signer_private_b=Ed25519PrivateKey.generate(),
        issuer_private_a=Ed25519PrivateKey.generate(),
        issuer_private_b=Ed25519PrivateKey.generate(),
    )


class TwoHostEnrollmentDenialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = _distinct_probe()

    def test_per_host_cryptographic_binding_admits_only_matching_host(self) -> None:
        artifacts = self.probe.build_signed_batch(HOST_A)
        admitted = self.probe.admit_synthetic(HOST_A, artifacts)
        self.probe.admitted_no_execution(admitted)
        with self.assertRaises(GateARefused) as wrong_host:
            self.probe.admit_synthetic(HOST_B, artifacts)
        self.assertEqual(wrong_host.exception.reason, "WRONG_HOST")

    def test_hosts_use_independent_signer_and_issuer_keys(self) -> None:
        record_a = self.probe.host_a
        record_b = self.probe.host_b
        self.assertNotEqual(
            record_a.owner_signer_public_key.public_bytes_raw(),
            record_b.owner_signer_public_key.public_bytes_raw(),
        )
        self.assertNotEqual(
            record_a.issuer_public_key.public_bytes_raw(),
            record_b.issuer_public_key.public_bytes_raw(),
        )
        token_a = self.probe.issue_observe_session(HOST_A, 20)
        with self.assertRaises(SessionRefused):
            self.probe.open_session(HOST_B, token_a)

    def test_enrollments_mapping_is_not_writable(self) -> None:
        view = self.probe.enrollments
        tampered = replace(self.probe.host_a, revoked=False, owner_signer_generation=99)
        with self.assertRaises(TypeError):
            view[HOST_A] = tampered  # type: ignore[index]
        self.probe.revoke_enrollment(HOST_A)
        with self.assertRaises(EnrollmentRefused):
            self.probe.build_signed_batch(HOST_A)

    def test_registry_view_cannot_restore_revoked_or_change_generation(self) -> None:
        self.probe.revoke_enrollment(HOST_A)
        view = self.probe.enrollments
        restored = replace(view[HOST_A], revoked=False, owner_signer_generation=99)
        with self.assertRaises(TypeError):
            view[HOST_A] = restored  # type: ignore[index]
        with self.assertRaises(EnrollmentRefused):
            self.probe.build_signed_batch(HOST_A)

    def test_retained_gate_denies_after_revocation(self) -> None:
        gate = self.probe.gate_for(HOST_A)
        artifacts = self.probe.build_signed_batch(HOST_A)
        self.probe.revoke_enrollment(HOST_A)
        from test_canonical_command_batch import COMMAND_ID, PAYLOAD
        from gate_a_admission import ADMISSION_CONTRACT, ADMISSION_MODE

        proposal = {
            "contract": ADMISSION_CONTRACT,
            "execute": False,
            "privilege_mode": ADMISSION_MODE,
            "batch_raw": artifacts.batch_raw,
            "decision_token": artifacts.decision_token,
            "command_id": COMMAND_ID,
            "payload": PAYLOAD,
        }
        with self.assertRaises(EnrollmentRefused) as revoked:
            gate.admit(proposal)
        self.assertEqual(revoked.exception.reason, "ENROLLMENT_REVOKED")

    def test_malformed_host_id_refused_not_type_error(self) -> None:
        for bad in (None, ["host:synthetic-a"], {"host": HOST_A}, 42):
            with self.assertRaises(EnrollmentRefused) as ctx:
                self.probe.require_enrolled_host(bad)
            self.assertEqual(ctx.exception.reason, "ENROLLED_HOST_UNKNOWN")

    def test_unknown_host_refused_before_gate_or_session(self) -> None:
        with self.assertRaises(EnrollmentRefused) as unknown:
            self.probe.build_signed_batch(UNKNOWN_HOST)
        self.assertEqual(unknown.exception.reason, "ENROLLED_HOST_UNKNOWN")
        artifacts = self.probe.build_signed_batch(HOST_A)
        with self.assertRaises(EnrollmentRefused) as admit:
            self.probe.admit_synthetic(UNKNOWN_HOST, artifacts)
        self.assertEqual(admit.exception.reason, "ENROLLED_HOST_UNKNOWN")
        with self.assertRaises(EnrollmentRefused):
            self.probe.issue_observe_session(UNKNOWN_HOST, 10)

    def test_revoked_enrollment_refused_for_batch_and_gate(self) -> None:
        self.probe.revoke_enrollment(HOST_A)
        with self.assertRaises(EnrollmentRefused) as revoked:
            self.probe.build_signed_batch(HOST_A)
        self.assertEqual(revoked.exception.reason, "ENROLLMENT_REVOKED")
        artifacts = self.probe.build_signed_batch(HOST_B)
        self.probe.revoke_enrollment(HOST_B)
        with self.assertRaises(EnrollmentRefused) as gate:
            self.probe.admit_synthetic(HOST_B, artifacts)
        self.assertEqual(gate.exception.reason, "ENROLLMENT_REVOKED")

    def test_signer_generation_mismatch_refused(self) -> None:
        artifacts = self.probe.build_signed_batch(HOST_A)
        with self.assertRaises(EnrollmentRefused) as mismatch:
            self.probe.verify_batch_binding(HOST_A, artifacts, signer_generation=9)
        self.assertEqual(mismatch.exception.reason, "SIGNER_GENERATION_MISMATCH")

    def test_cross_host_session_grant_is_refused(self) -> None:
        token_a = self.probe.issue_observe_session(HOST_A, 30)
        opened = self.probe.open_session(HOST_A, token_a)
        self.assertEqual(opened["host"], HOST_A)
        with self.assertRaises(SessionRefused) as refused:
            self.probe.open_session(HOST_B, token_a)
        self.assertIn(
            refused.exception.reason,
            ("WRONG_HOST", "WRONG_ISSUER_POLICY", "INVALID_GRANT", "INVALID_SIGNATURE"),
        )

    def test_epoch_rotation_rejects_old_and_accepts_new_tokens(self) -> None:
        old_token = self.probe.issue_observe_session(HOST_A, 30)
        self.probe.rotate_epoch(HOST_A, 2)
        with self.assertRaises(SessionRefused) as epoch:
            self.probe.open_session(HOST_A, old_token)
        self.assertEqual(epoch.exception.reason, "REVOKED_EPOCH")
        new_token = self.probe.issue_observe_session(HOST_A, 30)
        opened = self.probe.open_session(HOST_A, new_token)
        self.assertEqual(opened["host"], HOST_A)

    def test_stale_signer_generation_and_epoch_fail_closed(self) -> None:
        artifacts = self.probe.build_signed_batch(HOST_A)
        record = self.probe.host_a
        with self.assertRaises(BatchDecisionRefused) as stale:
            self.probe.verify_batch_binding(HOST_A, artifacts, generation=1)
        self.assertEqual(stale.exception.reason, "STALE_GENERATION")
        with self.assertRaises(BatchDecisionRefused) as bad_signer:
            verify_signed_batch(
                artifacts.decision_token,
                record.owner_signer_public_key,
                artifacts.batch_raw,
                host_id=HOST_A,
                operator="owner-synthetic",
                signer_key_id="signer-key:public-ref-1",
                signer_generation=9,
                generation=3,
                now_unix=NOW_UNIX,
                ledger=SyntheticNonceLedger(),
            )
        self.assertEqual(bad_signer.exception.reason, "WRONG_SIGNER")

    def test_revoked_session_and_ttl_boundary(self) -> None:
        token = self.probe.issue_observe_session(HOST_A, 5)
        opened = self.probe.open_session(HOST_A, token)
        self.probe.revoke_session(HOST_A, opened["session_id"])
        with self.assertRaises(SessionRefused) as revoked:
            self.probe.open_session(HOST_A, token)
        self.assertEqual(revoked.exception.reason, "REVOKED_SESSION")
        artifacts = self.probe.build_signed_batch(HOST_A, nonce=str(uuid.uuid4()))
        with self.assertRaises(BatchDecisionRefused) as expired:
            self.probe.verify_batch_binding(
                HOST_A, artifacts, now_unix=NOW_UNIX + 120,
            )
        self.assertEqual(expired.exception.reason, "BATCH_NOT_BOUND")

    def test_wrong_key_replay_and_split_brain(self) -> None:
        other_signer = Ed25519PrivateKey.generate()
        artifacts = self.probe.build_signed_batch(HOST_A)
        with self.assertRaises(BatchDecisionRefused) as wrong_key:
            verify_signed_batch(
                artifacts.decision_token,
                other_signer.public_key(),
                artifacts.batch_raw,
                host_id=HOST_A,
                operator="owner-synthetic",
                signer_key_id="signer-key:public-ref-1",
                signer_generation=2,
                generation=3,
                now_unix=NOW_UNIX,
                ledger=SyntheticNonceLedger(),
            )
        self.assertEqual(wrong_key.exception.reason, "WRONG_KEY")
        first = self.probe.admit_synthetic(HOST_A, artifacts)
        self.probe.admitted_no_execution(first)
        with self.assertRaises(GateARefused) as replay:
            self.probe.admit_synthetic(HOST_A, artifacts)
        self.assertEqual(replay.exception.reason, "REPLAY")
        split_probe = TwoHostEnrollmentDenialProbe(
            signer_private_a=self.probe._signer_privates[HOST_A],
            signer_private_b=self.probe._signer_privates[HOST_B],
            issuer_private_a=self.probe._issuer_privates[HOST_A],
            issuer_private_b=self.probe._issuer_privates[HOST_B],
        )
        primary = split_probe.build_signed_batch(HOST_A)
        split_probe.admit_synthetic(HOST_A, primary)
        conflicting_raw = batch_fixture._raw(
            batch_fixture._document(
                host_id=HOST_A,
                decision_id=PINNED_DECISION_A,
                session_id="55555555-5555-4555-8555-55555555555a",
                batch_id="66666666-6666-4666-8666-66666666666a",
                intent_text="Conflicting batch under pinned decision_id.",
            )
        )
        conflict_parsed = batch_fixture._parse(conflicting_raw, host_id=HOST_A)
        conflict = split_probe.sign_batch_raw(
            split_probe.require_enrolled_host(HOST_A),
            conflicting_raw,
            conflict_parsed,
            nonce=str(uuid.uuid4()),
        )
        with self.assertRaises(GateARefused) as split:
            split_probe.admit_synthetic(HOST_A, conflict)
        self.assertEqual(split.exception.reason, "SPLIT_BRAIN")


if __name__ == "__main__":
    unittest.main()
