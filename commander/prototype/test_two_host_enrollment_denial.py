"""Deterministic two-host enrollment / revocation denial matrix (#209)."""
from __future__ import annotations

import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gate_a_admission import GateARefused
from session import SessionRefused
from signed_batch_binding import BatchDecisionRefused, SyntheticNonceLedger, verify_signed_batch
import test_canonical_command_batch as batch_fixture
from two_host_enrollment_denial import (
    HOST_A,
    HOST_B,
    NOW_UNIX,
    TwoHostEnrollmentDenialProbe,
)

PINNED_DECISION_A = "33333333-3333-4333-8333-33333333330a"


class TwoHostEnrollmentDenialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.probe = TwoHostEnrollmentDenialProbe(
            signer_private=Ed25519PrivateKey.generate(),
            issuer_private=Ed25519PrivateKey.generate(),
        )

    def test_per_host_cryptographic_binding_admits_only_matching_host(self) -> None:
        artifacts = self.probe.build_signed_batch(HOST_A)
        admitted = self.probe.admit_synthetic(HOST_A, artifacts)
        self.probe.admitted_no_execution(admitted)
        with self.assertRaises(GateARefused) as wrong_host:
            self.probe.admit_synthetic(HOST_B, artifacts)
        self.assertEqual(wrong_host.exception.reason, "WRONG_HOST")

    def test_cross_host_session_grant_is_refused(self) -> None:
        token_a = self.probe.issue_observe_session(HOST_A, 30)
        opened = self.probe.open_session(HOST_A, token_a)
        self.assertEqual(opened["host"], HOST_A)
        with self.assertRaises(SessionRefused) as refused:
            self.probe.open_session(HOST_B, token_a)
        self.assertIn(
            refused.exception.reason,
            ("WRONG_HOST", "WRONG_ISSUER_POLICY"),
        )

    def test_stale_signer_generation_and_epoch_fail_closed(self) -> None:
        artifacts = self.probe.build_signed_batch(HOST_A)
        with self.assertRaises(BatchDecisionRefused) as stale:
            self.probe.verify_batch_binding(HOST_A, artifacts, generation=1)
        self.assertEqual(stale.exception.reason, "STALE_GENERATION")
        with self.assertRaises(BatchDecisionRefused) as bad_signer:
            self.probe.verify_batch_binding(HOST_A, artifacts, signer_generation=9)
        self.assertEqual(bad_signer.exception.reason, "WRONG_SIGNER")
        token = self.probe.issue_observe_session(HOST_A, 20)
        self.probe.rotate_epoch(HOST_A, 2)
        with self.assertRaises(SessionRefused) as epoch:
            self.probe.open_session(HOST_A, token)
        self.assertEqual(epoch.exception.reason, "REVOKED_EPOCH")

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
            signer_private=self.probe._signer_private,
            issuer_private=self.probe._issuer_private,
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
            HOST_A, conflicting_raw, conflict_parsed, nonce=str(uuid.uuid4()),
        )
        with self.assertRaises(GateARefused) as split:
            split_probe.admit_synthetic(HOST_A, conflict)
        self.assertEqual(split.exception.reason, "SPLIT_BRAIN")


if __name__ == "__main__":
    unittest.main()
