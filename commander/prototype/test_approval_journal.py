"""Cross-thread, cross-issuer and restart tests for SYNTHETIC approval ledger.

All state is in an automatically removed owner-private test directory.
No actual host service, elevation, network, or human authentication.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from approval_journal import ApprovalJournal, ApprovalJournalError
from owner_decision import SyntheticOwnerDecisionSigner
from session import OwnerPolicy, SessionIssuer, SessionRefused

POLICY = OwnerPolicy("synthetic-policy", "owner", "canary-linux", "FULL_ADMIN", 60)
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x34]) * 32)
OWNER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x56]) * 32)


class ApprovalJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-approval-journal-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "decisions.db"
        self.journal = ApprovalJournal(self.path, initialize=True)
        self.signer = SyntheticOwnerDecisionSigner(OWNER_KEY)

    def issuer(self, journal=None):
        return SessionIssuer(
            ISSUER_KEY, POLICY, clock=lambda: 1000,
            owner_public_key=OWNER_KEY.public_key(),
            approval_journal=self.journal if journal is None else journal,
        )

    def decision(self):
        return self.signer.sign(
            policy=POLICY.policy_id, host=POLICY.host, operator=POLICY.operator,
            issued=1000, duration=60, max_session_seconds=30
        )

    def test_same_decision_rejected_after_issuer_restarts(self):
        approval = self.decision()
        first = self.issuer().issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                     owner_decision=approval)
        self.assertTrue(first)
        reopened = ApprovalJournal(self.path, initialize=False)
        successor = self.issuer(reopened)
        with self.assertRaises(SessionRefused) as failure:
            successor.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                            owner_decision=approval)
        self.assertEqual(failure.exception.reason, "OWNER_DECISION_REPLAY")

    def test_concurrent_issuers_one_grant_only(self):
        decision = self.decision()
        barrier = threading.Barrier(8)

        def attempt(_):
            issuer = self.issuer(ApprovalJournal(self.path))
            barrier.wait(timeout=5)
            try:
                return issuer.issue(
                    "owner", POLICY.host, "FULL_ADMIN", 20,
                    owner_decision=decision
                ), None
            except SessionRefused as error:
                return None, error.reason

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        grants = [token for token, _ in outcomes if token]
        refusals = [reason for _, reason in outcomes if reason]
        self.assertEqual(len(grants), 1, outcomes)
        self.assertEqual(refusals, ["OWNER_DECISION_REPLAY"] * 7)

    def test_same_issuer_concurrent_calls_only_one_grant(self):
        decision = self.decision()
        issuer = self.issuer()
        def attempt(_):
            try:
                return issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                    owner_decision=decision), None
            except SessionRefused as error:
                return None, error.reason
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(bool(token) for token, _ in outcomes), 1)
        self.assertEqual(sum(reason == "OWNER_DECISION_REPLAY"
                             for _, reason in outcomes), 7)

    def test_missing_journal_refuses_full_admin(self):
        approval = self.decision()
        issuer = SessionIssuer(ISSUER_KEY, POLICY, clock=lambda: 1000,
                               owner_public_key=OWNER_KEY.public_key())
        with self.assertRaises(SessionRefused) as failure:
            issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                         owner_decision=approval)
        self.assertEqual(failure.exception.reason, "APPROVAL_JOURNAL_UNAVAILABLE")

    def test_deleted_journal_fails_closed_and_never_recreates(self):
        approval = self.decision()
        issuer = self.issuer()
        self.path.unlink()
        with self.assertRaises(SessionRefused) as failure:
            issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                         owner_decision=approval)
        self.assertEqual(failure.exception.reason, "APPROVAL_JOURNAL_UNAVAILABLE")
        self.assertFalse(self.path.exists())
        with self.assertRaises(ApprovalJournalError):
            ApprovalJournal(self.path, initialize=False)

    def test_corrupt_journal_refuses_without_returning_token(self):
        self.path.write_bytes(b"not a sqlite database, no authority")
        with self.assertRaises(ApprovalJournalError):
            ApprovalJournal(self.path)
        with self.assertRaises(SessionRefused) as failure:
            self.issuer().issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                owner_decision=self.decision())
        self.assertEqual(failure.exception.reason, "APPROVAL_JOURNAL_UNAVAILABLE")

    def test_refuse_to_reinitialize_existing_authority_state(self):
        with self.assertRaises(ApprovalJournalError):
            ApprovalJournal(self.path, initialize=True)

    @unittest.skipUnless(os.name == "posix", "POSIX owner-private directory proof")
    def test_group_world_writable_directory_refused(self):
        outside = Path(self.temp.name) / "shared"
        outside.mkdir(mode=0o777)
        outside.chmod(0o777)
        with self.assertRaises(ApprovalJournalError):
            ApprovalJournal(outside / "state.db", initialize=True)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions proof")
    def test_world_readable_state_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ApprovalJournalError):
            ApprovalJournal(self.path, initialize=False)

    def test_no_network_or_shell_apis(self):
        self.assertFalse(hasattr(self.journal, "run_command"))
        self.assertFalse(hasattr(self.journal, "send_message"))
        self.assertFalse(hasattr(self.journal, "issue_grant"))


if __name__ == "__main__":
    unittest.main()
