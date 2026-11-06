"""True fixed OS child cleanup precedes host-journal cleanup. No root or network."""
from pathlib import Path
import tempfile
import unittest

from approval_journal import ApprovalJournal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from host_session_journal import HostSessionJournal, HostJournalError, JournalBoundSyntheticAgent
from owner_decision import SyntheticOwnerDecisionSigner
from process_containment import FixedProcessCanary
from session_process_canary import ProcessBoundSyntheticSession
from session import OwnerPolicy, SessionIssuer, SessionRefused

POLICY = OwnerPolicy("bound-canary-policy", "owner", "bound-test-host", "FULL_ADMIN", 60)
OWNER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x81]) * 32)
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x82]) * 32)


class ProcessBoundSessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ldw-bound-canary-")
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name)
        self.host_journal = HostSessionJournal(home / "host.db", initialize=True)
        self.approval_journal = ApprovalJournal(home / "issuer.db", initialize=True)
        self.issuer = SessionIssuer(
            ISSUER_KEY, POLICY, clock=lambda: 1000,
            owner_public_key=OWNER_KEY.public_key(),
            approval_journal=self.approval_journal
        )
        self.time = [100.]
        self.agent = JournalBoundSyntheticAgent(
            ISSUER_KEY.public_key(), POLICY, POLICY.host,
            host_journal=self.host_journal,
            owner_public_key=OWNER_KEY.public_key(), clock=lambda: 1000
        )
        self.canary = FixedProcessCanary(clock=lambda: self.time[0], duration_seconds=2)
        self.bound = ProcessBoundSyntheticSession(self.agent, self.canary)
        self.addCleanup(self.bound.close)

    def token(self):
        signed = SyntheticOwnerDecisionSigner(OWNER_KEY).sign(
            policy=POLICY.policy_id, host=POLICY.host, operator="owner",
            issued=1000, duration=50, max_session_seconds=30)
        return self.issuer.issue(
            "owner", POLICY.host, "FULL_ADMIN", 20, owner_decision=signed
        )

    def deny(self, reason, action):
        with self.assertRaises(SessionRefused) as caught:
            action()
        self.assertEqual(caught.exception.reason, reason)

    def test_revoke_drain_verified_before_release(self):
        token = self.token()
        self.assertEqual(self.bound.start(token, "owner")["state"], "RUNNING")
        self.assertEqual(self.host_journal.status()["state"], "HOST_QUARANTINED")
        self.assertEqual(self.bound.stop()["state"], "DRAINED_VERIFIED")
        self.assertEqual(self.host_journal.status()["state"], "NO_UNVERIFIED_SESSIONS")
        self.assertEqual(self.canary.status()["state"], "DRAINED_VERIFIED")
        self.deny("SESSION_NOT_ADMISSIBLE", lambda: self.bound.start(token, "owner"))

    def test_unverifiable_cleanup_keeps_host_quarantined(self):
        self.bound.start(self.token(), "owner")
        self.deny("HOST_QUARANTINED",
                  lambda: self.bound.stop(simulate_unverifiable=True))
        self.assertEqual(self.host_journal.status()["state"], "HOST_QUARANTINED")
        self.assertEqual(self.bound.status()["state"], "HOST_QUARANTINED")
        self.deny("SESSION_NOT_ADMISSIBLE", lambda: self.bound.start(self.token(), "owner"))

    def test_expiry_drains_process_then_marks_verified(self):
        self.bound.start(self.token(), "owner")
        self.time[0] += 3
        self.assertEqual(self.bound.refresh()["state"], "DRAINED_VERIFIED")
        self.assertEqual(self.host_journal.status()["unverified_count"], 0)

    def test_unauthenticated_request_never_spawns_child(self):
        self.deny("INVALID_GRANT", lambda: self.bound.start("fake approval", "owner"))
        self.assertEqual(self.canary.status()["state"], "NEW")
        self.assertEqual(self.host_journal.status()["unverified_count"], 0)

    def test_host_journal_failure_cannot_claim_success(self):
        self.bound.start(self.token(), "owner")
        self.host_journal.synthetic_revoke_verified = lambda *a: (
            _ for _ in ()).throw(HostJournalError("HOST_JOURNAL_UNAVAILABLE"))
        self.deny("HOST_QUARANTINED", lambda: self.bound.stop())
        self.assertEqual(self.canary.status()["state"], "DRAINED_VERIFIED")
        self.assertEqual(self.host_journal.status()["state"], "HOST_QUARANTINED")
        self.assertEqual(self.bound.status()["state"], "HOST_QUARANTINED")


if __name__ == "__main__":
    unittest.main()
