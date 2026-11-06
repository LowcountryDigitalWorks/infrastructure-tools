"""Host-side restart/replay/quarantine tests: NO real privileges or OS commands."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from approval_journal import ApprovalJournal
from host_session_journal import HostSessionJournal, HostJournalError, JournalBoundSyntheticAgent
from owner_decision import SyntheticOwnerDecisionSigner
from session import OwnerPolicy, SessionIssuer, SessionRefused

POLICY = OwnerPolicy("synthetic-host-only", "owner", "host-fixture", "FULL_ADMIN", 60)
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x73]) * 32)
OWNER_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x74]) * 32)


class HostJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-host-session-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.host_path = self.root / "host-sessions.db"
        self.host_journal = HostSessionJournal(self.host_path, initialize=True)
        self.signer = SyntheticOwnerDecisionSigner(OWNER_KEY)
        self.owner_approval_journal = ApprovalJournal(
            self.root / "owner-decisions.db", initialize=True
        )
        self.issuer = SessionIssuer(
            ISSUER_KEY, POLICY, clock=lambda: 1000,
            owner_public_key=OWNER_KEY.public_key(),
            approval_journal=self.owner_approval_journal
        )

    def grant(self):
        decision = self.signer.sign(
            policy=POLICY.policy_id, host=POLICY.host, operator="owner",
            issued=1000, duration=60, max_session_seconds=30
        )
        return self.issuer.issue(
            "owner", POLICY.host, "FULL_ADMIN", 20, owner_decision=decision
        )

    def host(self, journal=None):
        return JournalBoundSyntheticAgent(
            ISSUER_KEY.public_key(), POLICY, POLICY.host,
            clock=lambda: 1000,
            owner_public_key=OWNER_KEY.public_key(),
            host_journal=journal or self.host_journal
        )

    def refused(self, code, action):
        with self.assertRaises(SessionRefused) as caught:
            action()
        self.assertEqual(caught.exception.reason, code)

    def test_synthetic_host_open_and_same_process_idempotent(self):
        token = self.grant()
        host = self.host()
        first = host.open(token, "owner")
        second = host.open(token, "owner")
        self.assertEqual(first, second)
        self.assertEqual(self.host_journal.status()["unverified_count"], 1)
        self.assertEqual(host.execute_canary(token, "owner", str(uuid.uuid4()), "proof")["result"],
                         "PROOF")

    def test_old_signed_grant_cannot_reopen_after_host_restart(self):
        token = self.grant()
        self.host().open(token, "owner")
        fresh_host = self.host(HostSessionJournal(self.host_path))
        self.refused("HOST_SESSION_REPLAY", lambda: fresh_host.open(token, "owner"))

    def test_new_grant_quarantined_while_old_host_session_unverified(self):
        first, second = self.grant(), self.grant()
        self.host().open(first, "owner")
        restarted = self.host(HostSessionJournal(self.host_path))
        self.refused("HOST_QUARANTINED", lambda: restarted.open(second, "owner"))
        self.assertEqual(self.host_journal.status()["state"], "HOST_QUARANTINED")

    def test_revoke_synthetic_session_marks_verified_tombstone_and_allows_next(self):
        token = self.grant()
        host = self.host()
        opened = host.open(token, "owner")
        self.assertEqual(host.revoke(opened["session_id"])["state"], "REVOKED")
        self.assertEqual(self.host_journal.status()["state"], "NO_UNVERIFIED_SESSIONS")
        self.refused("HOST_SESSION_REPLAY", lambda: self.host().open(token, "owner"))
        next_token = self.grant()
        self.assertEqual(self.host().open(next_token, "owner")["state"], "SYNTHETIC_OPEN")

    def test_failed_cleanup_does_not_claim_safe_host(self):
        token = self.grant()
        host = self.host()
        opened = host.open(token, "owner")
        def failure(*args):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        original = self.host_journal.synthetic_revoke_verified
        self.host_journal.synthetic_revoke_verified = failure
        self.addCleanup(lambda: setattr(self.host_journal, "synthetic_revoke_verified", original))
        self.refused("HOST_QUARANTINED", lambda: host.revoke(opened["session_id"]))
        self.assertEqual(self.host_journal.status()["state"], "HOST_QUARANTINED")
        self.refused("HOST_QUARANTINED", lambda: self.host().open(self.grant(), "owner"))

    def test_distinct_hosts_race_only_one_session_is_admitted(self):
        a, b = self.grant(), self.grant()
        barrier = threading.Barrier(2)
        def candidate(token):
            host = self.host(HostSessionJournal(self.host_path))
            barrier.wait(timeout=5)
            try:
                return host.open(token, "owner")["state"]
            except SessionRefused as e:
                return e.reason
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(candidate, (a, b)))
        self.assertEqual(result.count("SYNTHETIC_OPEN"), 1, result)
        self.assertEqual(result.count("HOST_QUARANTINED"), 1, result)

    def test_missing_host_journal_refuses_instead_of_recreating(self):
        self.host_path.unlink()
        with self.assertRaises(HostJournalError):
            HostSessionJournal(self.host_path)
        self.refused("HOST_JOURNAL_UNAVAILABLE", lambda: self.host().open(self.grant(), "owner"))
        self.assertFalse(self.host_path.exists())

    def test_corrupt_host_journal_refuses_instead_of_claiming_clean(self):
        self.host_path.write_bytes(b"invalid database fixture")
        with self.assertRaises(HostJournalError):
            HostSessionJournal(self.host_path)
        self.refused("HOST_JOURNAL_UNAVAILABLE", lambda: self.host().open(self.grant(), "owner"))

    def test_wrong_host_does_not_reserve_token(self):
        token = self.grant()
        bad_host = JournalBoundSyntheticAgent(
            ISSUER_KEY.public_key(), POLICY, "wrong-host",
            host_journal=self.host_journal, owner_public_key=OWNER_KEY.public_key(),
            clock=lambda: 1000
        )
        self.refused("WRONG_HOST", lambda: bad_host.open(token, "owner"))
        self.assertEqual(self.host_journal.status()["unverified_count"], 0)
        self.host().open(token, "owner")

    def test_missing_host_journal_constructor_refuses(self):
        with self.assertRaises(ValueError):
            JournalBoundSyntheticAgent(
                ISSUER_KEY.public_key(), POLICY, POLICY.host,
                host_journal=None, owner_public_key=OWNER_KEY.public_key()
            )

    def test_expired_grant_not_recorded(self):
        token = self.grant()
        expired = self.host(HostSessionJournal(self.host_path))
        expired._clock = lambda: 2000
        self.refused("EXPIRED_OR_NOT_YET_VALID", lambda: expired.open(token, "owner"))
        self.assertEqual(self.host_journal.status()["unverified_count"], 0)

    def test_host_journal_has_no_repair_remote_or_approval_tools(self):
        for command in ("clear", "reset", "issue_grant", "execute_shell",
                        "recover_from_model", "send_message"):
            self.assertFalse(hasattr(self.host_journal, command))


if __name__ == "__main__":
    unittest.main()
