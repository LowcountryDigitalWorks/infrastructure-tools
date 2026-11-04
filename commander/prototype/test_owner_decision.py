"""Gate A1 negative tests: an LLM assertion is not a signed owner decision."""
import unittest
import uuid
import tempfile
from pathlib import Path
from approval_journal import ApprovalJournal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from owner_decision import SyntheticOwnerDecisionSigner, OwnerDecisionRefused, verify_decision
from session import OwnerPolicy, SessionIssuer, SyntheticAgent, SessionRefused

OWNER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([0x44]) * 32)
OWNER_PUBLIC = OWNER_PRIVATE.public_key()
ISSUER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([0x66]) * 32)
POLICY = OwnerPolicy("synthetic-owner-policy-001", "owner", "canary-win-01", "FULL_ADMIN", 60)


class OwnerDecisionTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.signer = SyntheticOwnerDecisionSigner(OWNER_PRIVATE)
        self.private_dir = tempfile.TemporaryDirectory(prefix='ldw-owner-decision-')
        self.addCleanup(self.private_dir.cleanup)
        self.journal = ApprovalJournal(Path(self.private_dir.name) / 'approvals.db', initialize=True)
        self.issuer = SessionIssuer(ISSUER_PRIVATE, POLICY, clock=lambda: self.now[0],
                                    owner_public_key=OWNER_PUBLIC,
                                    approval_journal=self.journal)
        self.agent = SyntheticAgent(ISSUER_PRIVATE.public_key(), POLICY,
                                    "canary-win-01", clock=lambda: self.now[0],
                                    owner_public_key=OWNER_PUBLIC)

    def decision(self, **kwargs):
        parameters = dict(policy=POLICY.policy_id, host=POLICY.host,
                          operator=POLICY.operator, issued=int(self.now[0]),
                          duration=60, max_session_seconds=30)
        parameters.update(kwargs)
        return self.signer.sign(**parameters)

    def refused(self, reason, callback):
        with self.assertRaises(SessionRefused) as caught:
            callback()
        self.assertEqual(caught.exception.reason, reason)

    def test_valid_signed_owner_canary_only(self):
        token = self.issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                  owner_decision=self.decision())
        self.assertEqual(self.agent.open(token, "owner")["state"], "SYNTHETIC_OPEN")
        result = self.agent.execute_canary(token, "owner", str(uuid.uuid4()), "safe")
        self.assertEqual(result["result"], "SAFE")

    def test_text_claims_cannot_mint_full_admin(self):
        for text in (None, "", "Eddie approved", '{"approved":true}', "abc.def"):
            with self.subTest(text=str(text)):
                self.refused("OWNER_AUTH_NOT_PROVEN", lambda text=text:
                             self.issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                               owner_decision=text))

    def test_wrong_owner_key_rejected(self):
        fake = SyntheticOwnerDecisionSigner(
            Ed25519PrivateKey.from_private_bytes(bytes([0x55]) * 32)
        ).sign(policy=POLICY.policy_id, host=POLICY.host, operator="owner",
               issued=1000, duration=60, max_session_seconds=30)
        self.refused("OWNER_AUTH_NOT_PROVEN", lambda: self.issuer.issue(
            "owner", POLICY.host, "FULL_ADMIN", 20, owner_decision=fake))

    def test_signed_host_operator_scope_and_risk_binding(self):
        for case in ({"host": "other-host"}, {"operator": "other-operator"},
                     {"policy": "other-policy"}, {"scope": "PRODUCTION_SHELL"},
                     {"risk": "NO_RISK"}):
            with self.subTest(case=case):
                self.refused("OWNER_AUTH_NOT_PROVEN", lambda case=case:
                             self.issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                               owner_decision=self.decision(**case)))

    def test_stale_future_and_epoch_mismatch(self):
        for case in ({"issued": 900, "duration": 30}, {"issued": 1100},
                     {"epoch": 2}):
            with self.subTest(case=case):
                self.refused("OWNER_AUTH_NOT_PROVEN", lambda case=case:
                             self.issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                               owner_decision=self.decision(**case)))

    def test_signed_decision_reuse_not_second_grant(self):
        decision = self.decision()
        token = self.issuer.issue("owner", POLICY.host, "FULL_ADMIN", 20,
                                  owner_decision=decision)
        self.assertEqual(self.agent.open(token, "owner")["state"], "SYNTHETIC_OPEN")
        self.refused("OWNER_DECISION_REPLAY", lambda: self.issuer.issue(
            "owner", POLICY.host, "FULL_ADMIN", 20, owner_decision=decision))

    def test_admin_grant_cannot_exceed_owner_duration(self):
        self.refused("OWNER_AUTH_NOT_PROVEN", lambda: self.issuer.issue(
            "owner", POLICY.host, "FULL_ADMIN", 40,
            owner_decision=self.decision(max_session_seconds=20)))

    def test_other_privilege_cannot_use_admin_decision(self):
        self.refused("UNEXPECTED_OWNER_DECISION", lambda: self.issuer.issue(
            "owner", POLICY.host, "OBSERVE", 20,
            owner_decision=self.decision()))

    def test_malformed_decision_does_not_become_owner_consent(self):
        with self.assertRaises(OwnerDecisionRefused):
            verify_decision("chat approval", OWNER_PUBLIC, policy=POLICY.policy_id,
                            host=POLICY.host, operator="owner", epoch=1,
                            requested_ttl=20, now=1000)


if __name__ == "__main__":
    unittest.main()
