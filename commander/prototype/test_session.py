import unittest
import uuid
import json
import base64

from session import OwnerPolicy, SessionIssuer, SyntheticAgent, SessionRefused, MAX_COMMANDS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TEST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key()
POLICY = OwnerPolicy(
    policy_id="synthetic-owner-policy-001", operator="owner", host="canary-win-01",
    max_privilege="FULL_ADMIN", max_ttl_seconds=60
)


def new_id():
    return str(uuid.uuid4())


class SyntheticSessionTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.issuer = SessionIssuer(TEST_PRIVATE_KEY, POLICY, clock=lambda: self.now[0])
        self.agent = SyntheticAgent(TEST_PUBLIC_KEY, POLICY, "canary-win-01", clock=lambda: self.now[0])
        self.token = self.issuer.issue("owner", "canary-win-01", "FULL_ADMIN", 20)

    def assert_refused(self, reason, thunk):
        with self.assertRaises(SessionRefused) as result:
            thunk()
        self.assertEqual(result.exception.reason, reason)

    def test_opens_valid_full_admin_scope_as_synthetic_only(self):
        r = self.agent.open(self.token, "owner")
        self.assertEqual((r["state"], r["host"]), ("SYNTHETIC_OPEN", "canary-win-01"))

    def test_canary_command_not_shell_execution(self):
        self.agent.open(self.token, "owner")
        r = self.agent.execute_canary(self.token, "owner", new_id(), "harmless proof")
        self.assertEqual((r["state"], r["result"]), ("SYNTHETIC_CANARY_PASS", "HARMLESS PROOF"))
        self.assertNotIn("stdout", r)
        self.assertNotIn("admin", r)

    def test_duplicate_same_command_only_one_execution(self):
        self.agent.open(self.token, "owner")
        cid = new_id()
        self.assertFalse(self.agent.execute_canary(self.token, "owner", cid, "first")["duplicate"])
        self.assertTrue(self.agent.execute_canary(self.token, "owner", cid, "first")["duplicate"])
        self.assert_refused("COMMAND_ID_CONFLICT", lambda: self.agent.execute_canary(
            self.token, "owner", cid, "changed"
        ))

    def test_command_budget_and_session_busy(self):
        self.agent.open(self.token, "owner")
        for _ in range(MAX_COMMANDS):
            self.agent.execute_canary(self.token, "owner", new_id(), "hello")
        self.assert_refused("COMMAND_BUDGET_EXHAUSTED", lambda: self.agent.execute_canary(
            self.token, "owner", new_id(), "one-more"
        ))
        second = self.issuer.issue("owner", "canary-win-01", "FULL_ADMIN", 20)
        self.assert_refused("HOST_BUSY", lambda: self.agent.open(second, "owner"))

    def test_operator_and_target_fail_closed(self):
        self.assert_refused("WRONG_OPERATOR", lambda: self.agent.open(self.token, "ir02"))
        self.assert_refused("POLICY_REFUSED", lambda: self.issuer.issue(
            "ir02", "canary-win-01", "FULL_ADMIN", 5
        ))
        self.assert_refused("POLICY_REFUSED", lambda: self.issuer.issue(
            "owner", "unregistered-linux", "FULL_ADMIN", 5
        ))

    def test_host_bound_not_reusable_on_other_host(self):
        other = SyntheticAgent(TEST_PUBLIC_KEY, POLICY, "other-host", clock=lambda: self.now[0])
        self.assert_refused("WRONG_HOST", lambda: other.open(self.token, "owner"))

    def test_tampered_token_refused(self):
        p, sig = self.token.split(".")
        first = "A" if sig[0] != "A" else "B"
        tampered = p + "." + first + sig[1:]
        self.assert_refused("INVALID_SIGNATURE", lambda: self.agent.open(tampered, "owner"))

    def test_expired_grant_cannot_open_or_execute(self):
        self.agent.open(self.token, "owner")
        self.now[0] += 21
        self.assert_refused("EXPIRED_OR_NOT_YET_VALID", lambda: self.agent.open(self.token, "owner"))
        self.assert_refused("EXPIRED_OR_NOT_YET_VALID", lambda: self.agent.execute_canary(
            self.token, "owner", new_id(), "stale"
        ))

    def test_future_grant_rejected(self):
        future_issuer = SessionIssuer(TEST_PRIVATE_KEY, POLICY, clock=lambda: 1500)
        future = future_issuer.issue("owner", "canary-win-01", "OBSERVE", 10)
        self.assert_refused("EXPIRED_OR_NOT_YET_VALID", lambda: self.agent.open(future, "owner"))

    def test_revoked_session_does_not_reopen(self):
        session = self.agent.open(self.token, "owner")["session_id"]
        self.agent.revoke(session)
        self.assert_refused("REVOKED_SESSION", lambda: self.agent.open(self.token, "owner"))
        self.assert_refused("REVOKED_SESSION", lambda: self.agent.execute_canary(
            self.token, "owner", new_id(), "not allowed"
        ))

    def test_epoch_rotation_refuses_old_grant(self):
        self.agent.open(self.token, "owner")
        self.agent.set_epoch(2)
        self.assert_refused("REVOKED_EPOCH", lambda: self.agent.open(self.token, "owner"))

    def test_public_key_agent_cannot_mint_a_forged_grant(self):
        self.assertFalse(hasattr(self.agent, "_private_key"))
        self.assertFalse(hasattr(self.agent, "_secret"))
        attacker_key = Ed25519PrivateKey.from_private_bytes(b"\\x22" * 32)
        forged_issuer = SessionIssuer(attacker_key, POLICY, clock=lambda: self.now[0])
        forged = forged_issuer.issue("owner", "canary-win-01", "FULL_ADMIN", 20)
        self.assert_refused("INVALID_SIGNATURE", lambda: self.agent.open(forged, "owner"))

    def test_no_overlong_grant_issued(self):
        self.assert_refused("POLICY_REFUSED", lambda: self.issuer.issue(
            "owner", "canary-win-01", "FULL_ADMIN", 120
        ))
        self.assert_refused("POLICY_REFUSED", lambda: self.issuer.issue(
            "owner", "canary-win-01", "FULL_ADMIN", 0
        ))

    def test_privilege_max_protects_owner_policy(self):
        limited = OwnerPolicy("observe-only", "owner", "canary-win-01", "OBSERVE", 30)
        issuer = SessionIssuer(TEST_PRIVATE_KEY, limited, clock=lambda: self.now[0])
        self.assert_refused("POLICY_REFUSED", lambda: issuer.issue(
            "owner", "canary-win-01", "FULL_ADMIN", 20
        ))

    def test_open_requires_signature_and_matching_policy(self):
        other = OwnerPolicy("other-policy", "owner", "canary-win-01", "FULL_ADMIN", 60)
        host = SyntheticAgent(TEST_PUBLIC_KEY, other, "canary-win-01", clock=lambda: self.now[0])
        self.assert_refused("WRONG_ISSUER_POLICY", lambda: host.open(self.token, "owner"))

    def test_unsupported_operation_not_exposed(self):
        self.agent.open(self.token, "owner")
        self.assertFalse(hasattr(self.agent, "run_command"))
        self.assertFalse(hasattr(self.agent, "execute_shell"))
        self.assertFalse(hasattr(self.agent, "file_write"))


if __name__ == "__main__":
    unittest.main()
