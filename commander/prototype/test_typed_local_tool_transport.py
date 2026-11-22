"""Typed loopback tool transport: happy path + adversarial negatives (#209)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_session_journal import HostSessionJournal
from local_tool_loopback_harness import LocalToolLoopbackHarness, run_typed_local_canary
from model_output_boundary import BLOCKED_STATUS
from model_tool_transport_proof import model_typed_tool_call, model_tool_result
from session import OwnerPolicy, SessionIssuer, SessionRefused
from typed_local_tool_transport import (
    TypedLocalToolDispatcher,
    TrustedTransportBinding,
    sanitize_tool_payload,
    TypedLocalToolRefused,
)

PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes([0x44]) * 32)
PUBLIC = PRIVATE.public_key()
POLICY = OwnerPolicy("typed-transport-test", "trusted-operator", "synthetic-ldw01", "MAINTAIN", 60)


def cid() -> str:
    return str(uuid.uuid4())


class TypedLocalToolTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-typed-transport-")
        self.addCleanup(self.temp.cleanup)
        self.now = [2_000.0]
        self.harness = LocalToolLoopbackHarness(
            PRIVATE, POLICY, Path(self.temp.name), clock=lambda: self.now[0],
        )
        self.harness.issue_grant(25)

    def test_happy_path_real_fixture_and_fixed_process(self):
        proof = run_typed_local_canary(PRIVATE)
        self.assertEqual(proof["state"], "TYPED_LOCAL_TRANSPORT_PROOF_COMPLETE")
        self.assertEqual(proof["file_integrity"], "PASS")
        self.assertEqual(proof["child_process"], "PASS")

    def test_loopback_chain_matches_local_canary_semantics(self):
        opened = self.harness.invoke("session_open", {})
        self.assertEqual(opened["state"], "SESSION_OPEN")
        hosts = self.harness.invoke("hosts_list", {})
        self.assertEqual(hosts["hosts"], ["synthetic-ldw01"])
        write = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "proof.txt", "value": "LDW",
        })
        read = self.harness.invoke("fs_read", {"command_id": cid(), "name": "proof.txt"})
        self.assertEqual(write["result"]["sha256"], read["result"]["sha256"])
        proc = self.harness.invoke("run_fixed_canary", {"command_id": cid()})
        self.assertEqual(proc["result"]["exit_code"], 0)
        preview = self.harness.invoke("process_read", {})
        self.assertEqual(preview["process"]["output"], "LDW_LOCAL_PROCESS_PROOF")
        closed = self.harness.invoke("session_close", {})
        self.assertEqual(closed["state"], "REVOKED")

    def test_model_typed_tool_call_stays_blocked(self):
        blocked = model_typed_tool_call("session_open", {"operator": "attacker"})
        self.assertEqual(blocked, {"status": BLOCKED_STATUS})
        self.assertEqual(model_tool_result({"tool": "fs_write", "path": "/etc/passwd"}),
                         {"status": BLOCKED_STATUS})

    # --- adversarial negatives (>=12) ---

    def test_neg_identity_operator_injection_in_arguments(self):
        out = self.harness.invoke("session_open", {"operator": "attacker"})
        self.assertEqual(out, {"state": "TOOL_REFUSED", "reason": "IDENTITY_INJECTION_REFUSED"})

    def test_neg_identity_host_injection_in_arguments(self):
        out = self.harness.invoke("hosts_list", {"host": "evil-host"})
        self.assertEqual(out["reason"], "IDENTITY_INJECTION_REFUSED")

    def test_neg_grant_injection_in_tool_arguments(self):
        out = self.harness.invoke("fs_write", {
            "grant": "forged", "command_id": cid(), "name": "x.txt", "value": "a",
        })
        self.assertEqual(out["reason"], "IDENTITY_INJECTION_REFUSED")

    def test_neg_unknown_tool_name(self):
        out = self.harness.invoke("shell_exec", {"command": "id"})
        self.assertEqual(out["reason"], "UNKNOWN_TOOL")

    def test_neg_fake_admin_tool_name(self):
        out = self.harness.invoke("FULL_ADMIN", {})
        self.assertEqual(out["reason"], "UNKNOWN_TOOL")

    def test_neg_malformed_non_dict_arguments(self):
        dispatcher = TypedLocalToolDispatcher(
            self.harness._probe,
            TrustedTransportBinding(POLICY.policy_id, POLICY.operator, POLICY.host),
            active_grant=self.harness._issued_grant,
        )
        with self.assertRaises(TypedLocalToolRefused) as err:
            dispatcher.dispatch("hosts_list", "not-a-dict")  # type: ignore[arg-type]
        self.assertEqual(err.exception.reason, "MALFORMED_ARGUMENTS")

    def test_neg_wrong_operator_on_probe_execute(self):
        self.harness.invoke("session_open", {})
        with self.assertRaises(SessionRefused) as err:
            self.harness._probe.execute(
                self.harness._issued_grant, "wrong-operator", cid(),
                "file_create", name="bad.txt", value="x",
            )
        self.assertEqual(err.exception.reason, "WRONG_OPERATOR")

    def test_neg_wrong_host_grant(self):
        other_policy = OwnerPolicy(POLICY.policy_id, POLICY.operator, "other-host", "MAINTAIN", 60)
        issuer = SessionIssuer(PRIVATE, other_policy, clock=lambda: self.now[0])
        bad = issuer.issue(POLICY.operator, "other-host", "MAINTAIN", 10)
        dispatcher = TypedLocalToolDispatcher(
            self.harness._probe,
            TrustedTransportBinding(POLICY.policy_id, POLICY.operator, POLICY.host),
            active_grant=bad,
        )
        with self.assertRaises(SessionRefused) as err:
            dispatcher.dispatch("session_open", {})
        self.assertIn(err.exception.reason, ("WRONG_HOST", "WRONG_ISSUER_POLICY"))

    def test_neg_expired_grant_replay(self):
        self.harness.invoke("session_open", {})
        self.now[0] = 2_100.0
        out = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "late.txt", "value": "x",
        })
        self.assertEqual(out["state"], "TOOL_REFUSED")

    def test_neg_revoked_session_denied(self):
        opened = self.harness.invoke("session_open", {})
        sid = opened["session_id"]
        self.harness.invoke("session_close", {"session_id": sid})
        out = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "after.txt", "value": "x",
        })
        self.assertEqual(out["state"], "TOOL_REFUSED")

    def test_neg_command_id_conflict(self):
        self.harness.invoke("session_open", {})
        request = cid()
        self.harness.invoke("fs_write", {
            "command_id": request, "name": "once.txt", "value": "a",
        })
        out = self.harness.invoke("fs_write", {
            "command_id": request, "name": "once.txt", "value": "b",
        })
        self.assertEqual(out["state"], "TOOL_REFUSED")

    def test_neg_path_traversal_filename(self):
        self.harness.invoke("session_open", {})
        out = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "../escape.txt", "value": "x",
        })
        self.assertEqual(out["state"], "TOOL_REFUSED")
        self.assertIn(out["reason"], ("INVALID_FIXTURE_FILE", "MALFORMED_ARGUMENTS"))

    def test_neg_symlink_fixture_escape(self):
        self.harness.invoke("session_open", {})
        target = Path(self.temp.name) / "link.txt"
        try:
            outside = Path(self.temp.name).parent / "outside-target.txt"
            outside.write_text("outside", encoding="utf-8")
            target.symlink_to(outside)
        except OSError:
            self.skipTest("symlink creation unavailable on host")
        out = self.harness.invoke("fs_read", {
            "command_id": cid(), "name": "link.txt",
        })
        self.assertEqual(out["state"], "TOOL_REFUSED")
        self.assertEqual(out["reason"], "SYMLINK_REFUSED")

    def test_neg_output_oversize_payload(self):
        huge = {"k": "x" * 5000}
        with self.assertRaises(TypedLocalToolRefused) as err:
            sanitize_tool_payload(huge)
        self.assertEqual(err.exception.reason, "OUTPUT_OVERSIZE")

    def test_neg_offline_transport_denial(self):
        self.harness.set_offline(True)
        self.assertEqual(self.harness.invoke("hosts_list", {}),
                         {"state": "TRANSPORT_OFFLINE", "status": "DENIED"})

    def test_neg_stale_host_journal_blocks_second_open(self):
        journal_ctx = tempfile.TemporaryDirectory(prefix="ldw-journal-")
        self.addCleanup(journal_ctx.cleanup)
        journal_path = Path(journal_ctx.name) / "journal.db"
        harness = LocalToolLoopbackHarness(
            PRIVATE, POLICY, Path(self.temp.name),
            clock=lambda: self.now[0], use_host_journal=True, journal_path=journal_path,
        )
        harness.issue_grant(20)
        first = harness.invoke("session_open", {})
        self.assertEqual(first["state"], "SESSION_OPEN")
        harness.issue_grant(20)
        second = harness.invoke("session_open", {})
        self.assertEqual(second["state"], "TOOL_REFUSED")
        self.assertIn(second["reason"], ("HOST_QUARANTINED", "HOST_SESSION_REPLAY", "HOST_BUSY"))

    def test_neg_process_read_before_run(self):
        self.harness.invoke("session_open", {})
        out = self.harness.invoke("process_read", {})
        self.assertEqual(out["reason"], "PROCESS_NOT_RUN")

    def test_neg_process_read_denied_after_grant_ttl_and_repeat(self):
        self.harness.invoke("session_open", {})
        self.harness.invoke("run_fixed_canary", {"command_id": cid()})
        preview_live = self.harness.invoke("process_read", {})
        self.assertEqual(preview_live["state"], "PROCESS_READ")
        self.now[0] = 2_040.0
        denied = self.harness.invoke("process_read", {})
        self.assertEqual(denied, {"state": "TOOL_REFUSED", "reason": "EXPIRED_OR_NOT_YET_VALID"})
        denied_again = self.harness.invoke("process_read", {})
        self.assertEqual(denied_again["reason"], "EXPIRED_OR_NOT_YET_VALID")

    def test_neg_session_close_foreign_session_id_leaves_bound_session(self):
        opened = self.harness.invoke("session_open", {})
        sid = opened["session_id"]
        foreign = str(uuid.uuid4())
        self.assertNotEqual(foreign, sid)
        blocked = self.harness.invoke("session_close", {"session_id": foreign})
        self.assertEqual(blocked, {"state": "TOOL_REFUSED", "reason": "SESSION_ID_MISMATCH"})
        still_open = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "open.txt", "value": "still",
        })
        self.assertEqual(still_open["state"], "LOCAL_USER_MODE_PROOF")
        closed = self.harness.invoke("session_close", {})
        self.assertEqual(closed["state"], "REVOKED")

    def test_neg_unknown_argument_field_on_fs_write(self):
        self.harness.invoke("session_open", {})
        out = self.harness.invoke("fs_write", {
            "command_id": cid(), "name": "extra.txt", "value": "x", "safe": True,
        })
        self.assertEqual(out, {"state": "TOOL_REFUSED", "reason": "UNKNOWN_ARGUMENT_FIELD"})

    def test_pos_session_close_without_session_id_uses_bound_session(self):
        opened = self.harness.invoke("session_open", {})
        self.harness.invoke("run_fixed_canary", {"command_id": cid()})
        closed = self.harness.invoke("session_close", {})
        self.assertEqual(closed["state"], "REVOKED")
        self.assertEqual(closed["session_id"], opened["session_id"])


if __name__ == "__main__":
    unittest.main()
