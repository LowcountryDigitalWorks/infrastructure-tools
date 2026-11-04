"""End-to-end local-user filesystem/process canaries, no remote or elevated access."""
import tempfile
from pathlib import Path
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from local_user_mode import LocalUserModeProbe
from session import OwnerPolicy, SessionIssuer, SessionRefused

PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x33]) * 32)
PUBLIC_KEY = PRIVATE_KEY.public_key()
POLICY = OwnerPolicy("disposable-local-probe", "owner", "synthetic-win-01",
                     "MAINTAIN", 60)


def cid():
    return str(uuid.uuid4())


class LocalUserModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-commander-canary-")
        self.addCleanup(self.temp.cleanup)
        self.now = [1000.0]
        self.issuer = SessionIssuer(PRIVATE_KEY, POLICY, clock=lambda: self.now[0])
        self.agent = LocalUserModeProbe(
            PUBLIC_KEY, POLICY, "synthetic-win-01", Path(self.temp.name),
            clock=lambda: self.now[0],
        )
        self.grant = self.issuer.issue("owner", "synthetic-win-01", "MAINTAIN", 20)
        self.session = self.agent.open(self.grant, "owner")

    def denied(self, reason, thunk):
        with self.assertRaises(SessionRefused) as e:
            thunk()
        self.assertEqual(e.exception.reason, reason)

    def action(self, op, *, command_id=None, name=None, value=None):
        return self.agent.execute(self.grant, "owner", command_id or cid(), op,
                                  name=name, value=value)

    def test_actual_temporary_file_create_read_and_child_process(self):
        created = self.action("file_create", name="fixture.txt", value="synthetic value")
        self.assertEqual(created["state"], "LOCAL_USER_MODE_PROOF")
        self.assertEqual((Path(self.temp.name) / "fixture.txt").read_text(), "synthetic value")
        read = self.action("file_read", name="fixture.txt")
        self.assertEqual(read["result"]["text"], "synthetic value")
        self.assertEqual(read["result"]["sha256"], created["result"]["sha256"])
        child = self.action("fixed_process")
        self.assertEqual(child["result"], {
            "exit_code": 0, "output": "LDW_LOCAL_PROCESS_PROOF"
        })
        self.denied("COMMAND_BUDGET_EXHAUSTED", lambda: self.action("fixed_process"))

    def test_duplicate_write_has_no_second_file_open(self):
        request = cid()
        self.assertFalse(self.action(
            "file_create", command_id=request, name="copy.txt", value="once")["duplicate"])
        self.assertTrue(self.action(
            "file_create", command_id=request, name="copy.txt", value="once")["duplicate"])
        self.denied("COMMAND_ID_CONFLICT", lambda: self.action(
            "file_create", command_id=request, name="copy.txt", value="changed"))
        self.assertEqual((Path(self.temp.name) / "copy.txt").read_text(), "once")

    def test_reused_filename_is_not_overwritten(self):
        self.action("file_create", name="existing.txt", value="first")
        self.denied("FIXTURE_FILE_EXISTS", lambda: self.action(
            "file_create", name="existing.txt", value="second"))
        self.assertEqual((Path(self.temp.name) / "existing.txt").read_text(), "first")

    def test_rejects_path_traversal_and_missing_file(self):
        for name in ("../secret.txt", "C:\\Windows\\secret.txt", "/etc/passwd",
                     "nested/path.txt", "not-text.exe"):
            self.denied("INVALID_FIXTURE_FILE", lambda name=name:
                        self.action("file_create", name=name, value="x"))
        self.denied("FIXTURE_FILE_MISSING", lambda: self.action(
            "file_read", name="missing.txt"))

    def test_rejects_symlinks_without_touching_target(self):
        external = Path(self.temp.name).parent / ("ldw-external-" + cid() + ".txt")
        external.write_text("outside")
        self.addCleanup(lambda: external.unlink(missing_ok=True))
        link = Path(self.temp.name) / "symlink.txt"
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not available")
        self.denied("SYMLINK_REFUSED", lambda: self.action(
            "file_create", name="symlink.txt", value="blocked"))
        self.assertEqual(external.read_text(), "outside")

    def test_invalid_content_and_process_args_fail_closed(self):
        self.denied("INVALID_FIXTURE_VALUE", lambda: self.action(
            "file_create", name="too-large.txt", value="x" * 1025))
        self.denied("INVALID_PROBE_ARGUMENTS", lambda: self.action(
            "fixed_process", name="any.txt"))
        self.denied("INVALID_PROBE_ARGUMENTS", lambda: self.action(
            "file_read", name="any.txt", value="injected"))
        self.denied("UNSUPPORTED_PROBE_OPERATION", lambda: self.action("shell"))
        self.assertFalse(hasattr(self.agent, "execute_arbitrary"))

    def test_tamper_wrong_actor_and_wrong_host_refused(self):
        self.denied("WRONG_OPERATOR", lambda: self.agent.execute(
            self.grant, "ir02", cid(), "fixed_process"))
        other = LocalUserModeProbe(
            PUBLIC_KEY, POLICY, "other-host", Path(self.temp.name),
            clock=lambda: self.now[0])
        self.denied("WRONG_HOST", lambda: other.open(self.grant, "owner"))
        p, sig = self.grant.split(".")
        fake = p + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
        self.denied("INVALID_SIGNATURE", lambda: self.agent.execute(
            fake, "owner", cid(), "fixed_process"))

    def test_revoked_or_expired_session_cannot_touch_files(self):
        self.agent.revoke(self.session["session_id"])
        self.denied("REVOKED_SESSION", lambda: self.action(
            "file_create", name="revoke.txt", value="blocked"))
        self.assertFalse((Path(self.temp.name) / "revoke.txt").exists())

    def test_expired_session_without_revoke_fails_closed(self):
        self.now[0] += 21
        self.denied("EXPIRED_OR_NOT_YET_VALID", lambda: self.action(
            "file_create", name="expired.txt", value="blocked"))
        self.assertFalse((Path(self.temp.name) / "expired.txt").exists())

    def test_root_must_be_existing_real_directory(self):
        with self.assertRaises(ValueError):
            LocalUserModeProbe(PUBLIC_KEY, POLICY, "synthetic-win-01",
                               Path(self.temp.name) / "absent")


if __name__ == "__main__":
    unittest.main()
