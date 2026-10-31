#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("MODULE_LOAD_FAILED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pub = load("dragonfly_canary_publication", ROOT / "tools/dragonfly_canary_publication.py")
inst = load("dragonfly_canary_redrix_install", ROOT / "tools/dragonfly_canary_redrix_install.py")


class RedrixInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.uid = os.getuid()
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700)
        self.authorized = ssh / "authorized_keys"
        self.key_data = "AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey"
        self.key_sha256 = hashlib.sha256(
            f"ssh-ed25519 {self.key_data}".encode("ascii")
        ).hexdigest()
        self.line = (
            f'restrict,command="{inst.FORCED_COMMAND}" '
            f"ssh-ed25519 {self.key_data} material\n"
        )
        self.authorized.write_text(self.line, encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        self.package_dir = self.root / "package"
        self.archive, self.checksum = pub.build_redrix(ROOT, self.package_dir)
        self.extracted = self.root / "extracted"
        self.extracted.mkdir()
        with tarfile.open(self.archive, "r:gz") as tf:
            tf.extractall(self.extracted, filter="data")
        self.package_root = self.extracted / pub.REDRIX_PACKAGE
        self._write_accepted_115_baseline()

    def tearDown(self):
        self.temp.cleanup()

    def _install(self, **kwargs):
        return inst.install_fixture(
            self.archive,
            self.checksum,
            self.home,
            self.uid,
            inst.FORCED_COMMAND,
            self.key_sha256,
            **kwargs,
        )

    def _write(self, rel: Path, data: bytes, mode: int):
        target = self.home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, mode)

    def _write_accepted_115_baseline(self):
        for source_path, blob, rel, mode in inst.ROLLBACK:
            data = (self.package_root / "rollback" / source_path).read_bytes()
            self.assertEqual(inst._git_blob(data), blob)
            self._write(rel, data, mode)

    def _write_current_baseline(self):
        for source_path, blob, rel, mode in inst.CURRENT:
            data = (self.package_root / "payload" / source_path).read_bytes()
            self.assertEqual(inst._git_blob(data), blob)
            self._write(rel, data, mode)

    def _auth_digest(self):
        return hashlib.sha256(self.authorized.read_bytes()).hexdigest()

    def _assert_accepted_115_restored(self):
        for _, blob, rel, mode in inst.ROLLBACK:
            target = self.home / rel
            self.assertEqual(inst._git_blob(target.read_bytes()), blob)
            self.assertEqual(target.stat().st_mode & 0o777, mode)
        rollback_rels = {item[2] for item in inst.ROLLBACK}
        for _, _, rel, _ in inst.CURRENT:
            if rel not in rollback_rels:
                self.assertFalse((self.home / rel).exists())

    def test_install_and_readback_preserve_authorized_keys(self):
        before = self._auth_digest()
        receipt = self._install()
        self.assertEqual(receipt["rollbackBaseline"], "accepted-115")
        self.assertEqual(self._auth_digest(), before)
        result = inst.readback_fixture(self.home, self.uid, inst.FORCED_COMMAND)
        self.assertTrue(result["authorizedKeysInvariant"])
        self.assertEqual(result["rollbackBaseline"], "accepted-115")
        self.assertEqual(result["files"], 7)
        for _, blob, rel, mode in inst.CURRENT:
            target = self.home / rel
            self.assertEqual(inst._git_blob(target.read_bytes()), blob)
            self.assertEqual(target.stat().st_mode & 0o777, mode)

    def test_reinstall_of_current_receipted_state_is_idempotent(self):
        first = self._install()
        second = self._install()
        self.assertEqual(first, second)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_partial_failure_rolls_back_exact_accepted_115_baseline(self):
        before = self._auth_digest()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_SYNTHETIC_INSTALL_FAULT"):
            self._install(fault_after=3)
        self.assertEqual(self._auth_digest(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())
        self.assertFalse((self.home / inst.RECEIPT_REL).exists())
        self._assert_accepted_115_restored()

    def test_post_receipt_fault_rolls_back_and_removes_stale_receipt(self):
        before = self._auth_digest()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_SYNTHETIC_POST_RECEIPT_FAULT"):
            self._install(fault_after_receipt=True)
        self.assertEqual(self._auth_digest(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())
        self.assertFalse((self.home / inst.RECEIPT_REL).exists())
        self._assert_accepted_115_restored()

    def test_explicit_rollback_restores_115_and_removes_receipt(self):
        before = self._auth_digest()
        self._install()
        inst.rollback_fixture(self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND)
        self.assertEqual(self._auth_digest(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())
        self.assertFalse((self.home / inst.RECEIPT_REL).exists())
        self._assert_accepted_115_restored()

    def test_interrupted_rollback_requires_and_completes_recovery(self):
        before = self._auth_digest()
        self._install()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_SYNTHETIC_ROLLBACK_FAULT"):
            inst.rollback_fixture(
                self.archive,
                self.checksum,
                self.home,
                self.uid,
                inst.FORCED_COMMAND,
                fault_after=1,
            )
        self.assertTrue((self.home / inst.TRANSACTION_REL).is_file())
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TRANSACTION_RECOVERY_REQUIRED"):
            self._install()
        inst.recover_fixture(self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())
        self.assertFalse((self.home / inst.RECEIPT_REL).exists())
        self.assertEqual(self._auth_digest(), before)
        self._assert_accepted_115_restored()

    def test_unknown_transport_baseline_is_refused_before_transaction(self):
        receiver = self.home / inst.RECEIVER_REL
        receiver.write_bytes(b"unknown receiver\n")
        os.chmod(receiver, 0o700)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_BASELINE_UNRECOGNIZED"):
            self._install()
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_forced_key_options_must_be_exact_and_are_never_rewritten(self):
        bad = self.line.replace("restrict,", "restrict,port-forwarding,")
        self.authorized.write_text(bad, encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        before = self.authorized.read_bytes()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FORCED_KEY_RESTRICTION_INVALID"):
            self._install()
        self.assertEqual(self.authorized.read_bytes(), before)

    def test_authorized_keys_mode_must_be_owner_only(self):
        os.chmod(self.authorized, 0o644)
        before = self.authorized.read_bytes()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FILE_MODE_INVALID"):
            self._install()
        self.assertEqual(self.authorized.read_bytes(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_group_writable_target_parent_is_refused(self):
        app = self.home / ".local/lib/ldw-dragonfly-jit"
        os.chmod(app, 0o770)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TARGET_PARENT_INVALID"):
            self._install()
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_group_writable_home_is_refused(self):
        os.chmod(self.home, 0o770)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_HOME_INVALID"):
            self._install()

    def test_readback_refuses_post_install_authorized_keys_change(self):
        self._install()
        self.authorized.write_text(self.line + "# changed\n", encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_AUTHORIZED_KEYS_CHANGED"):
            inst.readback_fixture(self.home, self.uid, inst.FORCED_COMMAND)

    def test_existing_transaction_blocks_blind_retry(self):
        transaction = self.home / inst.TRANSACTION_REL
        transaction.parent.mkdir(parents=True, exist_ok=True)
        marker = {
            "schema": 2,
            "operation": "install",
            "sourceCommit": inst.SOURCE_COMMIT,
            "packageSha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "authorizedKeysSha256": self._auth_digest(),
            "baseline": "accepted-115",
            "preexisting": {rel.as_posix(): rel in {item[2] for item in inst.ROLLBACK} for _, _, rel, _ in inst.CURRENT},
        }
        inst._write_transaction(transaction, marker)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TRANSACTION_RECOVERY_REQUIRED"):
            self._install()

    def test_recovery_restores_partial_receiver_from_durable_marker(self):
        auth = self._auth_digest()
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        preexisting = {rel.as_posix(): rel in {item[2] for item in inst.ROLLBACK} for _, _, rel, _ in inst.CURRENT}
        marker = {
            "schema": 2,
            "operation": "install",
            "sourceCommit": inst.SOURCE_COMMIT,
            "packageSha256": archive_digest,
            "authorizedKeysSha256": auth,
            "baseline": "accepted-115",
            "preexisting": preexisting,
        }
        transaction = self.home / inst.TRANSACTION_REL
        transaction.parent.mkdir(parents=True, exist_ok=True)
        inst._write_transaction(transaction, marker)
        current_receiver = self.package_root / "payload/dragonfly-jit/ssh_forced_receiver.py"
        self._write(inst.RECEIVER_REL, current_receiver.read_bytes(), 0o700)
        self.assertEqual(inst._git_blob((self.home / inst.RECEIVER_REL).read_bytes()), inst.CURRENT[0][1])
        inst.recover_fixture(
            self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
        )
        self.assertFalse(transaction.exists())
        self.assertEqual(inst._git_blob((self.home / inst.RECEIVER_REL).read_bytes()), inst.ROLLBACK[0][1])
        self.assertEqual(self._auth_digest(), auth)

    def test_rollback_is_refused_when_current_state_was_not_upgraded_from_115(self):
        # Rebuild the fixture as exact current state before any receipt exists.
        for _, _, rel, _ in inst.CURRENT:
            path = self.home / rel
            if path.exists():
                path.unlink()
        self._write_current_baseline()
        receipt = self._install()
        self.assertEqual(receipt["rollbackBaseline"], "accepted-133")
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_ROLLBACK_BASELINE_REFUSED"):
            inst.rollback_fixture(self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND)

    def test_symlinked_parent_is_refused(self):
        app = self.home / ".local/lib/ldw-dragonfly-jit"
        for child in list(app.iterdir()):
            child.unlink()
        app.rmdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        app.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TARGET_PARENT_INVALID"):
            self._install()

    def test_rollback_receiver_mode_drift_is_refused_before_transaction(self):
        receiver = self.home / inst.RECEIVER_REL
        os.chmod(receiver, 0o644)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FILE_MODE_INVALID"):
            self._install()
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_post_preflight_authorized_keys_swap_is_refused_at_install(self):
        inst._revalidate_gate_a3_before_transaction(
            self.home,
            self.uid,
            inst.FORCED_COMMAND,
            self.key_sha256,
            require_accepted_115=True,
        )
        swapped = self.line.replace(self.key_data, "AAAAC3NzaC1lZDI1NTE5AAAAIAnotherFixtureOnlyKey")
        self.authorized.write_text(swapped, encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TRANSPORT_KEY_IDENTITY_INVALID"):
            self._install()
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())


if __name__ == "__main__":
    unittest.main()
