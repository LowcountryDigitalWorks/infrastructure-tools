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
        self.line = (
            f'restrict,command="{inst.FORCED_COMMAND}" '
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey material\n"
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

    def _auth_digest(self):
        return hashlib.sha256(self.authorized.read_bytes()).hexdigest()

    def test_install_and_readback_preserve_authorized_keys(self):
        before = self._auth_digest()
        receipt = inst.install_fixture(
            self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
        )
        self.assertEqual(receipt["baseline"], "accepted-115")
        self.assertEqual(self._auth_digest(), before)
        result = inst.readback_fixture(self.home, self.uid, inst.FORCED_COMMAND)
        self.assertTrue(result["authorizedKeysInvariant"])
        self.assertEqual(result["files"], 7)
        for _, blob, rel, mode in inst.CURRENT:
            target = self.home / rel
            self.assertEqual(inst._git_blob(target.read_bytes()), blob)
            self.assertEqual(target.stat().st_mode & 0o777, mode)

    def test_partial_failure_rolls_back_exact_accepted_115_baseline(self):
        before = self._auth_digest()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_SYNTHETIC_INSTALL_FAULT"):
            inst.install_fixture(
                self.archive,
                self.checksum,
                self.home,
                self.uid,
                inst.FORCED_COMMAND,
                fault_after=3,
            )
        self.assertEqual(self._auth_digest(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())
        for source_path, blob, rel, mode in inst.ROLLBACK:
            target = self.home / rel
            self.assertEqual(inst._git_blob(target.read_bytes()), blob)
            self.assertEqual(target.stat().st_mode & 0o777, mode)
        rollback_rels = {item[2] for item in inst.ROLLBACK}
        for _, _, rel, _ in inst.CURRENT:
            if rel not in rollback_rels:
                self.assertFalse((self.home / rel).exists())

    def test_unknown_transport_baseline_is_refused_before_transaction(self):
        receiver = self.home / inst.RECEIVER_REL
        receiver.write_bytes(b"unknown receiver\n")
        os.chmod(receiver, 0o700)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_BASELINE_UNRECOGNIZED"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_forced_key_options_must_be_exact_and_are_never_rewritten(self):
        bad = self.line.replace("restrict,", "restrict,port-forwarding,")
        self.authorized.write_text(bad, encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        before = self.authorized.read_bytes()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FORCED_KEY_RESTRICTION_INVALID"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )
        self.assertEqual(self.authorized.read_bytes(), before)

    def test_authorized_keys_mode_must_be_owner_only(self):
        os.chmod(self.authorized, 0o644)
        before = self.authorized.read_bytes()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FILE_MODE_INVALID"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )
        self.assertEqual(self.authorized.read_bytes(), before)
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_group_writable_target_parent_is_refused(self):
        app = self.home / ".local/lib/ldw-dragonfly-jit"
        os.chmod(app, 0o770)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TARGET_PARENT_INVALID"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )
        self.assertFalse((self.home / inst.TRANSACTION_REL).exists())

    def test_group_writable_home_is_refused(self):
        os.chmod(self.home, 0o770)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_HOME_INVALID"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )

    def test_readback_refuses_post_install_authorized_keys_change(self):
        inst.install_fixture(
            self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
        )
        self.authorized.write_text(self.line + "# changed\n", encoding="utf-8")
        os.chmod(self.authorized, 0o600)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_AUTHORIZED_KEYS_CHANGED"):
            inst.readback_fixture(self.home, self.uid, inst.FORCED_COMMAND)

    def test_existing_transaction_blocks_blind_retry(self):
        transaction = self.home / inst.TRANSACTION_REL
        transaction.parent.mkdir(parents=True, exist_ok=True)
        transaction.write_text("{}\n", encoding="utf-8")
        os.chmod(transaction, 0o600)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TRANSACTION_RECOVERY_REQUIRED"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )

    def test_recovery_restores_partial_receiver_from_durable_marker(self):
        auth = self._auth_digest()
        archive_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        preexisting = {rel.as_posix(): rel in {item[2] for item in inst.ROLLBACK} for _, _, rel, _ in inst.CURRENT}
        marker = {
            "schema": 1,
            "sourceCommit": inst.SOURCE_COMMIT,
            "packageSha256": archive_digest,
            "authorizedKeysSha256": auth,
            "baseline": "accepted-115",
            "preexisting": preexisting,
            "phase": "installing",
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

    def test_symlinked_parent_is_refused(self):
        app = self.home / ".local/lib/ldw-dragonfly-jit"
        for child in list(app.iterdir()):
            child.unlink()
        app.rmdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        app.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_TARGET_PARENT_INVALID"):
            inst.install_fixture(
                self.archive, self.checksum, self.home, self.uid, inst.FORCED_COMMAND
            )


if __name__ == "__main__":
    unittest.main()
