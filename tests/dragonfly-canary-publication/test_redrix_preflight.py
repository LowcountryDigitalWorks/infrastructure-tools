#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
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


pre = load("dragonfly_canary_redrix_preflight", ROOT / "tools/dragonfly_canary_redrix_preflight.py")
inst = load("dragonfly_canary_redrix_install_preflight_test", ROOT / "tools/dragonfly_canary_redrix_install.py")


def git_blob_bytes(blob: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), "cat-file", "blob", blob], stderr=subprocess.DEVNULL)


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


class RedrixPreflightTests(unittest.TestCase):
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
        self.authorized.chmod(0o600)
        for _source_path, blob, rel, mode in inst.ROLLBACK:
            target = self.home / rel
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(git_blob_bytes(blob))
            target.chmod(mode)

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, expected_key_sha256: str | None = None):
        return pre.preflight_fixture(
            self.home,
            self.uid,
            inst,
            expected_key_sha256 or self.key_sha256,
        )

    def test_exact_accepted_115_preflight_is_read_only(self):
        before = snapshot(self.home)
        result = self.collect()
        after = snapshot(self.home)
        self.assertEqual(before, after)
        self.assertEqual(result["baseline"], "accepted-115")
        self.assertTrue(result["authorizedKeysInvariant"])
        self.assertEqual(result["transportKeyIdentity"], "expected")
        self.assertFalse(result["transactionPending"])
        self.assertFalse(result["receiptPresent"])
        self.assertFalse(result["packageOwnedResidue"])
        self.assertEqual(result["installerBlob"], pre.INSTALLER_BLOB)

    def test_installer_identity_is_pinned_to_accepted_blob(self):
        installer = pre._load_installer()
        self.assertEqual(installer.SOURCE_COMMIT, inst.SOURCE_COMMIT)
        self.assertEqual(pre._git_blob(pre.INSTALLER_PATH.read_bytes()), pre.INSTALLER_BLOB)
        with tempfile.TemporaryDirectory() as td:
            wrong = Path(td) / "installer.py"
            wrong.write_text("# wrong installer\n", encoding="utf-8")
            with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_INSTALLER_IDENTITY_MISMATCH"):
                pre._load_installer(wrong)

    def test_pending_transaction_is_refused_before_baseline_read(self):
        transaction = self.home / inst.TRANSACTION_REL
        transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        transaction.write_text("{}\n", encoding="utf-8")
        transaction.chmod(0o600)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_TRANSACTION_RECOVERY_REQUIRED"):
            self.collect()

    def test_existing_receipt_is_refused_for_first_gate_a_install(self):
        receipt = self.home / inst.RECEIPT_REL
        receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipt.write_text("{}\n", encoding="utf-8")
        receipt.chmod(0o600)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_RECEIPT_PRESENT"):
            self.collect()

    def test_package_owned_residue_is_refused_even_with_accepted_115_transport(self):
        current_only = next(item for item in inst.CURRENT if item[2] not in {r[2] for r in inst.ROLLBACK})
        _source, blob, rel, mode = current_only
        target = self.home / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(git_blob_bytes(blob))
        target.chmod(mode)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_RESIDUE_PRESENT"):
            self.collect()

    def test_current_transport_baseline_is_refused_for_first_install(self):
        for _source, _blob, rel, mode in inst.ROLLBACK:
            target = self.home / rel
            current_blob = next(item[1] for item in inst.CURRENT if item[2] == rel)
            target.write_bytes(git_blob_bytes(current_blob))
            target.chmod(mode)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_BASELINE_NOT_ACCEPTED_115"):
            self.collect()

    def test_forced_key_restriction_drift_is_refused_without_rewrite(self):
        bad = self.line.replace("restrict,", "restrict,port-forwarding,")
        self.authorized.write_text(bad, encoding="utf-8")
        self.authorized.chmod(0o600)
        before = self.authorized.read_bytes()
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FORCED_KEY_RESTRICTION_INVALID"):
            self.collect()
        self.assertEqual(self.authorized.read_bytes(), before)

    def test_transport_key_identity_swap_is_refused(self):
        swapped = self.line.replace(self.key_data, "AAAAC3NzaC1lZDI1NTE5AAAAIAnotherFixtureOnlyKey")
        self.authorized.write_text(swapped, encoding="utf-8")
        self.authorized.chmod(0o600)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_TRANSPORT_KEY_IDENTITY_INVALID"):
            self.collect()

    def test_expected_transport_key_hash_is_validated(self):
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_EXPECTED_TRANSPORT_KEY_SHA256_INVALID"):
            self.collect(expected_key_sha256="not-a-hash")

    def test_multiple_active_authorized_keys_are_refused(self):
        self.authorized.write_text(self.line + self.line, encoding="utf-8")
        self.authorized.chmod(0o600)
        with self.assertRaisesRegex(inst.InstallError, "REDRIX_FORCED_KEY_RESTRICTION_INVALID"):
            self.collect()

    def test_authorized_keys2_is_refused(self):
        alternate = self.home / pre.AUTHORIZED_KEYS2_REL
        alternate.write_text("synthetic\n", encoding="utf-8")
        alternate.chmod(0o600)
        with self.assertRaisesRegex(pre.PreflightError, "REDRIX_PREFLIGHT_AUTHORIZED_KEYS_ALTERNATE_PRESENT"):
            self.collect()


if __name__ == "__main__":
    unittest.main()
