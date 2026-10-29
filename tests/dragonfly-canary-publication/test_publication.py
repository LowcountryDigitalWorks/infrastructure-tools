#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/dragonfly_canary_publication.py"
spec = importlib.util.spec_from_file_location("dragonfly_canary_publication", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("PUBLICATION_MODULE_LOAD_FAILED")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DragonflyCanaryPublicationTests(unittest.TestCase):
    def _checksum(self, archive: Path) -> Path:
        checksum = archive.with_name(archive.name + ".sha256")
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
            encoding="ascii",
        )
        return checksum

    def test_redrix_package_is_reproducible_and_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            first, first_sum = mod.build_redrix(ROOT, base / "one")
            second, second_sum = mod.build_redrix(ROOT, base / "two")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_sum.read_text(), second_sum.read_text())
            manifest = mod.verify_redrix(ROOT, first, first_sum)
            self.assertEqual(manifest["sourceCommit"], mod.SOURCE_COMMIT)
            self.assertEqual(manifest["sourceTree"], mod.SOURCE_TREE)
            self.assertEqual(manifest["rollbackCommit"], mod.ROLLBACK_COMMIT)
            self.assertFalse(manifest["containsCredential"])
            self.assertFalse(manifest["containsBootstrap"])
            self.assertFalse(manifest["containsPrivateKey"])
            self.assertFalse(manifest["authorizedKeysMutationAuthorized"])
            self.assertEqual(len(manifest["entries"]), 9)

    def test_ldw01_package_is_reproducible_and_uses_accepted_dispatcher(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            first, first_sum = mod.build_ldw01(ROOT, base / "one")
            second, second_sum = mod.build_ldw01(ROOT, base / "two")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_sum.read_text(), second_sum.read_text())
            manifest = mod.verify_ldw01(ROOT, first, first_sum)
            self.assertEqual(manifest["sourceCommit"], mod.SOURCE_COMMIT)
            self.assertEqual(manifest["dispatcherAuthority"]["commit"], mod.DISPATCH_COMMIT)
            self.assertEqual(manifest["dispatcherAuthority"]["blob"], mod.DISPATCH_BLOB)
            current_dispatch = str(mod._git(ROOT, "rev-parse", f"{mod.SOURCE_COMMIT}:ci-dispatch/Dispatch.psm1")).strip()
            self.assertNotEqual(current_dispatch, mod.DISPATCH_BLOB)
            self.assertEqual(len(manifest["entries"]), 3)

    def test_redrix_inventory_and_targets_are_closed(self):
        expected_targets = {
            "~/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py",
            "~/.local/lib/ldw-dragonfly-jit/handoff_contract.py",
            "~/.local/lib/ldw-dragonfly-jit/canary_executor.py",
            "~/.local/lib/ldw-dragonfly-jit/dragonfly_jit.py",
            "~/.local/lib/ldw-dragonfly-jit/canary-guest/bootstrap.sh",
            "~/.local/lib/ci-runner/guest/run-one.sh",
            "~/.local/lib/ci-runner/guest/ci7-runner.service",
        }
        self.assertEqual({item[2] for item in mod.REDRIX_CURRENT}, expected_targets)
        self.assertEqual({item[2] for item in mod.REDRIX_ROLLBACK}, {
            "~/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py",
            "~/.local/lib/ldw-dragonfly-jit/handoff_contract.py",
        })

    def test_all_pinned_git_blobs_resolve_exactly(self):
        for path, blob, _, _ in mod.REDRIX_CURRENT:
            self.assertEqual(str(mod._git(ROOT, "rev-parse", f"{mod.SOURCE_COMMIT}:{path}")).strip(), blob)
        for path, blob, _, _ in mod.REDRIX_ROLLBACK:
            self.assertEqual(str(mod._git(ROOT, "rev-parse", f"{mod.ROLLBACK_COMMIT}:{path}")).strip(), blob)
        for commit, path, blob in mod.LDW01_FILES:
            self.assertEqual(str(mod._git(ROOT, "rev-parse", f"{commit}:{path}")).strip(), blob)

    def test_dispatcher_sha256_representation_is_explicit(self):
        raw = mod._blob(ROOT, mod.DISPATCH_COMMIT, "ci-dispatch/Dispatch.psm1", mod.DISPATCH_BLOB)
        lf = hashlib.sha256(raw).hexdigest()
        crlf_bytes = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        crlf = hashlib.sha256(crlf_bytes).hexdigest()
        self.assertEqual(
            mod.DISPATCH_SHA256,
            lf,
            f"DISPATCH_SHA256_REPRESENTATION_MISMATCH raw={lf} crlf={crlf}",
        )

    def test_wrong_checksum_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            archive, checksum = mod.build_redrix(ROOT, Path(td) / "pkg")
            checksum.write_text("0" * 64 + f"  {archive.name}\n", encoding="ascii")
            with self.assertRaisesRegex(mod.PublicationError, "PACKAGE_CHECKSUM_MISMATCH"):
                mod.verify_redrix(ROOT, archive, checksum)

    def test_redrix_symlink_member_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / f"{mod.REDRIX_PACKAGE}.tar.gz"
            with archive.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
                    with tarfile.open(fileobj=gz, mode="w") as tf:
                        root = tarfile.TarInfo(mod.REDRIX_PACKAGE)
                        root.type = tarfile.DIRTYPE
                        tf.addfile(root)
                        link = tarfile.TarInfo(mod.REDRIX_PACKAGE + "/escape")
                        link.type = tarfile.SYMTYPE
                        link.linkname = "/tmp/escape"
                        tf.addfile(link)
            checksum = self._checksum(archive)
            with self.assertRaisesRegex(mod.PublicationError, "PACKAGE_MEMBER_TYPE_REFUSED"):
                mod.verify_redrix(ROOT, archive, checksum)

    def test_ldw01_path_escape_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / f"{mod.LDW01_PACKAGE}.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(mod.LDW01_PACKAGE + "/../escape", b"x")
            checksum = self._checksum(archive)
            with self.assertRaisesRegex(mod.PublicationError, "PACKAGE_ARCHIVE_PATH_REFUSED"):
                mod.verify_ldw01(ROOT, archive, checksum)

    def test_packages_do_not_contain_key_or_credential_files(self):
        forbidden = {"authorized_keys", "known_hosts", "id_ed25519", "credentials", "credential.secret"}
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            redrix, _ = mod.build_redrix(ROOT, base / "redrix")
            with tarfile.open(redrix, "r:gz") as tf:
                names = {Path(item.name).name.lower() for item in tf.getmembers() if item.isfile()}
            ldw01, _ = mod.build_ldw01(ROOT, base / "ldw01")
            with zipfile.ZipFile(ldw01, "r") as zf:
                names |= {Path(item.filename).name.lower() for item in zf.infolist() if not item.is_dir()}
            self.assertTrue(forbidden.isdisjoint(names))


if __name__ == "__main__":
    unittest.main()
