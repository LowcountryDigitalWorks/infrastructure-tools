#!/usr/bin/env python3
"""Source-only REDRIX archive contract, runnable on Windows and POSIX hosts."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "dragonfly_canary_publication", ROOT / "tools/dragonfly_canary_publication.py"
)
assert spec is not None and spec.loader is not None
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)

# Accepted package contract, independent of filesystem permissions or manifest data.
MODES = {
    "manifest.json": 0o600,
    "payload/dragonfly-jit/ssh_forced_receiver.py": 0o700,
    "payload/dragonfly-jit/handoff_contract.py": 0o600,
    "payload/dragonfly-jit/canary_executor.py": 0o600,
    "payload/dragonfly-jit/dragonfly_jit.py": 0o600,
    "payload/dragonfly-jit/canary-guest/bootstrap.sh": 0o700,
    "payload/ci-runner/guest/run-one.sh": 0o755,
    "payload/ci-runner/guest/ci7-runner.service": 0o644,
    "rollback/dragonfly-jit/ssh_forced_receiver.py": 0o700,
    "rollback/dragonfly-jit/handoff_contract.py": 0o600,
}


class RedrixPackageModeTests(unittest.TestCase):
    def test_native_build_has_exact_modes_and_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            archive, checksum = pub.build_redrix(ROOT, Path(td) / "native")
            pub.verify_redrix(ROOT, archive, checksum)
            with tarfile.open(archive, "r:gz") as tf:
                actual = {
                    member.name.split("/", 1)[1]: member.mode
                    for member in tf.getmembers() if member.isfile()
                }
                self.assertEqual(actual, MODES)
                self.assertTrue(all(m.mode == 0o755 for m in tf.getmembers() if m.isdir()))

    def test_windows_and_posix_staging_metadata_produce_identical_archives(self):
        gettarinfo = tarfile.TarFile.gettarinfo

        def staging_metadata(windows):
            def get_info(tf, *args, **kwargs):
                info = gettarinfo(tf, *args, **kwargs)
                if info.isfile():
                    # Windows chmod only controls the read-only bit. Writable
                    # staging files report 0666, including scripts and manifest.
                    relative = info.name.split("/", 1)[1]
                    info.mode = 0o100666 if windows else 0o100000 | MODES[relative]
                return info
            return get_info

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with mock.patch.object(tarfile.TarFile, "gettarinfo", staging_metadata(True)):
                windows, windows_sum = pub.build_redrix(ROOT, base / "windows")
            with mock.patch.object(tarfile.TarFile, "gettarinfo", staging_metadata(False)):
                posix, posix_sum = pub.build_redrix(ROOT, base / "posix")
            pub.verify_redrix(ROOT, windows, windows_sum)
            pub.verify_redrix(ROOT, posix, posix_sum)
            self.assertEqual(windows.read_bytes(), posix.read_bytes())
            self.assertEqual(windows_sum.read_bytes(), posix_sum.read_bytes())

    def test_rechecksummed_wrong_modes_remain_refused(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            archive, _ = pub.build_redrix(ROOT, base / "source")
            for relative, expected in MODES.items():
                with self.subTest(member=relative, expected=oct(expected)):
                    tampered = base / "tampered.tar.gz"
                    with tarfile.open(archive, "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
                        for member in src.getmembers():
                            if member.name == f"{pub.REDRIX_PACKAGE}/{relative}":
                                member.mode = 0o666
                            handle = src.extractfile(member) if member.isfile() else None
                            try:
                                dst.addfile(member, handle)
                            finally:
                                if handle is not None:
                                    handle.close()
                    checksum = tampered.with_name(tampered.name + ".sha256")
                    checksum.write_text(
                        f"{hashlib.sha256(tampered.read_bytes()).hexdigest()}  {tampered.name}\n",
                        encoding="ascii",
                    )
                    with self.assertRaisesRegex(pub.PublicationError, "PACKAGE_FILE_MODE_MISMATCH"):
                        pub.verify_redrix(ROOT, tampered, checksum)


if __name__ == "__main__":
    unittest.main()
