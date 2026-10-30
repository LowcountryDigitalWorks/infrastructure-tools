#!/usr/bin/env python3
"""Source-only LDW01 ZIP contract, runnable on Windows and POSIX hosts."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "dragonfly_canary_publication", ROOT / "tools/dragonfly_canary_publication.py"
)
assert spec is not None and spec.loader is not None
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)

# Accepted package contract, independent of host permissions and manifest data.
MODES = {
    "manifest.json": 0o600,
    "ci-dispatch/DragonflyCanary.psm1": 0o600,
    "ci-dispatch/DragonflyCanaryRuntime.psm1": 0o600,
    "ci-dispatch/Dispatch.psm1": 0o600,
}


class Ldw01PackageModeTests(unittest.TestCase):
    def test_native_build_has_exact_modes_and_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            archive, checksum = pub.build_ldw01(ROOT, Path(td) / "native")
            pub.verify_ldw01(ROOT, archive, checksum)
            with zipfile.ZipFile(archive) as zf:
                members = zf.infolist()
                self.assertEqual({
                    info.filename.split("/", 1)[1]: info.external_attr >> 16
                    for info in members
                }, {path: stat.S_IFREG | mode for path, mode in MODES.items()})
                self.assertEqual([info.filename for info in members], sorted(info.filename for info in members))
                self.assertTrue(all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in members))
                self.assertTrue(all(info.create_system == 3 for info in members))

    def test_windows_and_posix_staging_metadata_produce_identical_archives(self):
        path_stat = Path.stat
        zip_info = zipfile.ZipInfo

        def staging_metadata(windows):
            def get_stat(path, *args, **kwargs):
                result = path_stat(path, *args, **kwargs)
                if pub.LDW01_PACKAGE in path.parts and stat.S_ISREG(result.st_mode):
                    values = list(result)
                    values[0] = stat.S_IFREG | (0o666 if windows else 0o600)
                    return os.stat_result(values)
                return result
            return get_stat

        def host_zip_info(windows):
            class HostZipInfo(zip_info):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.create_system = 0 if windows else 3
            return HostZipInfo

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            archives = []
            for windows, name in ((True, "windows"), (False, "posix")):
                with mock.patch.object(Path, "stat", staging_metadata(windows)), mock.patch.object(
                    zipfile, "ZipInfo", host_zip_info(windows)
                ):
                    archives.append(pub.build_ldw01(ROOT, base / name))
            for archive, checksum in archives:
                pub.verify_ldw01(ROOT, archive, checksum)
            self.assertEqual(archives[0][0].read_bytes(), archives[1][0].read_bytes())
            self.assertEqual(archives[0][1].read_bytes(), archives[1][1].read_bytes())

    def test_rechecksummed_wrong_modes_remain_refused(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            archive, _ = pub.build_ldw01(ROOT, base / "source")
            for relative in MODES:
                with self.subTest(member=relative):
                    tampered = base / "tampered.zip"
                    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w") as dst:
                        for info in src.infolist():
                            data = src.read(info)
                            if info.filename == f"{pub.LDW01_PACKAGE}/{relative}":
                                info.external_attr = (stat.S_IFREG | 0o666) << 16
                            dst.writestr(info, data)
                    checksum = tampered.with_name(tampered.name + ".sha256")
                    checksum.write_text(
                        f"{hashlib.sha256(tampered.read_bytes()).hexdigest()}  {tampered.name}\n",
                        encoding="ascii",
                    )
                    with self.assertRaisesRegex(pub.PublicationError, "PACKAGE_FILE_MODE_MISMATCH"):
                        pub.verify_ldw01(ROOT, tampered, checksum)

    def test_unlisted_regular_file_is_refused(self):
        write = pub._write

        def inject_unlisted_file(root, relative, data, mode):
            write(root, relative, data, mode)
            if relative == "manifest.json":
                (root / "unlisted.txt").write_bytes(b"unlisted source fixture\n")

        with tempfile.TemporaryDirectory() as td, mock.patch.object(pub, "_write", inject_unlisted_file):
            with self.assertRaisesRegex(pub.PublicationError, "PACKAGE_INVENTORY_DRIFT"):
                pub.build_ldw01(ROOT, Path(td) / "source")


if __name__ == "__main__":
    unittest.main()
