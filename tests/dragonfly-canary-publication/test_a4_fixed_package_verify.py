"""Adversarial Linux normal-user tests for source-only A4 pinned bundle byte reader."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools" / "dragonfly_gate_a4_fixed_package_verify.py"
INSPECTOR = ROOT / "tools" / "dragonfly_gate_a4_live_evidence.py"
spec = importlib.util.spec_from_file_location("ldw_a4_fixed_package", SOURCE)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

UID = os.getuid() if hasattr(os, "getuid") else 1000
GID = os.getgid() if hasattr(os, "getgid") else 1000


@unittest.skipUnless(os.name == "posix", "Linux descriptor and ownership proof")
class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-a4-package-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "fake-root"
        self.root.mkdir(mode=0o700)
        self.dirs = [self.root]
        parent = self.root
        for segment in probe.FIXED_PACKAGE_PARTS:
            parent = parent / segment
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            self.dirs.append(parent)
        self.file = parent / probe.FIXED_INSPECTOR_FILE
        self.file.write_bytes(INSPECTOR.read_bytes())
        self.file.chmod(0o644)

    def result(self):
        output = probe._observe_tree(self.root, UID, GID)
        self.assertEqual(output["marker"], probe.MARKER)
        self.assertEqual(output["schema"], 1)
        for flag in ("protectedInstallAuthorized", "physicalExecutionAuthorized",
                     "privilegedChannelAuthenticated", "a4Pass", "runtimeAuthority",
                     "jitAdmissionAuthorized", "hostMutationPerformed"):
            self.assertIs(output[flag], False)
        return output

    def hold(self, reason=None):
        r = self.result()
        self.assertEqual(r["classification"], "HOLD")
        self.assertIs(r["fixedPackageBytesObserved"], False)
        if reason:
            self.assertEqual(r["reasonCode"], reason)

    def test_valid_synthetic_bytes_are_always_non_authorizing(self):
        r = self.result()
        self.assertEqual(r["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertIs(r["fixedPackageBytesObserved"], True)
        self.assertEqual(r["reasonCode"], "INDEPENDENT_ROOT_ISSUER_AND_CHANNEL_NOT_INSTALLED")

    def test_hardcoded_runtime_never_installs_or_executes(self):
        self.assertIs(probe.PROTECTED_INSTALL_ENABLED, False)
        self.assertIs(probe.PHYSICAL_EXECUTION_ENABLED, False)
        self.assertEqual(probe.FIXED_PACKAGE_PARTS, ("usr", "libexec", "ldw-redrix-a4"))
        self.assertEqual(probe.FIXED_INSPECTOR_FILE, "dragonfly_gate_a4_live_evidence.py")

    def test_source_blob_and_sha_are_real_pins(self):
        import hashlib
        data = INSPECTOR.read_bytes()
        self.assertEqual(len(data), probe.PINNED_INSPECTOR_SIZE)
        self.assertEqual(hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest(),
                         probe.PINNED_INSPECTOR_GIT_BLOB)
        self.assertEqual(hashlib.sha256(data).hexdigest(), probe.PINNED_INSPECTOR_SHA256)

    def test_production_entrypoint_fixed_to_linux_root_and_uid0(self):
        with mock.patch.object(probe, "_observe_tree", return_value=probe._report("HOLD")) as checker:
            out = probe.observe_fixed_package()
        self.assertEqual(out["classification"], "HOLD")
        checker.assert_called_once_with(Path("/"), 0, 0)

    def test_missing_package_directory_refuses(self):
        shutil.rmtree(self.dirs[-1])
        self.hold("PACKAGE_READ_UNAVAILABLE")

    def test_missing_inspector_refuses(self):
        self.file.unlink()
        self.hold("PACKAGE_READ_UNAVAILABLE")

    def test_empty_inspector_refuses(self):
        self.file.write_bytes(b"")
        self.hold("INSPECTOR_SIZE_DRIFT")

    def test_appended_bytes_refuse(self):
        self.file.write_bytes(INSPECTOR.read_bytes()+b"\n")
        self.hold("INSPECTOR_SIZE_DRIFT")

    def test_changed_equal_size_bytes_refuse(self):
        data = bytearray(INSPECTOR.read_bytes())
        data[-1] ^= 0x01
        self.file.write_bytes(data)
        self.hold("INSPECTOR_BLOB_DRIFT")

    def test_symlink_inspector_refuses(self):
        self.file.unlink()
        self.file.symlink_to(INSPECTOR)
        self.hold()

    def test_symlink_directory_ancestor_refuses(self):
        child = self.dirs[2]
        shutil.rmtree(child)
        child.symlink_to(ROOT / "tools", target_is_directory=True)
        self.hold()

    def test_world_writable_root_refuses(self):
        self.root.chmod(0o777)
        self.hold("PACKAGE_ANCESTOR_WRITABLE")

    def test_group_writable_package_dir_refuses(self):
        self.dirs[-1].chmod(0o775)
        self.hold("PACKAGE_ANCESTOR_WRITABLE")

    def test_group_writable_intermediate_dir_refuses(self):
        self.dirs[1].chmod(0o775)
        self.hold("PACKAGE_ANCESTOR_WRITABLE")

    def test_group_writable_inspector_refuses(self):
        self.file.chmod(0o664)
        self.hold("INSPECTOR_WRITABLE_BY_UNTRUSTED")

    def test_wrong_root_uid_refuses(self):
        self.assertEqual(probe._observe_tree(self.root, UID+1, GID)["reasonCode"], "PACKAGE_OWNER_UNTRUSTED")

    def test_wrong_root_gid_refuses(self):
        self.assertEqual(probe._observe_tree(self.root, UID, GID+1)["reasonCode"], "PACKAGE_OWNER_UNTRUSTED")

    def test_inspector_hardlink_refuses(self):
        os.link(self.file, self.dirs[-1] / "second-name")
        self.hold("INSPECTOR_HARDLINK_REFUSED")

    def test_non_directory_ancestor_refuses(self):
        shutil.rmtree(self.dirs[1])
        self.dirs[1].write_text("not-a-directory")
        self.hold("PACKAGE_READ_UNAVAILABLE")

    def test_file_mutated_while_descriptor_open_refuses(self):
        original = probe._read_pinned
        def sabotage(fd):
            original(fd)
            data = bytearray(self.file.read_bytes())
            data[0] ^= 1
            self.file.write_bytes(data)
        with mock.patch.object(probe, "_read_pinned", side_effect=sabotage):
            self.hold("INSPECTOR_DESCRIPTOR_CHANGED")

    def test_file_path_replaced_while_pinned_refuses(self):
        original = probe._read_pinned
        def replace(fd):
            original(fd)
            replacement = self.file.with_name("replacement")
            replacement.write_bytes(INSPECTOR.read_bytes())
            replacement.chmod(0o644)
            os.replace(replacement, self.file)
        with mock.patch.object(probe, "_read_pinned", side_effect=replace):
            self.hold("INSPECTOR_PATH_REPLACED")

    def test_ancestor_replaced_while_pinned_refuses(self):
        original = probe._read_pinned
        def replace_dir(fd):
            original(fd)
            original_dir = self.dirs[-1]
            os.rename(original_dir, original_dir.with_name("moved"))
            original_dir.mkdir(mode=0o755)
        with mock.patch.object(probe, "_read_pinned", side_effect=replace_dir):
            self.hold()

    def test_block_external_execution_and_socket_mutations(self):
        with mock.patch.object(os, "system", side_effect=AssertionError("system called")), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("run called")), \
             mock.patch.object(socket, "socket", side_effect=AssertionError("socket called")):
            r = self.result()
        self.assertEqual(r["classification"], "DATA_ONLY_NOT_AUTHORIZED")

    def test_platform_refusal_before_filesystem_access(self):
        with mock.patch.object(probe.sys, "platform", "win32"):
            self.hold("PLATFORM_OR_SOURCE_SHAPE_REFUSED")

    def test_bool_owner_uid_refused_not_int(self):
        self.assertEqual(probe._observe_tree(self.root, True, GID)["reasonCode"],
                         "PLATFORM_OR_SOURCE_SHAPE_REFUSED")

    def test_absent_live_package_stays_hold_without_authority(self):
        with mock.patch.object(probe, "_observe_tree",
                               return_value=probe._report("PACKAGE_READ_UNAVAILABLE")):
            r = probe.observe_fixed_package()
        self.assertEqual(r["classification"], "HOLD")
        self.assertIs(r["a4Pass"], False)


if __name__ == "__main__":
    unittest.main()
