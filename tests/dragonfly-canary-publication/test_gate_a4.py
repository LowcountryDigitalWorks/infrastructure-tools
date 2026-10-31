#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ACCEPTED_MAIN_COMMIT = "f736bbd36da4e99bb10c6e33b0dfba3bd7074f0b"


def git_tree_blob(commit: str, path: str) -> str:
    output = subprocess.check_output(
        ["git", "-C", str(ROOT), "ls-tree", commit, path],
        text=True,
    ).strip()
    return output.split()[2]


def git_cat_file_blob(blob: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "cat-file", "blob", blob],
    )


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("MODULE_LOAD_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a4 = load("dragonfly_gate_a4_test", ROOT / "tools" / "dragonfly_gate_a4.py")


def git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


class FakeInstaller:
    SOURCE_COMMIT = "78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca"
    SOURCE_TREE = "5f54ee5b76f49250db1358f058745cb30b6587ef"
    FORCED_COMMAND = "/home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"
    CURRENT = (
        ("payload/a.py", "aa" * 20, Path(".local/lib/ldw-dragonfly-jit/a.py"), 0o600),
        ("payload/b.py", "bb" * 20, Path(".local/lib/ldw-dragonfly-jit/b.py"), 0o600),
        ("payload/c.sh", "cc" * 20, Path(".local/lib/ldw-dragonfly-jit/c.sh"), 0o700),
    )
    ROLLBACK = (
        ("rollback/a.py", "dd" * 20, Path(".local/lib/ldw-dragonfly-jit/a.py"), 0o600),
        ("rollback/b.py", "ee" * 20, Path(".local/lib/ldw-dragonfly-jit/b.py"), 0o600),
    )

    def __init__(self):
        rollback_targets = {rel.as_posix() for _, _, rel, _ in self.ROLLBACK}
        preexisting = {
            rel.as_posix(): rel.as_posix() in rollback_targets
            for _, _, rel, _ in self.CURRENT
        }
        self.package_sha = "a" * 64
        self.receipt = {
            "schema": 2,
            "sourceCommit": self.SOURCE_COMMIT,
            "sourceTree": self.SOURCE_TREE,
            "packageSha256": self.package_sha,
            "authorizedKeysSha256": "b" * 64,
            "rollbackBaseline": "accepted-115",
            "preexisting": preexisting,
        }
        self.result = {
            "sourceCommit": self.SOURCE_COMMIT,
            "sourceTree": self.SOURCE_TREE,
            "authorizedKeysInvariant": True,
            "transactionPending": False,
            "rollbackBaseline": "accepted-115",
            "files": len(self.CURRENT),
        }
        self.calls = 0
        self.receipt_reads = 0

    def _read_receipt(self, home, uid):
        del home, uid
        self.receipt_reads += 1
        return dict(self.receipt)

    def readback_fixture(self, home, uid, forced_command):
        del home, uid
        if forced_command != self.FORCED_COMMAND:
            raise RuntimeError("FORCED_COMMAND_DRIFT")
        self.calls += 1
        return dict(self.result)


class FakeA0:
    PROC_ROOT = Path("/synthetic/proc")

    def __init__(self):
        self.network_calls = 0
        self.mutate_network = False

    def _validate_jit_state(self, home, uid):
        del home, uid
        return {
            "jitState": "STOPPED",
            "runIdPresent": False,
            "qemuPidPresent": False,
            "runResidueCount": 0,
            "guestLockAvailable": True,
            "stateLockAvailable": True,
        }

    def _qemu_snapshot(self, runner, proc_root, uid):
        del runner, proc_root, uid
        return {"qemuProcessCount": 0, "sameUidKvmFdProcessCount": 0}

    def _transport_authorized_key(self, home, uid, expected_key_sha256):
        del home, uid
        if len(expected_key_sha256) != 64:
            raise RuntimeError("A0_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")
        return {
            "authorizedKeysInvariant": True,
            "authorizedKeysActiveEntries": 1,
            "sshDirectoryMode": "0700",
            "transportKeyIdentity": "expected",
        }

    def _network_snapshot(self, runner, expected_host_fingerprint):
        del runner
        self.network_calls += 1
        value = {
            "hostFingerprintInvariant": expected_host_fingerprint.startswith("SHA256:"),
            "sshServiceActive": True,
            "sshServiceEnabled": True,
            "tcp22Listening": True,
            "tcp22NonLoopbackListening": True,
            "tailscaleBackend": "Running",
            "tailscaleSelfOnline": True,
            "tailscaleSsh": False,
            "tailscaleServeOrFunnelConfigured": False,
        }
        if self.mutate_network and self.network_calls > 1:
            value["tailscaleSelfOnline"] = False
        return value


class GateA4Tests(unittest.TestCase):
    def setUp(self):
        self.installer = FakeInstaller()
        self.a0 = FakeA0()
        self.kwargs = {
            "home": Path("/synthetic/home"),
            "uid": 1000,
            "installer": self.installer,
            "a0": self.a0,
            "runner": object(),
            "expected_local_alias": "redrix",
            "expected_host_fingerprint": "SHA256:SyntheticFingerprint",
            "expected_transport_key_sha256": "c" * 64,
            "expected_package_sha256": "a" * 64,
            "proc_root": Path("/synthetic/proc"),
        }

    def collect(self):
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            return a4.collect_a4(**self.kwargs)

    def test_accepted_post_install_state_emits_stable_sanitized_evidence(self):
        result = self.collect()
        self.assertEqual(result["marker"], "DRAGONFLY_GATE_A4_V1")
        self.assertEqual(result["installedSourceCommit"], self.installer.SOURCE_COMMIT)
        self.assertEqual(result["installedSourceTree"], self.installer.SOURCE_TREE)
        self.assertEqual(result["packageIdentity"], "expected")
        self.assertTrue(result["rollbackReceiptValidated"])
        self.assertTrue(result["installReceiptValidated"])
        self.assertEqual(result["jitState"], "STOPPED")
        self.assertEqual(result["transportKeyIdentity"], "expected")
        self.assertEqual(result["stabilityPasses"], 2)
        self.assertRegex(result["snapshotSha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(self.installer.calls, 2)
        self.assertEqual(self.installer.receipt_reads, 2)
        self.assertNotIn("expectedTransportKeySha256", result)
        self.assertNotIn("expectedHostFingerprint", result)
        self.assertNotIn("expectedPackageSha256", result)
        self.assertNotIn("packageSha256", result)
        self.assertNotIn("rollbackRetained", result)

    def test_snapshot_movement_is_refused(self):
        self.a0.mutate_network = True
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_SNAPSHOT_CHANGED_DURING_READBACK"):
                a4.collect_a4(**self.kwargs)

    def test_wrong_installed_identity_is_refused(self):
        self.installer.result["sourceCommit"] = "0" * 40
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_INSTALLED_SOURCE_COMMIT_MISMATCH"):
                a4.collect_a4(**self.kwargs)

    def test_rollback_must_remain_accepted_115(self):
        self.installer.result["rollbackBaseline"] = "accepted-133"
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_ROLLBACK_BASELINE_NOT_RETAINED"):
                a4.collect_a4(**self.kwargs)

    def test_local_alias_is_exact(self):
        with mock.patch.object(a4.socket, "gethostname", return_value="penguin"):
            with self.assertRaisesRegex(a4.A4Error, "A4_LOCAL_HOST_IDENTITY_MISMATCH"):
                a4.collect_a4(**self.kwargs)

    def test_pinned_dependency_blobs_match_accepted_main_git_objects(self):
        self.assertEqual(
            a4.INSTALLER_BLOB,
            git_tree_blob(ACCEPTED_MAIN_COMMIT, "tools/dragonfly_canary_redrix_install.py"),
        )
        self.assertEqual(
            a4.A0_BLOB,
            git_tree_blob(ACCEPTED_MAIN_COMMIT, "tools/dragonfly_gate_a0.py"),
        )

    def test_pinned_installer_git_object_bytes_match_executed_bytes(self):
        data = git_cat_file_blob(a4.INSTALLER_BLOB)
        self.assertEqual(a4._git_blob(data), a4.INSTALLER_BLOB)
        recorded: dict[str, bytes] = {}
        real_compile = compile

        def recording_compile(source, filename, mode, dont_inherit=False, optimize=-1, **_kwargs):
            recorded["source"] = source
            return real_compile(b"RESULT='ok'\n", filename, mode, dont_inherit=True)

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dependency.py"
            path.write_bytes(data)
            with mock.patch("builtins.compile", side_effect=recording_compile):
                module = a4._load_pinned(
                    "ldw_gate_a4_installer_bytes",
                    path,
                    a4.INSTALLER_BLOB,
                )
            self.assertEqual(recorded["source"], data)
            self.assertEqual(module.RESULT, "ok")

    def test_worktree_crlf_does_not_weaken_git_object_pin(self):
        data = git_cat_file_blob(a4.INSTALLER_BLOB)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dependency.py"
            path.write_bytes(data.replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(a4.A4Error, "A4_SOURCE_IDENTITY_MISMATCH"):
                a4._load_pinned("ldw_gate_a4_crlf", path, a4.INSTALLER_BLOB)

    def test_source_has_no_runtime_mutation_or_remote_control_surface(self):
        text = (ROOT / "tools" / "dragonfly_gate_a4.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess.run(",
            "subprocess.Popen(",
            "os.replace(",
            "os.unlink(",
            "os.remove(",
            "shutil.rmtree(",
            "generate-jitconfig",
            "gh api",
            "ssh.exe",
            "qemu-system-x86_64",
            ".install_fixture(",
            ".recover_fixture(",
            ".rollback_fixture(",
        ):
            self.assertNotIn(forbidden, text)

    def test_verified_bytes_execute_after_path_replacement(self):
        verified = b"VALUE = 'verified-bytes'\n"
        substituted = b"VALUE = 'substituted-bytes'\n"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dependency.py"
            path.write_bytes(verified)
            expected = a4._git_blob(verified)
            real_blob = a4._git_blob

            def swap_after_verified_read(data: bytes) -> str:
                path.write_bytes(substituted)
                return real_blob(data)

            with mock.patch.object(a4, "_git_blob", side_effect=swap_after_verified_read):
                module = a4._load_pinned("ldw_gate_a4_race", path, expected)
            self.assertEqual(path.read_bytes(), substituted)
            self.assertEqual(module.VALUE, "verified-bytes")
            self.assertEqual(module.__name__, "ldw_gate_a4_race")
            self.assertEqual(module.__file__, str(path))

    def test_mismatched_blob_does_not_execute(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "dependency.py"
            side = root / "executed.txt"
            path.write_bytes(
                f"from pathlib import Path\nPath({str(side)!r}).write_text('ran', encoding='utf-8')\n".encode(
                    "utf-8"
                )
            )
            with self.assertRaisesRegex(a4.A4Error, "A4_SOURCE_IDENTITY_MISMATCH"):
                a4._load_pinned("ldw_gate_a4_mismatch", path, "0" * 40)
            self.assertFalse(side.exists())

    def test_compile_failure_is_sanitized_import_failure(self):
        source = b"def (\n"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dependency.py"
            path.write_bytes(source)
            with self.assertRaisesRegex(a4.A4Error, "A4_SOURCE_IMPORT_FAILED") as caught:
                a4._load_pinned("ldw_gate_a4_bad", path, a4._git_blob(source))
            self.assertEqual(str(caught.exception), "A4_SOURCE_IMPORT_FAILED")

    def test_invalid_expected_package_hash_is_refused(self):
        self.kwargs["expected_package_sha256"] = "NOT_A_SHA"
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_EXPECTED_PACKAGE_SHA256_INVALID"):
                a4.collect_a4(**self.kwargs)
        self.assertEqual(self.installer.receipt_reads, 0)

    def test_wrong_receipt_package_hash_is_refused(self):
        self.installer.receipt["packageSha256"] = "f" * 64
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_RECEIPT_PACKAGE_IDENTITY_MISMATCH"):
                a4.collect_a4(**self.kwargs)

    def test_receipt_preexisting_true_to_false_on_rollback_target_is_refused(self):
        target = self.installer.ROLLBACK[0][2].as_posix()
        self.installer.receipt["preexisting"][target] = False
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_RECEIPT_PREEXISTING_MISMATCH"):
                a4.collect_a4(**self.kwargs)

    def test_receipt_preexisting_false_to_true_on_non_rollback_target_is_refused(self):
        non_rollback = self.installer.CURRENT[2][2].as_posix()
        self.assertNotIn(non_rollback, {rel.as_posix() for _, _, rel, _ in self.installer.ROLLBACK})
        self.installer.receipt["preexisting"][non_rollback] = True
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            with self.assertRaisesRegex(a4.A4Error, "A4_RECEIPT_PREEXISTING_MISMATCH"):
                a4.collect_a4(**self.kwargs)

    def test_accepted_receipt_package_identity_passes_before_readback(self):
        with mock.patch.object(a4.socket, "gethostname", return_value="redrix"):
            a4.collect_a4(**self.kwargs)
        self.assertGreaterEqual(self.installer.receipt_reads, 1)
        self.assertGreaterEqual(self.installer.calls, 1)


if __name__ == "__main__":
    unittest.main()
