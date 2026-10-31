#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


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
    CURRENT = tuple(range(7))

    def __init__(self):
        self.result = {
            "sourceCommit": self.SOURCE_COMMIT,
            "sourceTree": self.SOURCE_TREE,
            "authorizedKeysInvariant": True,
            "transactionPending": False,
            "rollbackBaseline": "accepted-115",
            "files": len(self.CURRENT),
        }
        self.calls = 0

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
            "expected_transport_key_sha256": "a" * 64,
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
        self.assertTrue(result["rollbackRetained"])
        self.assertTrue(result["installReceiptValidated"])
        self.assertEqual(result["jitState"], "STOPPED")
        self.assertEqual(result["transportKeyIdentity"], "expected")
        self.assertEqual(result["stabilityPasses"], 2)
        self.assertRegex(result["snapshotSha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(self.installer.calls, 2)
        self.assertNotIn("expectedTransportKeySha256", result)
        self.assertNotIn("expectedHostFingerprint", result)

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

    def test_pinned_dependency_blobs_match_accepted_sources(self):
        installer = ROOT / "tools" / "dragonfly_canary_redrix_install.py"
        a0_source = ROOT / "tools" / "dragonfly_gate_a0.py"
        self.assertEqual(git_blob(installer.read_bytes()), a4.INSTALLER_BLOB)
        self.assertEqual(git_blob(a0_source.read_bytes()), a4.A0_BLOB)

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


if __name__ == "__main__":
    unittest.main()
