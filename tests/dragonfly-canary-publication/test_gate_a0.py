#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
A0_PATH = ROOT / "tools" / "dragonfly_gate_a0.py"
BENIGN_PS = "1 init /sbin/init\n2 kthreadd [kthreadd]\n"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a0 = load("test_gate_a0_module", A0_PATH)
installer = load(
    "test_gate_a0_installer", ROOT / "tools" / "dragonfly_canary_redrix_install.py"
)
jit = load("test_gate_a0_jit", ROOT / "dragonfly-jit" / "dragonfly_jit.py")


def git(*args: str, text: bool = True):
    if text:
        return subprocess.check_output(
            ["git", "-C", str(ROOT), *args],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        stderr=subprocess.DEVNULL,
    )


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


class GateA0Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.state = self.root / "state"
        self.data = self.root / "data"
        self.home.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        (self.state / "runs").mkdir(mode=0o700)
        self.data.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.head = str(git("rev-parse", "HEAD"))

        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700)
        auth = ssh / "authorized_keys"
        auth.write_text(
            'restrict,command="/home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py" '
            'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA synthetic\n',
            encoding="utf-8",
        )
        auth.chmod(0o600)

        for source_path, blob, rel, mode in installer.ROLLBACK:
            del source_path
            target = self.home / rel
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(git("cat-file", "blob", blob, text=False))
            target.chmod(mode)

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, **overrides):
        args = {
            "repo": ROOT,
            "expected_head": self.head,
            "home": self.home,
            "uid": self.uid,
            "state_root": self.state,
            "data_root": self.data,
            "hostname": "redrix",
            "expected_local_alias": "redrix",
            "process_output": BENIGN_PS,
        }
        args.update(overrides)
        return a0.collect_a0(**args)

    def write_state(self, state: str, run_id=None, qemu_pid=None):
        payload = {
            "schema": jit.STATE_SCHEMA,
            "marker": jit.MARKER,
            "state": state,
            "updated_at": "2026-10-30T00:00:00+00:00",
            "run_id": run_id,
            "qemu_pid": qemu_pid,
            "reason": None,
        }
        path = self.state / "status.json"
        path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def test_source_surface_is_read_only_and_has_no_remote_or_runtime_action(self):
        text = A0_PATH.read_text(encoding="utf-8")
        forbidden = (
            "install_fixture(",
            "recover_fixture(",
            "rollback_fixture(",
            ".write_state(",
            ".start(",
            ".drain(",
            ".smoke(",
            ".recover(",
            "subprocess.Popen",
            "os.remove(",
            ".unlink(",
            ".mkdir(",
            "os.chmod(",
            "LOCK_EX",
            "gh api",
            "generate-jitconfig",
            "ssh ",
            "ssh.exe",
        )
        for value in forbidden:
            self.assertNotIn(value, text, value)
        self.assertIn("LOCK_SH", text)
        self.assertIn("DRAGONFLY_GATE_A0=PASS", text)
        self.assertIn("EVIDENCE_JSON=", text)

    def test_clean_accepted_115_state_emits_sanitized_evidence_without_mutation(self):
        before = snapshot(self.root)
        evidence = self.collect()
        after = snapshot(self.root)
        self.assertEqual(before, after)
        self.assertEqual(evidence["marker"], a0.MARKER)
        self.assertEqual(evidence["controllerHead"], self.head)
        self.assertEqual(evidence["localHostAlias"], "redrix")
        self.assertEqual(evidence["jitState"], "STOPPED")
        self.assertEqual(evidence["jitStateSource"], "implicit-default")
        self.assertFalse(evidence["statusFilePresent"])
        self.assertFalse(evidence["runIdPresent"])
        self.assertFalse(evidence["qemuPidPresent"])
        self.assertEqual(evidence["runResidueCount"], 0)
        self.assertEqual(evidence["qemuProcessCount"], 0)
        self.assertEqual(evidence["stabilityPasses"], 2)
        self.assertEqual(evidence["transportBaseline"], "accepted-115")
        self.assertTrue(evidence["authorizedKeysInvariant"])
        self.assertFalse(evidence["installTransactionPending"])
        self.assertFalse(evidence["installReceiptPresent"])
        self.assertNotIn("authorizedKeysSha256", evidence)
        self.assertNotIn("tailscaleIp", evidence)
        self.assertRegex(evidence["generatedAt"], r"^\d{4}-\d{2}-\d{2}T")
        stable = dict(evidence)
        digest = stable.pop("snapshotSha256")
        stable.pop("generatedAt")
        self.assertEqual(digest, hashlib.sha256(a0._canonical(stable)).hexdigest())

    def test_file_backed_stopped_is_distinguished_from_implicit_default(self):
        self.write_state("STOPPED")
        evidence = self.collect()
        self.assertTrue(evidence["statusFilePresent"])
        self.assertEqual(evidence["jitStateSource"], "file-backed")

    def test_snapshot_digest_is_reproducible_across_timestamps(self):
        first = self.collect()
        second = self.collect()
        self.assertEqual(first["snapshotSha256"], second["snapshotSha256"])

    def test_lock_file_presence_is_reported_without_mutation(self):
        for path in (self.state / "guest.lock", self.state / "state.lock"):
            path.write_bytes(b"")
            path.chmod(0o600)
        before = snapshot(self.root)
        evidence = self.collect()
        after = snapshot(self.root)
        self.assertEqual(before, after)
        self.assertTrue(evidence["guestLockFilePresent"])
        self.assertTrue(evidence["stateLockFilePresent"])
        self.assertTrue(evidence["guestLockAvailable"])
        self.assertTrue(evidence["stateLockAvailable"])

    def test_wrong_controller_head_refused(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_CONTROLLER_HEAD_MISMATCH"):
            self.collect(expected_head="0" * 40)

    def test_exact_local_alias_is_required(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_LOCAL_HOST_IDENTITY_MISMATCH"):
            self.collect(hostname="penguin", expected_local_alias="redrix")
        with self.assertRaisesRegex(a0.A0Error, "A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID"):
            self.collect(expected_local_alias="some-other-host")

    def test_non_stopped_state_refused(self):
        import uuid

        self.write_state("RUNNING", str(uuid.uuid4()), 12345)
        with self.assertRaisesRegex(a0.A0Error, "A0_JIT_STATE_NOT_STOPPED"):
            self.collect()

    def test_status_symlink_refused(self):
        target = self.root / "outside-status"
        target.write_text("{}\n", encoding="utf-8")
        (self.state / "status.json").symlink_to(target)
        with self.assertRaisesRegex(a0.A0Error, "A0_STATUS_PATH_INVALID"):
            self.collect()

    def test_run_residue_refused(self):
        (self.state / "runs" / "residue").mkdir(mode=0o700)
        with self.assertRaisesRegex(a0.A0Error, "A0_RUN_RESIDUE_PRESENT"):
            self.collect()

    def test_qemu_parser_detects_direct_alias_and_wrapped_processes(self):
        text = "\n".join(
            (
                "100 qemu-system-x86 /usr/bin/qemu-system-x86_64 -m 2048",
                "101 qemu-kvm /usr/bin/qemu-kvm -m 2048",
                "102 sh /bin/sh -c '/usr/bin/qemu-system-aarch64 -m 1024'",
                "103 kvm /usr/bin/kvm -m 1024",
                "104 python3 python3 harmless.py",
            )
        )
        self.assertEqual(a0._qemu_process_ids_from_ps(text), [100, 101, 102, 103])

    def test_qemu_process_refused_via_production_parser(self):
        process_output = "123 qemu-system-x86 /usr/bin/qemu-system-x86_64 -m 2048\n"
        with self.assertRaisesRegex(a0.A0Error, "A0_QEMU_PROCESS_PRESENT"):
            self.collect(process_output=process_output)

    def test_runtime_snapshot_change_refused(self):
        first = {
            "jitState": "STOPPED",
            "jitStateSource": "implicit-default",
            "statusFilePresent": False,
            "runIdPresent": False,
            "qemuPidPresent": False,
            "runResidueCount": 0,
            "qemuProcessCount": 0,
            "guestLockAvailable": True,
            "guestLockFilePresent": False,
            "stateLockAvailable": True,
            "stateLockFilePresent": False,
        }
        second = dict(first)
        second["statusFilePresent"] = True
        second["jitStateSource"] = "file-backed"
        with mock.patch.object(a0, "_runtime_snapshot", side_effect=[first, second]):
            with self.assertRaisesRegex(a0.A0Error, "A0_RUNTIME_SNAPSHOT_CHANGED"):
                self.collect()

    def test_install_transaction_and_receipt_are_refused(self):
        transaction = self.home / installer.TRANSACTION_REL
        transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        transaction.write_text("{}\n", encoding="utf-8")
        transaction.chmod(0o600)
        with self.assertRaisesRegex(a0.A0Error, "A0_INSTALL_TRANSACTION_PRESENT"):
            self.collect()
        transaction.unlink()
        receipt = self.home / installer.RECEIPT_REL
        receipt.write_text("{}\n", encoding="utf-8")
        receipt.chmod(0o600)
        with self.assertRaisesRegex(a0.A0Error, "A0_INSTALL_RECEIPT_PRESENT"):
            self.collect()

    def test_transport_baseline_tamper_refused(self):
        _source, _blob, rel, _mode = installer.ROLLBACK[0]
        target = self.home / rel
        target.write_bytes(b"tampered\n")
        with self.assertRaisesRegex(a0.A0Error, "REDRIX_BASELINE_UNRECOGNIZED"):
            self.collect()

    def test_authorized_key_restriction_refused(self):
        auth = self.home / ".ssh" / "authorized_keys"
        auth.write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA synthetic\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(a0.A0Error, "REDRIX_FORCED_KEY_RESTRICTION_INVALID"):
            self.collect()


if __name__ == "__main__":
    unittest.main()
