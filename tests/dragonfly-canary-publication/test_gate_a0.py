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

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a0 = load("test_gate_a0_module", ROOT / "tools" / "dragonfly_gate_a0.py")
installer = load(
    "test_gate_a0_installer", ROOT / "tools" / "dragonfly_canary_redrix_install.py"
)
jit = load("test_gate_a0_jit", ROOT / "dragonfly-jit" / "dragonfly_jit.py")


def git(*args: str, text: bool = True):
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args],
        text=text,
        stderr=subprocess.DEVNULL,
    ).strip() if text else subprocess.check_output(
        ["git", "-C", str(ROOT), *args], stderr=subprocess.DEVNULL
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
            "qemu_pids": [],
        }
        args.update(overrides)
        return a0.collect_a0(**args)

    def test_clean_accepted_115_state_emits_sanitized_evidence_without_mutation(self):
        before = snapshot(self.root)
        evidence = self.collect()
        after = snapshot(self.root)
        self.assertEqual(before, after)
        self.assertEqual(evidence["marker"], a0.MARKER)
        self.assertEqual(evidence["controllerHead"], self.head)
        self.assertEqual(evidence["jitState"], "STOPPED")
        self.assertFalse(evidence["runIdPresent"])
        self.assertFalse(evidence["qemuPidPresent"])
        self.assertEqual(evidence["runResidueCount"], 0)
        self.assertEqual(evidence["qemuProcessCount"], 0)
        self.assertEqual(evidence["transportBaseline"], "accepted-115")
        self.assertTrue(evidence["authorizedKeysInvariant"])
        self.assertFalse(evidence["installTransactionPending"])
        self.assertFalse(evidence["installReceiptPresent"])
        digest = evidence.pop("evidenceSha256")
        self.assertEqual(digest, hashlib.sha256(a0._canonical(evidence)).hexdigest())

    def test_wrong_controller_head_refused(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_CONTROLLER_HEAD_MISMATCH"):
            self.collect(expected_head="0" * 40)

    def test_wrong_local_host_refused(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_LOCAL_HOST_IDENTITY_REFUSED"):
            self.collect(hostname="some-other-host")

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
        (self.state / "status.json").write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (self.state / "status.json").chmod(0o600)

    def test_non_stopped_state_refused(self):
        import uuid

        self.write_state("RUNNING", str(uuid.uuid4()), 12345)
        with self.assertRaisesRegex(a0.A0Error, "A0_JIT_STATE_NOT_STOPPED"):
            self.collect()

    def test_run_residue_refused(self):
        (self.state / "runs" / "residue").mkdir(mode=0o700)
        with self.assertRaisesRegex(a0.A0Error, "A0_RUN_RESIDUE_PRESENT"):
            self.collect()

    def test_qemu_process_refused(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_QEMU_PROCESS_PRESENT"):
            self.collect(qemu_pids=[12345])

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
