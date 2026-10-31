#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools" / "dragonfly_gate_a1_transport_identity.py"
PREFLIGHT = ROOT / "tools" / "dragonfly_canary_redrix_preflight.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity = load("gate_a1_transport_identity_test", SOURCE)
bootstrap = load(
    "gate_a3_bootstrap_test",
    ROOT / "tools" / "dragonfly_gate_a3_bootstrap.py",
)


class GateA1TransportIdentityTests(unittest.TestCase):
    def test_derive_matches_redrix_a3_canonicalization(self):
        key_data = "AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey"
        line = f"ssh-ed25519 {key_data} comment"
        expected = hashlib.sha256(f"ssh-ed25519 {key_data}".encode("ascii")).hexdigest()
        self.assertEqual(identity.digest_from_ssh_keygen_y(line), expected)

    def test_substituted_provenance_is_rejected(self):
        digest = "a" * 64
        bad = identity.build_record(digest).replace(identity.PROVENANCE, "PROVENANCE=attacker")
        with self.assertRaisesRegex(identity.TransportIdentityError, "PROVENANCE_INVALID"):
            identity.parse_record(bad)

    def test_cli_derive_from_ssh_keygen_y(self):
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyKey material\n"
        proc = subprocess.run(
            [sys.executable, str(SOURCE), "derive-from-ssh-keygen-y"],
            input=line,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(len(proc.stdout.strip()), 64)

    def test_end_to_end_record_feeds_a3_bootstrap_render(self):
        digest = identity.digest_from_ssh_keygen_y(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture\n"
        )
        with tempfile.TemporaryDirectory() as td:
            record = Path(td) / "gate-a1-transport-identity.record"
            record.write_text(identity.build_record(digest), encoding="utf-8")
            command = bootstrap.render_command(gate_a1_transport_identity_record=record)
            self.assertIn(digest, command)


class GateA3BootstrapRecordTests(unittest.TestCase):
    def test_accepted_preflight_pin_matches_git_blob(self):
        data = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", "HEAD:tools/dragonfly_canary_redrix_preflight.py"],
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(len(data), bootstrap.ACCEPTED_A3_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), bootstrap.ACCEPTED_A3_SHA256)

    def test_bare_digest_cli_is_not_accepted(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/dragonfly_gate_a3_bootstrap.py"), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--gate-a1-transport-identity-record", proc.stdout)
        self.assertNotIn("--expected-transport-key-sha256", proc.stdout)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/dragonfly_gate_a3_bootstrap.py")],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_wrong_record_rejects_render(self):
        with tempfile.TemporaryDirectory() as td:
            record = Path(td) / "bad.record"
            record.write_text(
                "GATE_A1_TRANSPORT_IDENTITY_V1\nPROVENANCE=wrong\nTRANSPORT_PUBLIC_IDENTITY_SHA256="
                + ("c" * 64)
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(bootstrap.BootstrapInputError):
                bootstrap.render_command(gate_a1_transport_identity_record=record)


if __name__ == "__main__":
    unittest.main()
