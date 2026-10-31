#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_write_record_digest_cli_removed(self):
        proc = subprocess.run(
            [sys.executable, str(SOURCE), "write-record", "--help"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_derive_bound_requires_windows(self):
        if sys.platform == "win32":
            self.skipTest("bound derive integration requires synthetic key on Windows")
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("not-a-key")
            path = Path(handle.name)
        try:
            with self.assertRaisesRegex(identity.TransportIdentityError, "WINDOWS_REQUIRED"):
                identity.derive_bound_transport_public_identity(path)
        finally:
            path.unlink(missing_ok=True)

    def test_bootstrap_record_replacement_rejected(self):
        digest = identity.digest_from_ssh_keygen_y(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture\n"
        )
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "id_ed25519"
            key_path.write_text("fixture-private-key-bytes", encoding="utf-8")
            record = Path(td) / "gate-a1-transport-identity.record"
            record.write_text(identity.build_record("b" * 64), encoding="utf-8")
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                return_value=digest,
            ):
                with self.assertRaisesRegex(
                    bootstrap.BootstrapInputError,
                    "GATE_A1_TRANSPORT_IDENTITY_RECORD_MISMATCH",
                ):
                    bootstrap.render_command(
                        gate_a1_transport_private_key=key_path,
                        gate_a1_transport_identity_record=record,
                    )

    def test_bootstrap_bound_digest_in_render(self):
        digest = identity.digest_from_ssh_keygen_y(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture\n"
        )
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "id_ed25519"
            key_path.write_text("fixture-private-key-bytes", encoding="utf-8")
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                return_value=digest,
            ):
                command = bootstrap.render_command(gate_a1_transport_private_key=key_path)
            self.assertIn(digest, command)

    def test_path_substitution_uses_trusted_ssh_keygen_only(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("GetSystemDirectoryW", source)
        self.assertIn('system_directory / "OpenSSH" / "ssh-keygen.exe"', source)
        self.assertNotIn("Get-Command", source)
        self.assertNotIn("shutil.which", source)
        operator = (ROOT / "ci-dispatch/Invoke-DragonflyGateA1.ps1").read_text(encoding="utf-8")
        self.assertIn("derive-bound", operator)
        self.assertNotIn("Get-Command ssh-keygen", operator)
        self.assertNotIn("WINDIR", SOURCE.read_text(encoding="utf-8"))
        self.assertIn("GetSystemDirectoryW", SOURCE.read_text(encoding="utf-8"))
        self.assertIn("[Environment]::SystemDirectory", operator)

    def test_ssh_keygen_consumes_accepted_byte_snapshot_not_live_path(self):
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        expected = identity.digest_from_ssh_keygen_y(line + "\n")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            live = root / "id_ed25519"
            payload = b"synthetic-private-key-bytes"
            live.write_bytes(payload)
            marker = root / "argv.txt"
            if sys.platform == "win32":
                keygen = root / "ssh-keygen.cmd"
                keygen.write_text(
                    "@echo off\r\n"
                    f'echo %* > "{marker}"\r\n'
                    f"echo {line}\r\n",
                    encoding="ascii",
                )
            else:
                keygen = root / "ssh-keygen"
                keygen.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' \"$@\" > '{marker}'\n"
                    f"printf '%s\\n' '{line}'\n",
                    encoding="utf-8",
                )
                keygen.chmod(0o755)
            temp_dir = root / "out"
            digest = identity.derive_public_identity_from_accepted_bytes(
                payload,
                ssh_keygen=keygen,
                temp_dir=temp_dir,
                baseline_sha256=hashlib.sha256(payload).hexdigest(),
            )
            argv = marker.read_text(encoding="utf-8", errors="replace")
            self.assertEqual(digest, expected)
            self.assertIn("-P", argv)
            self.assertIn("-f", argv)
            self.assertNotIn(str(live), argv)
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])
            with self.assertRaisesRegex(identity.TransportIdentityError, "GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED"):
                identity.derive_public_identity_from_accepted_bytes(
                    payload,
                    ssh_keygen=keygen,
                    temp_dir=temp_dir,
                    baseline_sha256="ab" * 32,
                )
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])


class GateA3BootstrapRecordTests(unittest.TestCase):
    def test_accepted_preflight_pin_matches_git_blob(self):
        data = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{bootstrap.ACCEPTED_A3_COMMIT}:tools/dragonfly_canary_redrix_preflight.py"],
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(len(data), bootstrap.ACCEPTED_A3_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), bootstrap.ACCEPTED_A3_SHA256)

    def test_accepted_installer_pin_matches_git_blob(self):
        data = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{bootstrap.ACCEPTED_INSTALLER_COMMIT}:tools/dragonfly_canary_redrix_install.py"],
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(len(data), bootstrap.ACCEPTED_INSTALLER_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), bootstrap.ACCEPTED_INSTALLER_SHA256)

    def test_bootstrap_embeds_dual_source_pins(self):
        digest = "d" * 64
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256=bootstrap.ACCEPTED_A3_SHA256,
            exact_bytes=bootstrap.ACCEPTED_A3_BYTES,
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=bootstrap.ACCEPTED_INSTALLER_SHA256,
            installer_exact_bytes=bootstrap.ACCEPTED_INSTALLER_BYTES,
            transport_key_sha256=digest,
        )
        self.assertIn(bootstrap.ACCEPTED_A3_SHA256, code)
        self.assertIn(bootstrap.ACCEPTED_INSTALLER_SHA256, code)
        self.assertIn("__LDW_VERIFIED_INSTALLER_BYTES__", code)
        self.assertIn("fetch_pinned", code)
        self.assertIn("ProxyHandler({})", code)
        self.assertIn("A3_SOURCE_REDIRECT_REFUSED", code)

    def test_render_cli_requires_private_key(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/dragonfly_gate_a3_bootstrap.py"), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--gate-a1-transport-private-key", proc.stdout)
        self.assertNotIn("--expected-transport-key-sha256", proc.stdout)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/dragonfly_gate_a3_bootstrap.py")],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_wrong_record_provenance_rejects_render(self):
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "id_ed25519"
            key_path.write_text("fixture", encoding="utf-8")
            record = Path(td) / "bad.record"
            record.write_text(
                "GATE_A1_TRANSPORT_IDENTITY_V1\nPROVENANCE=wrong\nTRANSPORT_PUBLIC_IDENTITY_SHA256="
                + ("c" * 64)
                + "\n",
                encoding="utf-8",
            )
            digest = "d" * 64
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                return_value=digest,
            ):
                with self.assertRaises(bootstrap.BootstrapInputError):
                    bootstrap.render_command(
                        gate_a1_transport_private_key=key_path,
                        gate_a1_transport_identity_record=record,
                    )


if __name__ == "__main__":
    unittest.main()
