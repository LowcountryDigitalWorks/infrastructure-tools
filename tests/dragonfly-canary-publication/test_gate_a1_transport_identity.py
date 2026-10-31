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
            payload = b"fixture-private-key-bytes"
            key_path.write_bytes(payload)
            baseline = hashlib.sha256(payload).hexdigest()
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
                        gate_a1_transport_private_key_baseline_sha256=baseline,
                    )

    def test_bootstrap_bound_digest_in_render(self):
        digest = identity.digest_from_ssh_keygen_y(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture\n"
        )
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "id_ed25519"
            payload = b"fixture-private-key-bytes"
            key_path.write_bytes(payload)
            baseline = hashlib.sha256(payload).hexdigest()
            record = Path(td) / "gate-a1-transport-identity.record"
            record.write_text(identity.build_record(digest), encoding="utf-8")
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                return_value=digest,
            ) as derive_mock:
                command = bootstrap.render_command(
                    gate_a1_transport_private_key=key_path,
                    gate_a1_transport_identity_record=record,
                    gate_a1_transport_private_key_baseline_sha256=baseline,
                )
            derive_mock.assert_called_once_with(
                key_path,
                baseline_sha256=baseline,
            )
            self.assertIn(digest, command)

    def test_bootstrap_render_requires_trusted_record_and_baseline(self):
        digest = identity.digest_from_ssh_keygen_y(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture\n"
        )
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "id_ed25519"
            key_path.write_text("fixture", encoding="utf-8")
            record = Path(td) / "record"
            record.write_text(identity.build_record(digest), encoding="utf-8")
            with self.assertRaisesRegex(bootstrap.BootstrapInputError, "BASELINE_INVALID"):
                bootstrap.render_command(
                    gate_a1_transport_private_key=key_path,
                    gate_a1_transport_identity_record=record,
                    gate_a1_transport_private_key_baseline_sha256="not-a-digest",
                )
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                side_effect=identity.TransportIdentityError("GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED"),
            ):
                with self.assertRaisesRegex(
                    bootstrap.BootstrapInputError,
                    "GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED",
                ):
                    bootstrap.render_command(
                        gate_a1_transport_private_key=key_path,
                        gate_a1_transport_identity_record=record,
                        gate_a1_transport_private_key_baseline_sha256="a" * 64,
                    )

    def test_bootstrap_cli_requires_record_and_baseline(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/dragonfly_gate_a3_bootstrap.py"),
                "--gate-a1-transport-private-key",
                "C:\\fake\\id_ed25519",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--gate-a1-transport-identity-record", proc.stderr + proc.stdout)
        self.assertIn("--gate-a1-transport-private-key-baseline-sha256", proc.stderr + proc.stdout)

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
            for path in temp_dir.glob("ldw-gate-a1-key-*"):
                if sys.platform == "win32":
                    if not path.exists():
                        continue
                    data = path.read_bytes()
                    self.assertNotIn(payload, data)
                    if data:
                        self.assertEqual(data, b"\0" * len(data))
                else:
                    self.fail(f"unexpected temp key residue: {path}")
            with self.assertRaisesRegex(identity.TransportIdentityError, "GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED"):
                identity.derive_public_identity_from_accepted_bytes(
                    payload,
                    ssh_keygen=keygen,
                    temp_dir=temp_dir,
                    baseline_sha256="ab" * 32,
                )
            for path in temp_dir.glob("ldw-gate-a1-key-*"):
                if sys.platform == "win32":
                    if not path.exists():
                        continue
                    data = path.read_bytes()
                    self.assertNotIn(payload, data)
                    if data:
                        self.assertEqual(data, b"\0" * len(data))
                else:
                    self.fail(f"unexpected temp key residue: {path}")

    def test_temp_key_cleanup_failure_hold(self):
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = b"synthetic-private-key-bytes"
            keygen = root / "ssh-keygen.cmd" if sys.platform == "win32" else root / "ssh-keygen"
            if sys.platform == "win32":
                keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            else:
                keygen.write_text(f"#!/bin/sh\nprintf '%s\\n' '{line}'\n", encoding="utf-8")
                keygen.chmod(0o755)
            temp_dir = root / "out"
            if sys.platform == "win32":
                patcher = mock.patch.object(identity, "_FlushFileBuffers", return_value=False)
            else:
                patcher = mock.patch.object(
                    identity,
                    "_remove_temp_key_pathname",
                    side_effect=identity.TransportIdentityError("GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED"),
                )
            with patcher:
                with self.assertRaisesRegex(
                    identity.TransportIdentityError,
                    "GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED",
                ):
                    identity.derive_public_identity_from_accepted_bytes(
                        payload,
                        ssh_keygen=keygen,
                        temp_dir=temp_dir,
                        baseline_sha256=hashlib.sha256(payload).hexdigest(),
                    )

    def test_temp_key_replacement_during_ssh_keygen_blocked(self):
        if sys.platform != "win32":
            self.skipTest("Windows exclusive temp-key handle binding")
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        expected = identity.digest_from_ssh_keygen_y(line + "\n")
        payload = b"synthetic-private-key-bytes"
        evil = b"evil-replacement-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            attack_log = root / "attack.txt"
            keygen = root / "fake_keygen.py"
            keygen.write_text(
                """
import sys
import time
import threading
from pathlib import Path

key_path = Path(sys.argv[sys.argv.index("-f") + 1])
attack_log = Path(r"%s")
line = r"%s"

def attack() -> None:
    time.sleep(0.15)
    errors = []
    try:
        key_path.write_bytes(%r)
    except OSError as exc:
        errors.append("write:" + str(exc))
    try:
        key_path.unlink()
    except OSError as exc:
        errors.append("unlink:" + str(exc))
    attack_log.write_text("\\n".join(errors) if errors else "no-error", encoding="utf-8")

threading.Thread(target=attack, daemon=True).start()
time.sleep(0.45)
data = key_path.read_bytes()
if data == %r:
    print(line)
else:
    raise SystemExit(3)
"""
                % (str(attack_log), line, evil, payload),
                encoding="utf-8",
            )
            wrapper = root / "ssh-keygen.cmd"
            wrapper.write_text(f'@"{sys.executable}" "{keygen}" %*\r\n', encoding="ascii")
            temp_dir = root / "out"
            digest = identity.derive_public_identity_from_accepted_bytes(
                payload,
                ssh_keygen=wrapper,
                temp_dir=temp_dir,
                baseline_sha256=hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(digest, expected)
            self.assertTrue(attack_log.exists(), "attack thread should run during consumption")
            self.assertNotEqual(attack_log.read_text(encoding="utf-8"), "no-error")
            for path in temp_dir.glob("ldw-gate-a1-key-*"):
                if path.exists():
                    self.fail(f"unexpected temp key pathname residue: {path}")

    def test_temp_key_cleanup_pathname_hardlink_after_bound_destroy(self):
        if sys.platform != "win32":
            self.skipTest("Windows bound-handle cleanup pathname substitution")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        expected = identity.digest_from_ssh_keygen_y(line + "\n")
        payload = b"synthetic-private-key-bytes"
        fixture_bytes = b"UNRELATED-FIXTURE-BYTES-KEEP-INTACT"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "fixture.bin"
            fixture.write_bytes(fixture_bytes)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            moved_aside: dict[str, Path] = {}
            real_delete = identity._delete_temp_key_path_if_same_object

            def delete_with_pathname_substitution(
                path: Path,
                expected_identity: tuple[int, int, int],
            ) -> None:
                candidates = [
                    p
                    for p in temp_dir.glob("ldw-gate-a1-key-*")
                    if ".moved-aside" not in p.name and p.exists()
                ]
                if candidates:
                    target = candidates[0]
                    moved = target.with_name(target.name + ".moved-aside")
                    try:
                        if target.exists():
                            os.replace(target, moved)
                            moved_aside["path"] = moved
                        os.link(fixture, target)
                    except OSError:
                        pass
                real_delete(path, expected_identity)

            with mock.patch.object(
                identity,
                "_delete_temp_key_path_if_same_object",
                side_effect=delete_with_pathname_substitution,
            ):
                with self.assertRaisesRegex(
                    identity.TransportIdentityError,
                    "GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED",
                ):
                    identity.derive_public_identity_from_accepted_bytes(
                        payload,
                        ssh_keygen=keygen,
                        temp_dir=temp_dir,
                        baseline_sha256=hashlib.sha256(payload).hexdigest(),
                    )
            self.assertEqual(fixture.read_bytes(), fixture_bytes)
            moved = moved_aside.get("path")
            if moved is not None and moved.exists():
                self.assertNotIn(payload, moved.read_bytes())


    def test_blind_pathname_unlink_would_destroy_substitute_fixture(self):
        if sys.platform != "win32":
            self.skipTest("Windows verified-delete collateral regression")
        import os

        fixture_bytes = b"UNRELATED-FIXTURE-MUST-SURVIVE"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "fixture.bin"
            fixture.write_bytes(fixture_bytes)
            temp_dir = root / "out"
            temp_dir.mkdir()
            key_path = identity._new_exclusive_temp_key_path(temp_dir)
            handle = identity._create_bound_temp_key_handle(key_path, b"synthetic-private-key-bytes")
            bound = identity._bound_file_identity(handle)
            identity._CloseHandle(handle)
            os.replace(key_path, key_path.with_name(key_path.name + ".moved-aside"))
            os.link(fixture, key_path)
            with self.assertRaisesRegex(identity.TransportIdentityError, "TEMP_CLEANUP_FAILED"):
                identity._delete_temp_key_path_if_same_object(key_path, bound)
            self.assertEqual(fixture.read_bytes(), fixture_bytes)
            self.assertTrue(fixture.exists())

    def test_temp_key_cleanup_single_link_pathname_replacement_holds(self):
        if sys.platform != "win32":
            self.skipTest("Windows verified-delete single-link pathname substitution")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        payload = b"synthetic-private-key-bytes"
        victim_bytes = b"SINGLE-LINK-VICTIM-MUST-NOT-BE-DELETED"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            moved_aside: dict[str, Path] = {}
            real_delete = identity._delete_temp_key_path_if_same_object

            def delete_with_single_link_replacement(
                path: Path,
                expected_identity: tuple[int, int, int],
            ) -> None:
                victim_src = path.parent / "victim-single-link.bin"
                victim_src.write_bytes(victim_bytes)
                if path.exists():
                    moved = path.with_name(path.name + ".moved-aside")
                    os.replace(path, moved)
                    moved_aside["path"] = moved
                os.replace(victim_src, path)
                real_delete(path, expected_identity)

            with mock.patch.object(
                identity,
                "_delete_temp_key_path_if_same_object",
                side_effect=delete_with_single_link_replacement,
            ):
                with self.assertRaisesRegex(
                    identity.TransportIdentityError,
                    "GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED",
                ):
                    identity.derive_public_identity_from_accepted_bytes(
                        payload,
                        ssh_keygen=keygen,
                        temp_dir=temp_dir,
                        baseline_sha256=hashlib.sha256(payload).hexdigest(),
                    )
            victims = [
                p
                for p in temp_dir.glob("ldw-gate-a1-key-*")
                if ".moved-aside" not in p.name and p.is_file()
            ]
            self.assertEqual(len(victims), 1)
            self.assertEqual(victims[0].read_bytes(), victim_bytes)
            moved = moved_aside.get("path")
            if moved is not None and moved.exists():
                self.assertNotIn(payload, moved.read_bytes())

    def test_temp_key_cleanup_parent_directory_substitution_holds(self):
        if sys.platform != "win32":
            self.skipTest("Windows verified-delete parent-directory substitution")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        payload = b"synthetic-private-key-bytes"
        victim_bytes = b"PARENT-DIR-VICTIM-MUST-SURVIVE"
        captured_key_name: dict[str, str] = {}
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            real_delete = identity._delete_temp_key_path_if_same_object

            def delete_with_parent_directory_substitution(
                path: Path,
                expected_identity: tuple[int, int, int],
            ) -> None:
                captured_key_name["name"] = path.name
                parent = path.parent
                aside = parent.with_name(parent.name + ".aside")
                os.replace(parent, aside)
                parent.mkdir()
                (parent / path.name).write_bytes(victim_bytes)
                real_delete(path, expected_identity)

            with mock.patch.object(
                identity,
                "_delete_temp_key_path_if_same_object",
                side_effect=delete_with_parent_directory_substitution,
            ):
                with self.assertRaisesRegex(
                    identity.TransportIdentityError,
                    "GATE_A1_TRANSPORT_TEMP_CLEANUP_FAILED",
                ):
                    identity.derive_public_identity_from_accepted_bytes(
                        payload,
                        ssh_keygen=keygen,
                        temp_dir=temp_dir,
                        baseline_sha256=hashlib.sha256(payload).hexdigest(),
                    )
            name = captured_key_name.get("name")
            self.assertIsNotNone(name)
            victim_path = temp_dir / name
            self.assertTrue(victim_path.is_file())
            self.assertEqual(victim_path.read_bytes(), victim_bytes)
            aside = temp_dir.with_name(temp_dir.name + ".aside")
            if aside.is_dir():
                for path in aside.glob("ldw-gate-a1-key-*"):
                    if path.exists():
                        self.assertNotIn(payload, path.read_bytes())

    def test_windows_system_ssh_keygen_ephemeral_ed25519_derive_and_cleanup(self):
        """Hosted Windows: real System32 ssh-keygen against bound temp handle (FILE_SHARE_READ only)."""
        if sys.platform != "win32":
            self.skipTest("System32 OpenSSH integration requires Windows")
        system_keygen = identity.resolve_trusted_ssh_keygen_path()
        if not system_keygen.is_file():
            self.fail(
                "GATE_A1_SYSTEM_SSH_KEYGEN_MISSING: "
                f"trusted path not present: {system_keygen}"
            )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            gen_stem = root / "ephemeral-ed25519"
            gen_proc = subprocess.run(
                [
                    str(system_keygen),
                    "-t",
                    "ed25519",
                    "-f",
                    str(gen_stem),
                    "-N",
                    "",
                    "-q",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if gen_proc.returncode != 0:
                self.fail(
                    "GATE_A1_EPHEMERAL_KEYGEN_FAILED: "
                    f"rc={gen_proc.returncode} stderr={gen_proc.stderr!r}"
                )
            private_key_path = Path(f"{gen_stem}")
            pub_path = Path(f"{gen_stem}.pub")
            self.assertTrue(private_key_path.is_file(), "expected OpenSSH private key file")
            private_bytes = private_key_path.read_bytes()
            baseline = hashlib.sha256(private_bytes).hexdigest()
            y_proc = subprocess.run(
                [str(system_keygen), "-y", "-P", "", "-f", str(private_key_path)],
                capture_output=True,
                timeout=30,
                check=False,
            )
            if y_proc.returncode != 0 or not y_proc.stdout.strip():
                self.fail(
                    "GATE_A1_EPHEMERAL_KEYGEN_Y_FAILED: "
                    f"rc={y_proc.returncode} stderr={y_proc.stderr!r}"
                )
            expected_digest = identity.digest_from_ssh_keygen_y(
                y_proc.stdout.decode("ascii", errors="strict")
            )
            private_key_path.unlink(missing_ok=True)
            pub_path.unlink(missing_ok=True)
            self.assertFalse(private_key_path.exists())
            temp_dir = root / "derive-out"
            digest = identity.derive_public_identity_from_accepted_bytes(
                private_bytes,
                ssh_keygen=system_keygen,
                temp_dir=temp_dir,
                baseline_sha256=baseline,
            )
            self.assertEqual(digest, expected_digest)
            for path in temp_dir.glob("ldw-gate-a1-key-*"):
                if path.exists():
                    residue = path.read_bytes()
                    self.assertNotIn(private_bytes, residue)
                    if residue:
                        self.assertEqual(residue, b"\0" * len(residue))
                    self.fail(f"unexpected temp key pathname after cleanup: {path}")

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
        self.assertIn("--gate-a1-transport-identity-record", proc.stdout)
        self.assertIn("--gate-a1-transport-private-key-baseline-sha256", proc.stdout)
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
            baseline = "f" * 64
            with mock.patch.object(
                bootstrap,
                "derive_bound_transport_public_identity",
                return_value=digest,
            ):
                with self.assertRaises(bootstrap.BootstrapInputError):
                    bootstrap.render_command(
                        gate_a1_transport_private_key=key_path,
                        gate_a1_transport_identity_record=record,
                        gate_a1_transport_private_key_baseline_sha256=baseline,
                    )


if __name__ == "__main__":
    unittest.main()
