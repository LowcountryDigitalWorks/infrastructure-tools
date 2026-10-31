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
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])
            with self.assertRaisesRegex(identity.TransportIdentityError, "GATE_A1_TRANSPORT_PRIVATE_KEY_CHANGED"):
                identity.derive_public_identity_from_accepted_bytes(
                    payload,
                    ssh_keygen=keygen,
                    temp_dir=temp_dir,
                    baseline_sha256="ab" * 32,
                )
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])

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
    try:
        renamed = key_path.parent.with_name(key_path.parent.name + "-attack-rename")
        key_path.parent.rename(renamed)
    except OSError as exc:
        errors.append("rename:" + str(exc))
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
            attack_text = attack_log.read_text(encoding="utf-8")
            self.assertNotEqual(attack_text, "no-error")
            self.assertIn("write:", attack_text)
            self.assertIn("unlink:", attack_text)
            self.assertIn("rename:", attack_text)
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])

    def test_temp_key_cleanup_pathname_hardlink_after_bound_destroy(self):
        if sys.platform != "win32":
            self.skipTest("Windows bound-handle cleanup pathname substitution")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
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
            real_close = identity._CloseHandle
            state = {"done": False}

            def close_then_hardlink_swap(handle: int) -> bool:
                result = real_close(handle)
                if result and not state["done"]:
                    state["done"] = True
                    candidates = [
                        p
                        for p in temp_dir.glob("ldw-gate-a1-key-*")
                        if ".moved-aside" not in p.name and p.is_file()
                    ]
                    self.assertEqual(len(candidates), 1)
                    path = candidates[0]
                    moved = path.with_name(path.name + ".moved-aside")
                    os.replace(path, moved)
                    moved_aside["path"] = moved
                    os.link(fixture, path)
                return bool(result)

            disposition = mock.Mock(wraps=identity._SetFileInformationByHandle)
            with mock.patch.object(identity, "_CloseHandle", side_effect=close_then_hardlink_swap):
                with mock.patch.object(identity, "_SetFileInformationByHandle", disposition):
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
            self.assertFalse(disposition.called)
            self.assertEqual(fixture.read_bytes(), fixture_bytes)
            moved = moved_aside["path"]
            self.assertTrue(moved.is_file())
            self.assertEqual(moved.read_bytes(), b"")
            self.assertNotIn(payload, moved.read_bytes())
            linked = [
                p for p in temp_dir.glob("ldw-gate-a1-key-*") if ".moved-aside" not in p.name
            ]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0].read_bytes(), fixture_bytes)


    def test_explicit_temp_dir_cleanup_removes_key_file(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        expected = identity.digest_from_ssh_keygen_y(line + "\n")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            digest = identity.derive_public_identity_from_accepted_bytes(
                payload,
                ssh_keygen=keygen,
                temp_dir=temp_dir,
                baseline_sha256=hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(digest, expected)
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])

    def test_derive_bound_internal_temp_no_residue(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        expected = identity.digest_from_ssh_keygen_y(line + "\n")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory(prefix="ldw-gate-a1-parent-") as parent_name:
            parent = Path(parent_name)
            created: list[Path] = []
            real_mkdtemp = identity.tempfile.mkdtemp

            def capture_mkdtemp(*args, **kwargs):
                kwargs["dir"] = str(parent)
                path = real_mkdtemp(*args, **kwargs)
                created.append(Path(path))
                return path

            keygen = parent / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            with mock.patch.object(identity.tempfile, "mkdtemp", side_effect=capture_mkdtemp):
                digest = identity.derive_bound_transport_public_identity(
                    Path("unused"),
                    accepted_bytes=payload,
                    ssh_keygen=keygen,
                    temp_dir=None,
                    baseline_sha256=hashlib.sha256(payload).hexdigest(),
                )
            self.assertEqual(digest, expected)
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].exists())
            self.assertEqual(list(parent.glob("ldw-gate-a1-*")), [])

    def test_single_link_victim_swap_holds(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        payload = b"synthetic-private-key-bytes"
        victim_bytes = b"UNRELATED-SINGLE-LINK-VICTIM"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            moved_aside: dict[str, Path] = {}
            real_close = identity._CloseHandle
            state = {"done": False}

            def close_then_swap(handle: int) -> bool:
                result = real_close(handle)
                if result and not state["done"]:
                    state["done"] = True
                    candidates = [
                        p
                        for p in temp_dir.glob("ldw-gate-a1-key-*")
                        if ".moved-aside" not in p.name and p.is_file()
                    ]
                    self.assertEqual(len(candidates), 1)
                    path = candidates[0]
                    moved = path.with_name(path.name + ".moved-aside")
                    os.replace(path, moved)
                    moved_aside["path"] = moved
                    path.write_bytes(victim_bytes)
                return bool(result)

            with mock.patch.object(identity, "_CloseHandle", side_effect=close_then_swap):
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
            victim = moved_aside["path"].with_name(moved_aside["path"].name.removesuffix(".moved-aside"))
            self.assertEqual(victim.read_bytes(), victim_bytes)
            moved = moved_aside["path"]
            self.assertEqual(moved.stat().st_size, 0)
            self.assertEqual(moved.read_bytes(), b"")
            self.assertNotIn(payload, moved.read_bytes())

    def test_parent_directory_substitution_holds(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        payload = b"synthetic-private-key-bytes"
        victim_bytes = b"UNRELATED-PARENT-DIR-VICTIM"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            real_close = identity._CloseHandle
            state = {"done": False, "moved": None, "victim": None}

            def close_then_replace_parent(handle: int) -> bool:
                result = real_close(handle)
                if result and not state["done"]:
                    state["done"] = True
                    keys = [p for p in temp_dir.glob("ldw-gate-a1-key-*") if p.is_file()]
                    self.assertEqual(len(keys), 1)
                    moved_dir = temp_dir.with_name(temp_dir.name + "-original")
                    os.replace(temp_dir, moved_dir)
                    temp_dir.mkdir()
                    state["moved"] = moved_dir / keys[0].name
                    victim = temp_dir / keys[0].name
                    victim.write_bytes(victim_bytes)
                    state["victim"] = victim
                return bool(result)

            with mock.patch.object(identity, "_CloseHandle", side_effect=close_then_replace_parent):
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
            victim = state["victim"]
            self.assertIsNotNone(victim)
            self.assertEqual(victim.read_bytes(), victim_bytes)
            moved = state["moved"]
            self.assertEqual(moved.stat().st_size, 0)
            self.assertEqual(moved.read_bytes(), b"")
            self.assertNotIn(payload, moved.read_bytes())

    def test_reparse_identity_mismatch_does_not_delete(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        import os

        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        payload = b"synthetic-private-key-bytes"
        fixture_bytes = b"UNRELATED-REPARSE-TARGET"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "reparse-target"
            target.mkdir()
            kept = target / "keep.bin"
            kept.write_bytes(fixture_bytes)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
            temp_dir = root / "out"
            real_close = identity._CloseHandle
            state = {"done": False, "link": None, "moved": None}

            def close_then_reparse(handle: int) -> bool:
                result = real_close(handle)
                if result and not state["done"]:
                    state["done"] = True
                    keys = [p for p in temp_dir.glob("ldw-gate-a1-key-*") if p.is_file()]
                    self.assertEqual(len(keys), 1)
                    path = keys[0]
                    moved = path.with_name(path.name + ".moved-aside")
                    os.replace(path, moved)
                    state["moved"] = moved
                    subprocess.check_call(
                        ["cmd", "/c", "mklink", "/J", str(path), str(target)],
                        stdout=subprocess.DEVNULL,
                    )
                    state["link"] = path
                return bool(result)

            disposition = mock.Mock(wraps=identity._SetFileInformationByHandle)
            with mock.patch.object(identity, "_CloseHandle", side_effect=close_then_reparse):
                with mock.patch.object(identity, "_SetFileInformationByHandle", disposition):
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
            self.assertFalse(disposition.called)
            self.assertEqual(kept.read_bytes(), fixture_bytes)
            self.assertTrue(state["link"].is_dir())
            self.assertEqual(state["moved"].read_bytes(), b"")
            self.assertNotIn(payload, state["moved"].read_bytes())

        real_metadata = identity._by_handle_metadata
        calls = {"n": 0}

        def report_reparse(handle: int, *, failure: str):
            calls["n"] += 1
            metadata = real_metadata(handle, failure=failure)
            if calls["n"] == 3:
                metadata.reparse = True
            return metadata

        flag_disposition = mock.Mock(wraps=identity._SetFileInformationByHandle)
        with mock.patch.object(identity, "_by_handle_metadata", side_effect=report_reparse):
            with mock.patch.object(identity, "_SetFileInformationByHandle", flag_disposition):
                self._assert_cleanup_fault_leaves_truncated_original(None)
        self.assertGreaterEqual(calls["n"], 3)
        self.assertFalse(flag_disposition.called)

    def test_cleanup_disposition_fault_hold(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        self._assert_cleanup_fault_leaves_truncated_original(
            mock.patch.object(identity, "_SetFileInformationByHandle", return_value=False)
        )

    def test_cleanup_reopen_fault_hold(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        import ctypes

        real_create = identity._CreateFileW

        def fail_cleanup_open(*args, **kwargs):
            access = args[1] if len(args) > 1 else kwargs.get("dwDesiredAccess")
            if int(access) & identity._DELETE_ACCESS:
                return ctypes.c_void_p(-1).value
            return real_create(*args, **kwargs)

        self._assert_cleanup_fault_leaves_truncated_original(
            mock.patch.object(identity, "_CreateFileW", side_effect=fail_cleanup_open)
        )

    def test_cleanup_identity_fault_hold(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        real_metadata = identity._by_handle_metadata
        calls = {"n": 0}

        def mismatch_on_cleanup_handle(handle: int, *, failure: str):
            calls["n"] += 1
            metadata = real_metadata(handle, failure=failure)
            if calls["n"] == 3:
                metadata.file_index ^= 1
            return metadata

        disposition = mock.Mock(wraps=identity._SetFileInformationByHandle)
        with mock.patch.object(identity, "_by_handle_metadata", side_effect=mismatch_on_cleanup_handle):
            with mock.patch.object(identity, "_SetFileInformationByHandle", disposition):
                self._assert_cleanup_fault_leaves_truncated_original(None)
        self.assertGreaterEqual(calls["n"], 3)
        self.assertFalse(disposition.called)

    def test_cleanup_truncate_fault_hold(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = self._echo_keygen(root)
            temp_dir = root / "out"
            with mock.patch.object(identity, "_SetEndOfFile", return_value=False):
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
            residue = list(temp_dir.glob("ldw-gate-a1-key-*"))
            self.assertEqual(len(residue), 1)
            data = residue[0].read_bytes()
            self.assertNotIn(payload, data)
            self.assertEqual(data, b"\0" * len(payload))

    def test_cleanup_close_fault_hold(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        real_close = identity._CloseHandle
        calls = {"n": 0}

        def fail_original_close(handle: int) -> bool:
            calls["n"] += 1
            result = real_close(handle)
            if calls["n"] == 1:
                return False
            return bool(result)

        disposition = mock.Mock(wraps=identity._SetFileInformationByHandle)
        with mock.patch.object(identity, "_CloseHandle", side_effect=fail_original_close):
            with mock.patch.object(identity, "_SetFileInformationByHandle", disposition):
                self._assert_cleanup_fault_leaves_truncated_original(None)
        self.assertFalse(disposition.called)

    def test_cleanup_pathname_still_present_holds(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unrelated = root / "unrelated.bin"
            unrelated.write_bytes(b"keep-unrelated")
            keygen = self._echo_keygen(root)
            temp_dir = root / "out"
            with mock.patch.object(identity, "_temp_pathname_present", return_value=True):
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
            self.assertEqual(unrelated.read_bytes(), b"keep-unrelated")
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])

    def test_derivation_failure_preserved_when_cleanup_completes(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")
            temp_dir = root / "out"
            with self.assertRaisesRegex(
                identity.TransportIdentityError,
                "GATE_A1_TRANSPORT_PUBLIC_IDENTITY_DERIVATION_FAILED",
            ):
                identity.derive_public_identity_from_accepted_bytes(
                    payload,
                    ssh_keygen=keygen,
                    temp_dir=temp_dir,
                    baseline_sha256=hashlib.sha256(payload).hexdigest(),
                )
            self.assertEqual(list(temp_dir.glob("ldw-gate-a1-key-*")), [])

    def test_cleanup_failure_dominates_derivation_failure(self):
        if sys.platform != "win32":
            self.skipTest("Windows identity-bound temp cleanup")
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = root / "ssh-keygen.cmd"
            keygen.write_text("@echo off\r\nexit /b 1\r\n", encoding="ascii")
            temp_dir = root / "out"
            with mock.patch.object(identity, "_SetEndOfFile", return_value=False):
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

    def test_trusted_ssh_keygen_reads_synthetic_file_while_handle_held(self):
        if sys.platform != "win32":
            self.skipTest("Windows ssh-keygen share compatibility")
        import os

        payload = b"synthetic-not-a-real-private-key"
        keygen = identity.resolve_trusted_ssh_keygen_path()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ldw-gate-a1-key-synthetic"
            handle = identity._create_bound_temp_key_handle(path, payload)
            try:
                user = os.environ["USERNAME"]
                for args in (
                    ["/inheritance:r"],
                    ["/grant:r", f"{user}:(R,W)"],
                    ["/remove:g", "OWNER RIGHTS", "Users", "Authenticated Users", "Everyone"],
                ):
                    acl = subprocess.run(
                        ["icacls", str(path), *args],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(acl.returncode, 0, acl.stdout + acl.stderr)
                proc = subprocess.run(
                    [str(keygen), "-y", "-P", "", "-f", str(path)],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            finally:
                volume_serial, file_index = identity._destroy_bound_temp_key_handle(handle)
                identity._delete_identity_bound_temp_key(path, volume_serial, file_index)
            self.assertNotEqual(proc.returncode, 0)
            blob = (proc.stderr + proc.stdout).decode("utf-8", "replace").lower()
            self.assertIn("invalid format", blob)
            self.assertNotIn("permission denied", blob)
            self.assertNotIn("access is denied", blob)
            self.assertFalse(path.exists())

    def _echo_keygen(self, root: Path) -> Path:
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyNotARealKey fixture"
        keygen = root / "ssh-keygen.cmd"
        keygen.write_text(f"@echo off\r\necho {line}\r\n", encoding="ascii")
        return keygen

    def _assert_cleanup_fault_leaves_truncated_original(self, patcher) -> None:
        payload = b"synthetic-private-key-bytes"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keygen = self._echo_keygen(root)
            temp_dir = root / "out"
            context = patcher if patcher is not None else mock.patch.object(identity, "_FILE_BEGIN", 0)
            with context:
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
            residue = [p for p in temp_dir.glob("ldw-gate-a1-key-*") if p.is_file()]
            self.assertEqual(len(residue), 1)
            self.assertEqual(residue[0].read_bytes(), b"")
            self.assertNotIn(payload, residue[0].read_bytes())


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
