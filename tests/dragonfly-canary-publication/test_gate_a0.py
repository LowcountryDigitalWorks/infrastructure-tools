#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
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
INSTALLER_PATH = ROOT / "tools" / "dragonfly_canary_redrix_install.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a0 = load("test_gate_a0_module", A0_PATH)
installer = load("test_gate_a0_installer", INSTALLER_PATH)


def git_blob(blob: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "cat-file", "blob", blob],
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


class SyntheticRunner:
    def __init__(self, host_fingerprint: str):
        status = {
            "BackendState": "Running",
            "Self": {"Online": True, "TailscaleIPs": ["100.64.1.2"]},
            "Health": [],
            "TailnetName": "private.example.ts.net",
        }
        prefs = {
            "WantRunning": True,
            "RunSSH": False,
            "RouteAll": False,
            "RunWebClient": False,
            "ExitNodeID": "",
            "ExitNodeIP": "",
            "AdvertiseRoutes": [],
            "AdvertiseServices": [],
        }
        self.responses: dict[tuple[str, ...], tuple[int, str]] = {
            ("/usr/bin/ps", "-eo", "pid=,comm=,args="): (0, "1 init /sbin/init\n2 kthreadd [kthreadd]"),
            ("/usr/sbin/sshd", "-V"): (0, a0.EXPECTED_OPENSSH_PREFIX + ", OpenSSL 3.5.7"),
            ("/usr/bin/systemctl", "is-active", "ssh.service"): (0, "active"),
            ("/usr/bin/systemctl", "is-enabled", "ssh.service"): (0, "enabled"),
            ("/usr/bin/ss", "-ltnH"): (0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"),
            ("/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"): (
                0,
                f"256 {host_fingerprint} redrix (ED25519)",
            ),
            ("/usr/bin/systemctl", "is-active", "tailscaled.service"): (0, "active"),
            ("/usr/bin/systemctl", "is-enabled", "tailscaled.service"): (0, "enabled"),
            ("/usr/bin/tailscale", "version"): (0, a0.EXPECTED_TAILSCALE_VERSION + "\n  tailscale commit: synthetic"),
            ("/usr/bin/tailscale", "status", "--json"): (0, json.dumps(status)),
            ("/usr/bin/tailscale", "debug", "prefs"): (0, json.dumps(prefs)),
            ("/usr/bin/tailscale", "serve", "status", "--json"): (0, "{}"),
        }
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> tuple[int, str]:
        self.calls.append(argv)
        return self.responses.get(argv, (127, "synthetic command missing"))


class GateA0Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.state = self.home / ".local/state/ldw-dragonfly-jit"
        self.runs = self.state / "runs"
        self.state.mkdir(parents=True, mode=0o700)
        self.runs.mkdir(mode=0o700)

        self.transaction = self.home / ".local/state/ldw/dragonfly-canary-publication/install-transaction.json"
        self.receipt = self.home / ".local/state/ldw/dragonfly-canary-publication/install-receipt.json"
        self.auth = self.home / ".ssh/authorized_keys"
        self.auth.parent.mkdir(parents=True, mode=0o700)

        self.key_data = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.expected_key_sha = hashlib.sha256(f"ssh-ed25519 {self.key_data}".encode("ascii")).hexdigest()
        self.auth.write_text(
            f'restrict,command="{a0.FORCED_COMMAND}" ssh-ed25519 {self.key_data} synthetic\n',
            encoding="utf-8",
        )
        self.auth.chmod(0o600)

        for rel, (blob, mode) in a0.REQUIRED_ACCEPTED_115.items():
            target = self.home / rel
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(git_blob(blob))
            target.chmod(mode)

        optional_rel = Path(".local/lib/ldw-dragonfly-jit/dragonfly_jit.py")
        optional_blob, optional_mode = a0.OPTIONAL_ACCEPTED_CURRENT[optional_rel]
        optional_target = self.home / optional_rel
        optional_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        optional_target.write_bytes(git_blob(optional_blob))
        optional_target.chmod(optional_mode)

        self.expected_host_fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.runner = SyntheticRunner(self.expected_host_fp)
        self.original_globals = {
            "STATE_ROOT": a0.STATE_ROOT,
            "RUNS_ROOT": a0.RUNS_ROOT,
            "STATUS_PATH": a0.STATUS_PATH,
            "STATE_LOCK_PATH": a0.STATE_LOCK_PATH,
            "GUEST_LOCK_PATH": a0.GUEST_LOCK_PATH,
            "TRANSACTION_PATH": a0.TRANSACTION_PATH,
            "RECEIPT_PATH": a0.RECEIPT_PATH,
            "AUTHORIZED_KEYS_PATH": a0.AUTHORIZED_KEYS_PATH,
            "AUTHORIZED_KEYS2_PATH": a0.AUTHORIZED_KEYS2_PATH,
        }
        a0.STATE_ROOT = self.state
        a0.RUNS_ROOT = self.runs
        a0.STATUS_PATH = self.state / "status.json"
        a0.STATE_LOCK_PATH = self.state / "state.lock"
        a0.GUEST_LOCK_PATH = self.state / "guest.lock"
        a0.TRANSACTION_PATH = self.transaction
        a0.RECEIPT_PATH = self.receipt
        a0.AUTHORIZED_KEYS_PATH = self.auth
        a0.AUTHORIZED_KEYS2_PATH = self.home / ".ssh/authorized_keys2"

    def tearDown(self):
        for name, value in self.original_globals.items():
            setattr(a0, name, value)
        self.temp.cleanup()

    def _collect_impl(self, **overrides):
        args = {
            "home": self.home,
            "uid": self.uid,
            "runner": self.runner,
            "expected_local_alias": "redrix",
            "expected_host_fingerprint": self.expected_host_fp,
            "expected_transport_key_sha256": self.expected_key_sha,
        }
        args.update(overrides)
        return a0.collect_a0(**args)

    def collect(self, **overrides):
        original_is_file = Path.is_file
        original_is_symlink = Path.is_symlink
        manpage = Path("/usr/share/man/man5/authorized_keys.5.gz")

        def fake_is_file(path: Path) -> bool:
            if path == manpage:
                return True
            return original_is_file(path)

        def fake_is_symlink(path: Path) -> bool:
            if path == manpage:
                return False
            return original_is_symlink(path)

        with mock.patch.object(a0.socket, "gethostname", return_value="redrix"), \
             mock.patch.object(Path, "is_file", new=fake_is_file), \
             mock.patch.object(Path, "is_symlink", new=fake_is_symlink), \
             mock.patch.object(
                 a0.gzip,
                 "open",
                 side_effect=lambda *args, **kwargs: io.StringIO("authorized_keys supports restrict\n"),
             ):
            return self._collect_impl(**overrides)

    def write_state(self, state: str, run_id=None, qemu_pid=None):
        payload = {
            "schema": 1,
            "marker": "CI-RUNNER-DRAGONFLY-JIT-001",
            "state": state,
            "updated_at": "2026-10-30T00:00:00+00:00",
            "run_id": run_id,
            "qemu_pid": qemu_pid,
            "reason": None,
        }
        a0.STATUS_PATH.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        a0.STATUS_PATH.chmod(0o600)

    def test_embedded_transport_constants_match_accepted_installer_contract(self):
        rollback = {rel: (blob, mode) for _source, blob, rel, mode in installer.ROLLBACK}
        current = {rel: (blob, mode) for _source, blob, rel, mode in installer.CURRENT}
        self.assertEqual(a0.REQUIRED_ACCEPTED_115, rollback)
        current_only = {rel: value for rel, value in current.items() if rel not in rollback}
        self.assertEqual(a0.OPTIONAL_ACCEPTED_CURRENT, current_only)
        self.assertEqual(a0.FORCED_COMMAND, installer.FORCED_COMMAND)

    def test_source_is_standalone_read_only_and_has_no_checkout_or_remote_action_surface(self):
        text = A0_PATH.read_text(encoding="utf-8")
        forbidden = (
            "importlib",
            "git -C",
            "git clone",
            "urllib",
            "requests",
            ".write_text(",
            ".write_bytes(",
            ".mkdir(",
            ".unlink(",
            "os.remove(",
            "os.chmod(",
            "subprocess.Popen",
            "LOCK_EX",
            "generate-jitconfig",
            "tailscale set",
            "tailscale up",
            "systemctl start",
            "systemctl enable",
            "ssh.exe",
        )
        for value in forbidden:
            self.assertNotIn(value, text, value)
        self.assertIn("LOCK_SH", text)
        self.assertIn("DRAGONFLY_GATE_A0=PASS", text)
        self.assertIn("EVIDENCE_JSON=", text)

    def test_clean_state_emits_sanitized_evidence_without_file_mutation(self):
        before = snapshot(self.root)
        evidence = self.collect()
        after = snapshot(self.root)
        self.assertEqual(before, after)
        self.assertEqual(evidence["marker"], a0.MARKER)
        self.assertEqual(evidence["localHostAlias"], "redrix")
        self.assertEqual(evidence["jitState"], "STOPPED")
        self.assertEqual(evidence["jitStateSource"], "implicit-default")
        self.assertEqual(evidence["qemuProcessCount"], 0)
        self.assertEqual(evidence["transportBaseline"], "accepted-115")
        self.assertEqual(evidence["transportKeyIdentity"], "expected")
        self.assertTrue(evidence["hostFingerprintInvariant"])
        self.assertFalse(evidence["tailscaleSsh"])
        self.assertFalse(evidence["tailscaleAcceptRoutes"])
        self.assertFalse(evidence["tailscaleExitNodeUse"])
        self.assertEqual(evidence["tailscaleAdvertisedRoutes"], 0)
        self.assertFalse(evidence["tailscaleWebClient"])
        self.assertFalse(evidence["tailscaleServeOrFunnelConfigured"])
        self.assertEqual(evidence["stabilityPasses"], 2)
        self.assertNotIn("TailscaleIPs", json.dumps(evidence))
        self.assertNotIn("TailnetName", json.dumps(evidence))
        self.assertNotIn(self.key_data, json.dumps(evidence))
        stable = dict(evidence)
        digest = stable.pop("snapshotSha256")
        stable.pop("generatedAt")
        stable.pop("stabilityPasses")
        self.assertEqual(digest, hashlib.sha256(a0._canonical(stable)).hexdigest())

    def test_only_read_only_command_surface_is_invoked(self):
        self.collect()
        expected = {
            ("/usr/bin/ps", "-eo", "pid=,comm=,args="),
            ("/usr/sbin/sshd", "-V"),
            ("/usr/bin/systemctl", "is-active", "ssh.service"),
            ("/usr/bin/systemctl", "is-enabled", "ssh.service"),
            ("/usr/bin/ss", "-ltnH"),
            ("/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"),
            ("/usr/bin/systemctl", "is-active", "tailscaled.service"),
            ("/usr/bin/systemctl", "is-enabled", "tailscaled.service"),
            ("/usr/bin/tailscale", "version"),
            ("/usr/bin/tailscale", "status", "--json"),
            ("/usr/bin/tailscale", "debug", "prefs"),
            ("/usr/bin/tailscale", "serve", "status", "--json"),
        }
        self.assertEqual(set(self.runner.calls), expected)
        self.assertTrue(all(self.runner.calls.count(command) == 2 for command in expected))

    def test_file_backed_stopped_is_distinguished(self):
        self.write_state("STOPPED")
        evidence = self.collect()
        self.assertTrue(evidence["statusFilePresent"])
        self.assertEqual(evidence["jitStateSource"], "file-backed")

    def test_non_stopped_and_residue_are_refused(self):
        import uuid
        self.write_state("RUNNING", str(uuid.uuid4()), 1234)
        with self.assertRaisesRegex(a0.A0Error, "A0_JIT_STATE_NOT_STOPPED"):
            self.collect()
        a0.STATUS_PATH.unlink()
        (self.runs / "residue").mkdir(mode=0o700)
        with self.assertRaisesRegex(a0.A0Error, "A0_RUN_RESIDUE_PRESENT"):
            self.collect()

    def test_status_symlink_is_refused(self):
        target = self.root / "outside-status"
        target.write_text("{}\n", encoding="utf-8")
        a0.STATUS_PATH.symlink_to(target)
        with self.assertRaisesRegex(a0.A0Error, "A0_STATUS_PATH_INVALID"):
            self.collect()

    def test_lock_file_presence_is_reported_without_mutation(self):
        for path in (a0.GUEST_LOCK_PATH, a0.STATE_LOCK_PATH):
            path.write_bytes(b"")
            path.chmod(0o600)
        before = snapshot(self.root)
        evidence = self.collect()
        after = snapshot(self.root)
        self.assertEqual(before, after)
        self.assertTrue(evidence["guestLockFilePresent"])
        self.assertTrue(evidence["stateLockFilePresent"])

    def test_qemu_parser_detects_direct_alias_and_wrapped_processes(self):
        text = "\n".join((
            "100 qemu-system-x86 /usr/bin/qemu-system-x86_64 -m 2048",
            "101 qemu-kvm /usr/bin/qemu-kvm -m 2048",
            "102 sh /bin/sh -c '/usr/bin/qemu-system-aarch64 -m 1024'",
            "103 kvm /usr/bin/kvm -m 1024",
            "104 python3 python3 harmless.py",
        ))
        self.assertEqual(a0._qemu_process_ids_from_ps(text), [100, 101, 102, 103])
        self.runner.responses[("/usr/bin/ps", "-eo", "pid=,comm=,args=")] = (0, text)
        with self.assertRaisesRegex(a0.A0Error, "A0_QEMU_PROCESS_PRESENT"):
            self.collect()

    def test_publication_transaction_or_receipt_is_refused(self):
        self.transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.transaction.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(a0.A0Error, "A0_INSTALL_TRANSACTION_PRESENT"):
            self.collect()
        self.transaction.unlink()
        self.receipt.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(a0.A0Error, "A0_INSTALL_RECEIPT_PRESENT"):
            self.collect()

    def test_transport_file_tamper_is_refused(self):
        rel = next(iter(a0.REQUIRED_ACCEPTED_115))
        (self.home / rel).write_bytes(b"tampered\n")
        with self.assertRaisesRegex(a0.A0Error, "A0_TRANSPORT_BASELINE_UNRECOGNIZED"):
            self.collect()

    def test_transport_key_identity_and_restriction_are_refused_on_drift(self):
        with self.assertRaisesRegex(a0.A0Error, "A0_TRANSPORT_KEY_IDENTITY_INVALID"):
            self.collect(expected_transport_key_sha256="0" * 64)
        self.auth.write_text(f"ssh-ed25519 {self.key_data} synthetic\n", encoding="utf-8")
        with self.assertRaisesRegex(a0.A0Error, "A0_TRANSPORT_KEY_IDENTITY_INVALID"):
            self.collect()

    def test_exact_local_alias_is_required(self):
        with mock.patch.object(a0.socket, "gethostname", return_value="penguin"):
            with self.assertRaisesRegex(a0.A0Error, "A0_LOCAL_HOST_IDENTITY_MISMATCH"):
                self._collect_impl()
        with self.assertRaisesRegex(a0.A0Error, "A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID"):
            self.collect(expected_local_alias="other")

    def test_snapshot_change_between_passes_is_refused(self):
        clean = {"schema": 2, "marker": a0.MARKER, "stable": True}
        changed = {"schema": 2, "marker": a0.MARKER, "stable": False}
        with mock.patch.object(a0, "_collect_once", side_effect=[clean, changed]):
            with self.assertRaisesRegex(a0.A0Error, "A0_SNAPSHOT_CHANGED_DURING_READBACK"):
                a0.collect_a0(
                    home=self.home,
                    uid=self.uid,
                    runner=self.runner,
                    expected_local_alias="redrix",
                    expected_host_fingerprint=self.expected_host_fp,
                    expected_transport_key_sha256=self.expected_key_sha,
                )

    def test_openssh_version_listener_and_host_fingerprint_drift_fail_closed(self):
        self.runner.responses[("/usr/sbin/sshd", "-V")] = (0, "OpenSSH_99.0")
        with self.assertRaisesRegex(a0.A0Error, "A0_SSHD_VERSION_DRIFT"):
            self.collect()
        self.runner = SyntheticRunner(self.expected_host_fp)
        self.runner.responses[("/usr/bin/ss", "-ltnH")] = (0, "LISTEN 0 128 127.0.0.1:2222 0.0.0.0:*")
        with self.assertRaisesRegex(a0.A0Error, "A0_TCP22_NOT_NONLOOPBACK"):
            self.collect()
        self.runner = SyntheticRunner(self.expected_host_fp)
        with self.assertRaisesRegex(a0.A0Error, "A0_HOST_FINGERPRINT_MISMATCH"):
            self.collect(expected_host_fingerprint="SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

    def test_tailscale_status_prefs_serve_and_version_drift_fail_closed(self):
        self.runner.responses[("/usr/bin/tailscale", "version")] = (0, "9.9.9")
        with self.assertRaisesRegex(a0.A0Error, "A0_TAILSCALE_VERSION_DRIFT"):
            self.collect()

        self.runner = SyntheticRunner(self.expected_host_fp)
        status = {"BackendState": "Running", "Self": {"Online": False}, "Health": []}
        self.runner.responses[("/usr/bin/tailscale", "status", "--json")] = (0, json.dumps(status))
        with self.assertRaisesRegex(a0.A0Error, "A0_TAILSCALE_SELF_NOT_ONLINE"):
            self.collect()

        self.runner = SyntheticRunner(self.expected_host_fp)
        prefs = {"WantRunning": True, "RunSSH": True, "RouteAll": False, "RunWebClient": False}
        self.runner.responses[("/usr/bin/tailscale", "debug", "prefs")] = (0, json.dumps(prefs))
        with self.assertRaisesRegex(a0.A0Error, "A0_TAILSCALE_PREFS_DRIFT"):
            self.collect()

        self.runner = SyntheticRunner(self.expected_host_fp)
        self.runner.responses[("/usr/bin/tailscale", "serve", "status", "--json")] = (
            0,
            json.dumps({"AllowFunnel": {"redrix.ts.net:443": False}}),
        )
        with self.assertRaisesRegex(a0.A0Error, "A0_TAILSCALE_SERVE_OR_FUNNEL_CONFIGURED"):
            self.collect()

    def test_snapshot_digest_is_reproducible_and_excludes_timestamp(self):
        first = self.collect()
        second = self.collect()
        self.assertEqual(first["snapshotSha256"], second["snapshotSha256"])
        self.assertRegex(first["generatedAt"], r"^\d{4}-\d{2}-\d{2}T")


if __name__ == "__main__":
    unittest.main()
