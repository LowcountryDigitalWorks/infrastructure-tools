"""Fail-closed, no-network synthetic tests for REDRIX Crostini R2 observation."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "redrix_continuity_health.py"
spec = importlib.util.spec_from_file_location("redrix_continuity_health", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("SOURCE_IMPORT_FAILED")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


def good() -> dict:
    return {
        "tailscaled_active": True,
        "tailscaled_enabled": True,
        "ssh_active": True,
        "ssh_enabled": True,
        "backend": "Running",
        "self_online": True,
        "health_ok": True,
        "jit_clean": True,
        "kvm_rw": True,
        "qemu_absent": True,
    }


class TestClassification(unittest.TestCase):
    def test_stable_local_ready_never_claims_remote_ready_or_authorization(self):
        result = health.classify([good() for _ in range(3)])
        self.assertEqual(result["classification"], "LOCAL_SERVICES_HEALTHY_UNVERIFIED")
        self.assertEqual(result["peer_side_corrob"], "UNVERIFIED")
        self.assertIs(result["ci_dispatch_authorized"], False)
        self.assertEqual(result["process_visibility"], "UNVERIFIED")
        self.assertEqual(result["reasons"], ["EXTERNAL_PEER_AND_PRIVILEGED_PROCESS_PROOF_REQUIRED"])

    def test_stale_control_map_with_running_daemon_is_degraded(self):
        rows = [good() for _ in range(3)]
        for row in rows:
            row["self_online"] = False
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_NETWORK")

    def test_one_transient_offline_sample_disallows_local_ready(self):
        rows = [good(), good(), good()]
        rows[1]["self_online"] = False
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_NETWORK")

    def test_service_is_active_but_not_enabled(self):
        rows = [good() for _ in range(3)]
        rows[1]["tailscaled_enabled"] = False
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_SERVICE")

    def test_offline_backend_overshadows_no_health_warnings(self):
        rows = [dict(good(), backend="Stopped", health_ok=True) for _ in range(3)]
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_NETWORK")

    def test_jit_hold_or_qemu_forces_hold(self):
        for field in ("jit_clean", "qemu_absent"):
            with self.subTest(field=field):
                rows = [good() for _ in range(3)]
                rows[0][field] = False
                result = health.classify(rows)
                self.assertEqual(result["classification"], "HOLD")
                self.assertIn("JIT_STATE_OR_QEMU_UNSAFE", result["reasons"])

    def test_kvm_denied(self):
        rows = [dict(good(), kvm_rw=False) for _ in range(3)]
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_HOST")

    def test_unknown_or_too_few_samples_refused(self):
        self.assertEqual(health.classify([good()])["classification"], "HOLD")
        self.assertEqual(health.classify([good(), good(), None])["classification"], "HOLD")

    def test_unknown_service_flag_fails_closed(self):
        rows = [good() for _ in range(3)]
        rows[1]["ssh_active"] = None
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_SERVICE")

    def test_never_emits_sensitive_sample_content(self):
        rows = [dict(good(), private_key="DO-NOT-EMIT", peer_ip="192.0.2.55") for _ in range(3)]
        encoded = json.dumps(health.classify(rows))
        self.assertNotIn("DO-NOT-EMIT", encoded)
        self.assertNotIn("192.0.2.55", encoded)

    def test_health_warnings_degrade(self):
        rows = [dict(good(), health_ok=False) for _ in range(3)]
        self.assertEqual(health.classify(rows)["classification"], "DEGRADED_NETWORK")


class TestPassiveJitReading(unittest.TestCase):
    def test_preexisting_clean_controller_state_is_read_only(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            state_root = base / "state" / "ldw-dragonfly-jit"
            runs = state_root / "runs"
            runs.mkdir(parents=True)
            data_base = base / "data" / "ldw-jit" / "base"
            data_base.mkdir(parents=True)
            (data_base / "debian-13-genericcloud-amd64.qcow2").write_bytes(b"synthetic")
            statefile = state_root / "status.json"
            statefile.write_text(json.dumps({"schema": 1, "marker": health.MARKER,
                "state": "STOPPED", "run_id": None, "qemu_pid": None}), encoding="utf-8")
            before = {p.relative_to(base): (p.stat().st_mtime_ns, p.read_bytes())
                      for p in (statefile, data_base / "debian-13-genericcloud-amd64.qcow2")}
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(base / "state"),
                                                  "XDG_DATA_HOME": str(base / "data")}):
                self.assertEqual(health._jit_state(), {"clean": True})
                (runs / "unexpected").mkdir()
                self.assertEqual(health._jit_state(), {"clean": False})
                (runs / "unexpected").rmdir()
                (data_base / "debian-13-genericcloud-amd64.qcow2").rename(data_base / "absent")
                self.assertEqual(health._jit_state(), {"clean": False})
            self.assertEqual(statefile.read_bytes(), before[statefile.relative_to(base)][1])

    def test_status_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            state_root = base / "state" / "ldw-dragonfly-jit"
            state_root.mkdir(parents=True)
            (state_root / "runs").mkdir()
            target = base / "target"
            target.write_text('{"schema":1}', encoding="utf-8")
            (state_root / "status.json").symlink_to(target)
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(base / "state"),
                                                  "XDG_DATA_HOME": str(base / "data")}):
                self.assertEqual(health._jit_state(), {"clean": False})

    def test_probe_never_calls_mutating_tailscale_or_service_command(self):
        seen = []
        def fake(args):
            seen.append(list(args))
            if args[:2] == ["tailscale", "status"]:
                return json.dumps({"BackendState": "Running", "Self": {"Online": True}, "Health": []})
            return ""
        with mock.patch.object(health, "_command", side_effect=fake), \
             mock.patch.object(health, "_jit_state", return_value={"clean": True}), \
             mock.patch.object(health, "_qemu_absent", return_value=True), \
             mock.patch.object(health.os, "access", return_value=True):
            row = health.sample()
        self.assertTrue(row["self_online"])
        self.assertTrue(row["jit_clean"])
        self.assertTrue(all(c[0] in ("tailscale", "systemctl") for c in seen))
        self.assertFalse(any("restart" in c or "up" in c or "down" in c for c in seen))


class TestQemuReadback(unittest.TestCase):
    def test_pgrep_no_matches_exit_one_is_clean(self):
        result = mock.Mock(returncode=1, stdout="0\n")
        with mock.patch.object(health.subprocess, "run", return_value=result):
            self.assertTrue(health._qemu_absent())

    def test_pgrep_live_qemu_is_not_clean(self):
        result = mock.Mock(returncode=0, stdout="1\n")
        with mock.patch.object(health.subprocess, "run", return_value=result):
            self.assertFalse(health._qemu_absent())

    def test_pgrep_error_is_fail_closed(self):
        result = mock.Mock(returncode=2, stdout="0\n")
        with mock.patch.object(health.subprocess, "run", return_value=result):
            self.assertFalse(health._qemu_absent())


if __name__ == "__main__":
    unittest.main()
