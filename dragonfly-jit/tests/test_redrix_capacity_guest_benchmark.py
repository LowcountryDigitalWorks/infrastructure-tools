#!/usr/bin/env python3
"""Deterministic negatives for the unwired REDRIX guest benchmark. No QEMU."""
from __future__ import annotations

import ast
import importlib.util
from io import StringIO
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "redrix_capacity_guest_benchmark.py"
CONTROLLER = ROOT / "dragonfly_jit.py"


def load():
    spec = importlib.util.spec_from_file_location("redrix_capacity_guest_benchmark", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bench = load()


def clean(**overrides):
    obs = {
        "mem_available_mib": [8192, 8300, 8400],
        "psi": [(0.0, 0.0), (0.0, 0.0), (0.0, 0.0)],
        "balloon_inflate": [0, 0, 0],
        "oom_present": True,
        "load_fraction": 0.2,
        "free_disk_gib": 20,
        "kvm_rw": True,
        "qemu_present": False,
        "controller_state": "AVAILABLE",
        "lock_busy": False,
        "duplicate_lock": False,
        "symlink": False,
        "caller_path": False,
        "extra_argv": False,
        "base_sha512": bench.EXPECTED_BASE_SHA512,
        "controller_blob": bench.EXPECTED_CONTROLLER_BLOB,
        "parsed_guest": 2048,
        "parsed_reserve": 8192,
    }
    obs.update(overrides)
    return obs


def good_outcome():
    return {
        "started": True,
        "owned": True,
        "starttime_attested": True,
        "timed_out": False,
        "serial": bench.SUCCESS_MARKER,
        "poweroff_clean": True,
    }


class GuestBenchmarkTests(unittest.TestCase):
    def assert_closed(self, report):
        self.assertFalse(report["physical_guest_executed"])
        self.assertFalse(report["jit_admission_authorized"])
        self.assertFalse(report["provider_admission_authorized"])
        self.assertFalse(report["production_policy_changed"])
        self.assertEqual(report["production_reserve_mib"], 8192)
        self.assertEqual(report["research_floor_mib"], 8192)

    def test_live_controller_blob_and_contract_match_the_pin(self):
        identity = bench.read_controller_identity(CONTROLLER)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["blob"], bench.EXPECTED_CONTROLLER_BLOB)
        self.assertEqual(identity["guest_mib"], 2048)
        self.assertEqual(identity["reserve_mib"], 8192)
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        names = []
        for node in imports:
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            else:
                names.append(node.module or "")
        self.assertNotIn("subprocess", names)
        self.assertFalse(any(name.startswith("dragonfly_jit") for name in names))

    def test_cli_never_admits_or_launches(self):
        from contextlib import redirect_stdout
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = bench.main(["--run", "/tmp/evil", "qemu-system-x86_64"])
        self.assertEqual(code, 2)
        self.assertIn("CLI_NOT_ADMITTED", buffer.getvalue())
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Name) and node.func.id == "Popen" for node in calls))

    def test_preflight_failures_do_not_launch(self):
        cases = (
            ({"symlink": True}, "SYMLINK_REFUSED"),
            ({"duplicate_lock": True}, "GUEST_LOCK_BUSY"),
            ({"lock_busy": True}, "GUEST_LOCK_BUSY"),
            ({"qemu_present": True}, "QEMU_ALREADY_PRESENT"),
            ({"controller_state": "RUNNING"}, "CONTROLLER_STATE_REFUSED"),
            ({"base_sha512": "0" * 128}, "BASE_SHA512_MISMATCH"),
            ({"controller_blob": "0" * 40}, "CONTROLLER_BLOB_MISMATCH"),
            ({"mem_available_mib": [8192, 8191, 9000]}, "RESEARCH_MEMORY_FLOOR"),
            ({"psi": [(0.0, 0.0), (0.1, 0.0), (0.0, 0.0)]}, "PSI_UNSTABLE"),
            ({"balloon_inflate": [0, 1, 1]}, "BALLOON_INFLATION"),
            ({"oom_present": False}, "OOM_COUNTER_UNAVAILABLE"),
            ({"load_fraction": 0.9}, "CAPACITY_CPU"),
            ({"free_disk_gib": 4}, "CAPACITY_DISK"),
            ({"kvm_rw": False}, "KVM_NOT_READY"),
            ({"extra_argv": True}, "ARGV_OR_PATH_REFUSED"),
            ({"caller_path": True}, "ARGV_OR_PATH_REFUSED"),
        )
        for overrides, reason in cases:
            with self.subTest(reason=reason):
                report = bench.decide(clean(**overrides), bench.ADMISSION_TOKEN, good_outcome())
                self.assertEqual(report["reason"], reason)
                self.assertFalse(report["launched"])
                self.assert_closed(report)

    def test_admission_timeout_ownership_and_serial_failures(self):
        ready = clean()
        refused = bench.decide(ready, "nope", good_outcome())
        self.assertEqual(refused["reason"], "RUNTIME_ADMISSION_REQUIRED")
        self.assertFalse(refused["launched"])
        unwired = bench.decide(ready, bench.ADMISSION_TOKEN, None)
        self.assertEqual(unwired["reason"], "LAUNCH_NOT_WIRED")
        before = bench.decide(ready, bench.ADMISSION_TOKEN, {"started": False})
        self.assertEqual(before["reason"], "TIMEOUT_BEFORE_LAUNCH")
        uncertain = dict(good_outcome(), owned=False)
        death = bench.decide(ready, bench.ADMISSION_TOKEN, uncertain)
        self.assertEqual(death["reason"], "CHILD_OWNERSHIP_UNCERTAIN")
        self.assertTrue(death["evidence_retained"])
        timed = dict(good_outcome(), timed_out=True)
        self.assertEqual(bench.decide(ready, bench.ADMISSION_TOKEN, timed)["reason"], "GUEST_TIMEOUT")
        missing = dict(good_outcome(), serial="boot-only")
        self.assertEqual(bench.decide(ready, bench.ADMISSION_TOKEN, missing)["reason"], "SUCCESS_MARKER_MISSING")
        partial = dict(good_outcome(), serial="LDW_REDRIX_GUEST")
        self.assertEqual(bench.decide(ready, bench.ADMISSION_TOKEN, partial)["reason"], "SERIAL_PARTIAL")
        malformed = dict(good_outcome(), serial=bench.SUCCESS_MARKER + "\nextra")
        self.assertEqual(bench.decide(ready, bench.ADMISSION_TOKEN, malformed)["reason"], "SERIAL_MALFORMED")

    def test_injected_success_is_not_a_physical_or_provider_admission(self):
        report = bench.decide(clean(), bench.ADMISSION_TOKEN, good_outcome())
        self.assertEqual(report["classification"], "MEASURED_NOT_AUTHORIZED")
        self.assertEqual(report["reason"], "INJECTED_EVIDENCE_ONLY")
        self.assertTrue(report["launched"])
        self.assert_closed(report)

    def test_fixed_argv_has_no_network_and_workload_is_bounded(self):
        argv = bench.fixed_qemu_argv("overlay.qcow2", "serial.log")
        self.assertIsNotNone(argv)
        self.assertIn("-nic", argv)
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        self.assertNotIn("-netdev", argv)
        self.assertIn("2048M", argv)
        self.assertIsNone(bench.fixed_qemu_argv("-overlay", "serial.log"))
        source = bench.guest_workload_source()
        self.assertIn(bench.SUCCESS_MARKER, source)
        self.assertNotIn("socket", source)
        self.assertIn("chunks=1024", source)
        self.assertGreaterEqual(1024, 768)
        self.assertLessEqual(1024, 1280)

    def test_controller_symlink_and_bad_text_are_refused(self):
        self.assertIsNone(bench.parse_controller_text("GUEST_MEMORY_MIB = 1\n"))
        self.assertIsNone(bench.read_controller_identity(MODULE_PATH))
