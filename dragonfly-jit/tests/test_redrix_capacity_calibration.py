"""Synthetic, no-host-write tests for the REDRIX calibration-only observer."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "redrix_capacity_calibration.py"
spec = importlib.util.spec_from_file_location("redrix_capacity_calibration", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("TEST_SOURCE_UNAVAILABLE")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CalibrationTest(unittest.TestCase):
    def test_parses_source_constants_without_executing_code(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "controller.py"
            f.write_text('GUEST_MEMORY_MIB = 2048\nMIN_RESERVE_MIB = 8192\nraise RuntimeError("MUST_NOT_EXECUTE")\n')
            self.assertEqual(module.controller_memory_contract(f), (2048, 8192))

    def test_invalid_or_missing_source_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "controller.py"
            self.assertIsNone(module.controller_memory_contract(f))
            f.write_text('GUEST_MEMORY_MIB = 2048\nMIN_RESERVE_MIB = missing\n')
            self.assertIsNone(module.controller_memory_contract(f))
            f.write_text('GUEST_MEMORY_MIB = 0\nMIN_RESERVE_MIB = 8192\n')
            self.assertIsNone(module.controller_memory_contract(f))

    def test_memavailable_reads_kib_and_rejects_malformed(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "meminfo"
            f.write_text('MemTotal: 20480000 kB\nMemAvailable: 9840640 kB\n')
            self.assertEqual(module.read_available_mib(f), 9610)
            f.write_text('MemAvailable: INVALID kB\n')
            self.assertIsNone(module.read_available_mib(f))

    def test_memory_pressure_parses_both_lines(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "memory.pressure"
            f.write_text('some avg10=1.25 avg60=0.02 total=1\nfull avg10=0.00 avg60=0.00 total=0\n')
            self.assertEqual(module.read_pressure_avg10(f), (1.25, 0))
            f.write_text('some avg10=1.25\n')
            self.assertIsNone(module.read_pressure_avg10(f))
            f.write_text('some avg10=101\nfull avg10=0\n')
            self.assertIsNone(module.read_pressure_avg10(f))

    def test_oom_counter_reads_or_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "memory.events"
            f.write_text('low 0\noom 2\noom_kill 1\n')
            self.assertEqual(module.read_oom_events(f), (2, 1))
            f.write_text('oom 2\n')
            self.assertIsNone(module.read_oom_events(f))

    def test_candidate_is_not_approved_even_when_memory_passes(self):
        s = [(9625, (0, 0), (1, 0)) for _ in range(3)]
        out = module.classify(s, (2048, 8192))
        self.assertEqual(out["classification"], "MEASURED_NOT_AUTHORIZED")
        self.assertFalse(out["accepted_memory_floor_met_all_samples"])
        self.assertTrue(out["research_only_floor_met_all_samples"])
        self.assertFalse(out["research_only_profile"]["approved"])
        self.assertFalse(out["ci_dispatch_authorized"])
        self.assertFalse(out["jit_admission_authorized"])
        self.assertEqual(out["chromeos_host_corroboration"], "UNVERIFIED")
        self.assertEqual(out["guest_memory_peak"], "UNMEASURED")

    def test_missing_pressure_fails_closed(self):
        out = module.classify([(9625, None, None)] * 3, (2048, 8192))
        self.assertEqual(out["classification"], "HOLD")
        self.assertFalse(out["ci_dispatch_authorized"])

    def test_missing_contract_and_sample_bounds_fail_closed(self):
        self.assertEqual(module.classify([], None)["classification"], "HOLD")
        self.assertEqual(module.classify([(9600, (0, 0), None)] * 2, (2048, 8192))["classification"], "HOLD")
        self.assertEqual(module.classify([(9600, (0, 0), None)] * 7, (2048, 8192))["classification"], "HOLD")

    def test_oom_deltas_are_bounded_not_proof(self):
        s = [(9600, (0, 0), (1, 2)), (9590, (0.1, 0), (1, 2)), (9570, (0, 0), (2, 3))]
        out = module.classify(s, (2048, 8192))
        self.assertEqual(out["observed_oom_delta"], 1)
        self.assertEqual(out["observed_oom_kill_delta"], 1)
        self.assertEqual(out["minimum_memavailable_mib"], 9570)
        self.assertEqual(out["maximum_psi_some_avg10_pct"], 0.1)
        self.assertFalse(out["ci_dispatch_authorized"])

    def test_does_not_emit_raw_sensitive_input(self):
        out = module.classify([(9600, (0, 0), None)] * 3, (2048, 8192))
        self.assertNotIn('token', json.dumps(out).lower())
        self.assertNotIn('path', json.dumps(out).lower())

    def test_sampling_error_is_sanitized(self):
        from contextlib import redirect_stdout
        from io import StringIO
        buf = StringIO()
        with mock.patch.object(module, "read_available_mib", side_effect=RuntimeError("SENSITIVE_EXAMPLE")), \
             mock.patch("sys.argv", ["calibration", "--interval-seconds", "0"]), \
             redirect_stdout(buf):
            self.assertEqual(module.main(), 1)
        self.assertNotIn("SENSITIVE_EXAMPLE", buf.getvalue())
        self.assertEqual(json.loads(buf.getvalue())["classification"], "HOLD")


if __name__ == "__main__":
    unittest.main()
