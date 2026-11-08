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


def _sample(available=9600, pressure=(0.0, 0.0), oom=None, balloon=None):
    return (available, pressure, oom, balloon)


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

    def test_proc_psi_fallback_when_cgroup_missing(self):
        with tempfile.TemporaryDirectory() as root:
            cgroup = Path(root) / "missing.pressure"
            proc = Path(root) / "memory"
            proc.write_text('some avg10=0.00 avg60=0.00 total=0\nfull avg10=0.00 avg60=0.00 total=0\n')
            self.assertEqual(module.read_memory_pressure_avg10(cgroup, proc), (0.0, 0.0))

    def test_oom_counter_reads_or_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "memory.events"
            f.write_text('low 0\noom 2\noom_kill 1\n')
            self.assertEqual(module.read_oom_events(f), (2, 1))
            f.write_text('oom 2\n')
            self.assertIsNone(module.read_oom_events(f))
            missing = Path(root) / "absent"
            self.assertIsNone(module.read_oom_events(missing))

    def test_balloon_vmstat_realistic_fixture(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "vmstat"
            f.write_text(
                "balloon_inflate 6612023\n"
                "balloon_deflate 1872062\n"
                "nr_free_pages 123\n",
                encoding="ascii",
            )
            self.assertEqual(module.read_balloon_vmstat_pages(f), (6612023, 1872062))

    def test_balloon_vmstat_absent_is_none_not_zero(self):
        with tempfile.TemporaryDirectory() as root:
            f = Path(root) / "vmstat"
            f.write_text("nr_free_pages 1\n")
            self.assertIsNone(module.read_balloon_vmstat_pages(f))

    def test_balloon_sysfs_present_observation(self):
        with tempfile.TemporaryDirectory() as root:
            device = Path(root) / "virtio5"
            device.mkdir()
            self.assertEqual(module.observe_virtio_balloon_sysfs(device), "PRESENT")
            self.assertEqual(module.observe_virtio_balloon_sysfs(Path(root) / "missing"), "UNVERIFIED")

    def test_balloon_nonmonotonic_marks_hold_without_breaking_auth_flags(self):
        samples = [
            _sample(balloon=(100, 50)),
            _sample(balloon=(120, 60)),
            _sample(balloon=(90, 70)),
        ]
        out = module.classify(samples, (2048, 8192), virtio_balloon_sysfs="PRESENT")
        self.assertEqual(out["balloon_vmstat"], "HOLD")
        self.assertEqual(out["classification"], "MEASURED_NOT_AUTHORIZED")
        self.assertFalse(out["ci_dispatch_authorized"])

    def test_balloon_absent_still_measures_generic_fields(self):
        samples = [_sample(balloon=None) for _ in range(3)]
        out = module.classify(samples, (2048, 8192))
        self.assertEqual(out["balloon_vmstat"], "UNVERIFIED")
        self.assertEqual(out["classification"], "MEASURED_NOT_AUTHORIZED")

    def test_balloon_delta_indicative_only(self):
        samples = [
            _sample(balloon=(6612000, 1872000)),
            _sample(balloon=(6612010, 1872010)),
            _sample(balloon=(6612023, 1872062)),
        ]
        out = module.classify(samples, (2048, 8192), virtio_balloon_sysfs="PRESENT")
        self.assertEqual(out["balloon_vmstat"], "MEASURED_INDICATIVE")
        self.assertEqual(out["balloon_inflate_pages_delta"], 23)
        self.assertEqual(out["balloon_deflate_pages_delta"], 62)

    def test_candidate_is_not_approved_even_when_memory_passes(self):
        s = [_sample(9625, (0, 0), (1, 0), (1, 0)) for _ in range(3)]
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
        out = module.classify([_sample(9625, None, None, None)] * 3, (2048, 8192))
        self.assertEqual(out["classification"], "HOLD")
        self.assertFalse(out["ci_dispatch_authorized"])

    def test_missing_contract_and_sample_bounds_fail_closed(self):
        self.assertEqual(module.classify([], None)["classification"], "HOLD")
        self.assertEqual(module.classify([_sample(9600, (0, 0), None, None)] * 2, (2048, 8192))["classification"], "HOLD")
        self.assertEqual(module.classify([_sample(9600, (0, 0), None, None)] * 7, (2048, 8192))["classification"], "HOLD")

    def test_oom_deltas_are_bounded_not_proof(self):
        s = [
            _sample(9600, (0, 0), (1, 2), (10, 5)),
            _sample(9590, (0.1, 0), (1, 2), (12, 6)),
            _sample(9570, (0, 0), (2, 3), (15, 8)),
        ]
        out = module.classify(s, (2048, 8192))
        self.assertEqual(out["observed_oom_delta"], 1)
        self.assertEqual(out["observed_oom_kill_delta"], 1)
        self.assertEqual(out["minimum_memavailable_mib"], 9570)
        self.assertEqual(out["maximum_psi_some_avg10_pct"], 0.1)
        self.assertFalse(out["ci_dispatch_authorized"])

    def test_does_not_emit_raw_sensitive_input(self):
        out = module.classify([_sample(9600, (0, 0), None, None)] * 3, (2048, 8192))
        blob = json.dumps(out).lower()
        self.assertNotIn('token', blob)
        self.assertNotIn('ssh', blob)
        self.assertNotIn('tailscale', blob)
        self.assertNotIn('virtio5', blob)

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
