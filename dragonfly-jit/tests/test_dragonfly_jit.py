import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "dragonfly_jit.py"
PROVENANCE_PATH = Path(__file__).resolve().parents[1] / "base-provenance.json"
SPEC = importlib.util.spec_from_file_location("dragonfly_jit", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class DragonflyContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.state = self.root / "state"
        self.controller = mod.Controller(data_root=self.data, state_root=self.state)
        self.base = self.data / "base" / mod.BASE_FILENAME
        self.base.parent.mkdir(parents=True)
        self.base.write_bytes(b"fixture")

    def tearDown(self):
        self.temp.cleanup()

    def admitted_snapshot(self):
        return {
            "mem_available_mib": mod.GUEST_MEMORY_MIB + mod.MIN_RESERVE_MIB + 1,
            "load_fraction": 0.1,
            "free_disk_gib": mod.MIN_FREE_DISK_GIB + 1,
            "visible_cpus": 12,
        }

    def test_pin_is_full_sha512(self):
        self.assertEqual(128, len(mod.BASE_SHA512))
        int(mod.BASE_SHA512, 16)

    def test_provenance_file_matches_runtime_pin(self):
        provenance = json.loads(PROVENANCE_PATH.read_text())
        self.assertEqual(mod.BASE_FILENAME, provenance["filename"])
        self.assertEqual(mod.BASE_SHA512, provenance["sha512"])
        self.assertEqual("sha512", provenance["runtime_trust"])
        self.assertFalse(provenance["source_locator_is_immutable"])
        self.assertFalse(provenance["auto_refresh"])

    def test_base_digest_mismatch_fails_closed(self):
        with self.assertRaisesRegex(mod.DragonflyError, "BASE_SHA512_MISMATCH"):
            self.controller.verify_base()

    def test_base_symlink_is_refused(self):
        self.base.unlink()
        target = self.root / "target.qcow2"
        target.write_bytes(b"fixture")
        self.base.symlink_to(target)
        with self.assertRaisesRegex(mod.DragonflyError, "VERIFIED_BASE_REQUIRED|SYMLINK"):
            self.controller.verify_base()

    def test_state_root_symlink_is_refused_before_chmod(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        self.state.symlink_to(outside, target_is_directory=True)
        before = stat.S_IMODE(outside.stat().st_mode)
        with self.assertRaisesRegex(mod.DragonflyError, "SYMLINK_PATH_REFUSED"):
            self.controller.ensure_roots()
        self.assertEqual(before, stat.S_IMODE(outside.stat().st_mode))
        self.assertFalse((outside / "runs").exists())

    def test_admission_memory_disk_and_cpu_are_independent_failures(self):
        good = self.admitted_snapshot()
        for key, value, reason in (
            ("mem_available_mib", mod.GUEST_MEMORY_MIB + mod.MIN_RESERVE_MIB - 1, "CAPACITY_MEMORY"),
            ("free_disk_gib", mod.MIN_FREE_DISK_GIB - 1, "CAPACITY_DISK"),
            ("load_fraction", mod.MAX_LOAD_FRACTION + 0.01, "CAPACITY_CPU"),
        ):
            candidate = dict(good)
            candidate[key] = value
            with self.assertRaisesRegex(mod.DragonflyError, reason):
                mod.assert_admission(candidate)

    def test_start_only_marks_available_and_does_not_launch(self):
        with mock.patch.object(self.controller, "verify_base", return_value={}), \
             mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()), \
             mock.patch.object(mod.subprocess, "Popen") as popen:
            state = self.controller.start()
        self.assertEqual("AVAILABLE", state["state"])
        popen.assert_not_called()

    def test_start_refuses_stale_run_directory(self):
        self.controller.ensure_roots()
        (self.controller.runs_root / "11111111-1111-4111-8111-111111111111").mkdir()
        with mock.patch.object(self.controller, "verify_base", return_value={}), \
             mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()):
            with self.assertRaisesRegex(mod.DragonflyError, "STALE_RUN_STATE_REFUSED"):
                self.controller.start()

    def test_start_refuses_failed_or_hold_until_recovery(self):
        self.controller.ensure_roots()
        for state in ("FAILED", "HOLD"):
            self.controller.write_state(state, reason="SMOKE_FAILED")
            with mock.patch.object(self.controller, "verify_base", return_value={}), \
                 mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()):
                with self.assertRaisesRegex(mod.DragonflyError, "RECOVERY_REQUIRED"):
                    self.controller.start()

    def test_drain_available_goes_stopped(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        state = self.controller.drain()
        self.assertEqual("STOPPED", state["state"])

    def test_drain_available_with_busy_guest_lock_requests_prelaunch_drain(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        with mock.patch.object(self.controller, "_guest_lock_available", return_value=False):
            state = self.controller.drain()
        self.assertEqual("DRAINING", state["state"])
        self.assertEqual("DRAIN_REQUESTED", state["reason"])
        self.assertIsNone(state["run_id"])
        self.assertIsNone(state["qemu_pid"])

    def test_prelaunch_draining_converges_to_stopped_after_lock_released(self):
        self.controller.ensure_roots()
        self.controller.write_state("DRAINING", reason="DRAIN_REQUESTED")
        with mock.patch.object(self.controller, "_guest_lock_available", return_value=True):
            state = self.controller.drain()
        self.assertEqual("STOPPED", state["state"])

    def test_drain_stopped_does_not_infer_active_guest_from_busy_lock(self):
        self.controller.ensure_roots()
        self.controller.write_state("STOPPED")
        with mock.patch.object(self.controller, "_guest_lock_available", return_value=False):
            state = self.controller.drain()
        self.assertEqual("STOPPED", state["state"])

    def test_drain_running_never_kills_process(self):
        self.controller.ensure_roots()
        run_id = "11111111-1111-4111-8111-111111111111"
        self.controller.write_state("RUNNING", run_id=run_id, qemu_pid=999999)
        with mock.patch.object(mod.os, "kill") as kill:
            state = self.controller.drain()
        self.assertEqual("DRAINING", state["state"])
        self.assertEqual("DRAIN_REQUESTED", state["reason"])
        kill.assert_not_called()

    def test_drain_does_not_clear_hold(self):
        self.controller.ensure_roots()
        self.controller.write_state("HOLD", reason="RECOVERY_UNCERTAIN")
        state = self.controller.drain()
        self.assertEqual("HOLD", state["state"])
        self.assertEqual("RECOVERY_UNCERTAIN", state["reason"])

    def test_state_rejects_unknown_fields(self):
        self.controller.ensure_roots()
        self.controller.write_state("STOPPED")
        payload = json.loads(self.controller.state_path.read_text())
        payload["secret"] = "nope"
        self.controller.state_path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(mod.DragonflyError, "STATE_FIELDS_INVALID"):
            self.controller.read_state()

    def test_state_rejects_invalid_identity_and_pid_types(self):
        self.controller.ensure_roots()
        payload = {
            "schema": mod.STATE_SCHEMA,
            "marker": mod.MARKER,
            "state": "STOPPED",
            "updated_at": None,
            "run_id": "11111111-1111-4111-8111-111111111111",
            "qemu_pid": "1234",
            "reason": None,
        }
        self.controller.state_path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(mod.DragonflyError, "STATE_PID_INVALID"):
            self.controller.read_state()
        with self.assertRaisesRegex(mod.DragonflyError, "STATE_IDENTITY_INVALID"):
            self.controller.write_state("RUNNING")

    def test_status_projects_stale_residue_as_hold_without_deleting(self):
        self.controller.ensure_roots()
        self.controller.write_state("STOPPED")
        residue = self.controller.runs_root / "11111111-1111-4111-8111-111111111111"
        residue.mkdir()
        with mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()):
            status = self.controller.status()
        self.assertEqual("HOLD", status["state"])
        self.assertEqual("STALE_RUN_STATE", status["reason"])
        self.assertTrue(residue.exists())

    def test_status_projects_run_root_contamination_as_hold(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        contaminant = self.controller.runs_root / "unexpected-file"
        contaminant.write_text("x")
        with mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()):
            status = self.controller.status()
        self.assertEqual("HOLD", status["state"])
        self.assertEqual("RUN_ROOT_CONTAMINATED", status["reason"])
        self.assertEqual(-1, status["residue_count"])
        self.assertTrue(contaminant.exists())

    def _mock_smoke_dependencies(self):
        return (
            mock.patch.object(self.controller, "verify_base", return_value={}),
            mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()),
            mock.patch.object(mod.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(mod, "_pid_alive", return_value=False),
        )

    def test_smoke_qemu_contract_has_kvm_no_inbound_forward_or_host_mount(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        popen = mock.Mock()
        popen.pid = 4242
        popen.wait.return_value = 0
        calls = []
        kwargs_seen = []

        def capture(command, **kwargs):
            calls.append(command)
            kwargs_seen.append(kwargs)
            return popen

        verify, resources, which, pid_alive = self._mock_smoke_dependencies()
        with verify, resources, which, pid_alive, \
             mock.patch.object(mod.subprocess, "run") as run, \
             mock.patch.object(mod.subprocess, "Popen", side_effect=capture):
            result = self.controller.smoke()

        self.assertEqual("PASS", result["result"])
        self.assertEqual(1, len(calls))
        command = calls[0]
        joined = " ".join(str(part) for part in command)
        self.assertIn("-accel kvm", joined)
        self.assertIn("-netdev user,id=net0", joined)
        self.assertIn("-pidfile", command)
        self.assertNotIn("hostfwd", joined)
        self.assertNotIn("virtiofs", joined)
        self.assertNotIn("9p", joined)
        self.assertIs(kwargs_seen[0]["preexec_fn"], mod._set_parent_death_signal)
        self.assertEqual(2, run.call_count)
        self.assertEqual("AVAILABLE", self.controller.read_state()["state"])
        self.assertEqual([], list(self.controller.runs_root.iterdir()))

    def test_smoke_honors_prelaunch_drain_without_spawning_qemu(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        calls = 0

        def prepare(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.controller.drain()
            return mock.Mock(returncode=0)

        verify, resources, which, pid_alive = self._mock_smoke_dependencies()
        with verify, resources, which, pid_alive, \
             mock.patch.object(mod.subprocess, "run", side_effect=prepare), \
             mock.patch.object(mod.subprocess, "Popen") as popen:
            result = self.controller.smoke()

        self.assertEqual("DRAINED", result["result"])
        popen.assert_not_called()
        self.assertEqual("STOPPED", self.controller.read_state()["state"])
        self.assertEqual([], list(self.controller.runs_root.iterdir()))

    def test_smoke_failure_during_drain_remains_failed(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        popen = mock.Mock()
        popen.pid = 4242

        def fail_after_drain(*_args, **_kwargs):
            self.controller.drain()
            return 1

        popen.wait.side_effect = fail_after_drain
        verify, resources, which, pid_alive = self._mock_smoke_dependencies()
        with verify, resources, which, pid_alive, \
             mock.patch.object(mod.subprocess, "run"), \
             mock.patch.object(mod.subprocess, "Popen", return_value=popen):
            with self.assertRaisesRegex(mod.DragonflyError, "QEMU_NONZERO_EXIT"):
                self.controller.smoke()

        state = self.controller.read_state()
        self.assertEqual("FAILED", state["state"])
        self.assertEqual("SMOKE_FAILED", state["reason"])
        self.assertEqual([], list(self.controller.runs_root.iterdir()))

    def test_smoke_refuses_preexisting_residue(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        (self.controller.runs_root / "11111111-1111-4111-8111-111111111111").mkdir()
        with mock.patch.object(self.controller, "verify_base", return_value={}), \
             mock.patch.object(mod, "resource_snapshot", return_value=self.admitted_snapshot()), \
             mock.patch.object(mod.shutil, "which", return_value="/usr/bin/tool"):
            with self.assertRaisesRegex(mod.DragonflyError, "STALE_RUN_STATE_REFUSED"):
                self.controller.smoke()

    def _make_owned_run(self, *, qemu_pid=None):
        self.controller.ensure_roots()
        run_id, run_dir, overlay, seed, user_data, pidfile, _manifest = self.controller._new_run()
        overlay.write_bytes(b"")
        seed.write_bytes(b"")
        user_data.write_text("#cloud-config\n")
        self.controller._write_manifest(run_id, run_dir, overlay, seed, pidfile, qemu_pid=qemu_pid)
        return run_id, run_dir, overlay, seed, user_data, pidfile

    def test_cleanup_refuses_unknown_artifact(self):
        _run_id, run_dir, _overlay, _seed, _user_data, _pidfile = self._make_owned_run()
        (run_dir / "unexpected").write_text("x")
        with self.assertRaisesRegex(mod.DragonflyError, "UNKNOWN_RUN_ARTIFACT_REFUSED"):
            self.controller._cleanup_owned_run(run_dir)

    def test_cleanup_refuses_live_owned_pid(self):
        _run_id, run_dir, _overlay, _seed, _user_data, _pidfile = self._make_owned_run(qemu_pid=1234)
        with mock.patch.object(mod, "_pid_alive", side_effect=lambda pid: pid == 1234):
            with self.assertRaisesRegex(mod.DragonflyError, "LIVE_GUEST_CLEANUP_REFUSED"):
                self.controller._cleanup_owned_run(run_dir)

    def test_cleanup_refuses_live_pidfile_even_before_manifest_pid_update(self):
        _run_id, run_dir, _overlay, _seed, _user_data, pidfile = self._make_owned_run()
        pidfile.write_text("4321\n")
        with mock.patch.object(mod, "_pid_alive", side_effect=lambda pid: pid == 4321):
            with self.assertRaisesRegex(mod.DragonflyError, "LIVE_GUEST_CLEANUP_REFUSED"):
                self.controller._cleanup_owned_run(run_dir)

    def test_invalid_pidfile_fails_closed(self):
        _run_id, run_dir, _overlay, _seed, _user_data, pidfile = self._make_owned_run()
        pidfile.write_text("not-a-pid\n")
        with self.assertRaisesRegex(mod.DragonflyError, "PIDFILE_INVALID"):
            self.controller._cleanup_owned_run(run_dir)

    def test_recover_refuses_multiple_run_directories_and_holds(self):
        self.controller.ensure_roots()
        (self.controller.runs_root / "11111111-1111-4111-8111-111111111111").mkdir()
        (self.controller.runs_root / "22222222-2222-4222-8222-222222222222").mkdir()
        with self.assertRaisesRegex(mod.DragonflyError, "MULTIPLE_RUN_DIRS"):
            self.controller.recover()
        self.assertEqual("HOLD", self.controller.read_state()["state"])
        self.assertEqual("RECOVERY_UNCERTAIN", self.controller.read_state()["reason"])

    def test_recover_refuses_missing_manifest_and_holds(self):
        self.controller.ensure_roots()
        (self.controller.runs_root / "11111111-1111-4111-8111-111111111111").mkdir()
        with self.assertRaisesRegex(mod.DragonflyError, "OWNERSHIP_MANIFEST_REQUIRED"):
            self.controller.recover()
        self.assertEqual("HOLD", self.controller.read_state()["state"])

    def test_recover_refuses_malformed_manifest_and_holds(self):
        self.controller.ensure_roots()
        run_dir = self.controller.runs_root / "11111111-1111-4111-8111-111111111111"
        run_dir.mkdir()
        (run_dir / "ownership.json").write_text("{")
        with self.assertRaisesRegex(mod.DragonflyError, "JSON_READ_INVALID"):
            self.controller.recover()
        self.assertEqual("HOLD", self.controller.read_state()["state"])
        self.assertEqual("RECOVERY_UNCERTAIN", self.controller.read_state()["reason"])

    def test_recover_refuses_live_owned_pid_and_holds(self):
        _run_id, _run_dir, _overlay, _seed, _user_data, _pidfile = self._make_owned_run(qemu_pid=1234)
        with mock.patch.object(mod, "_pid_alive", side_effect=lambda pid: pid == 1234):
            with self.assertRaisesRegex(mod.DragonflyError, "LIVE_GUEST_CLEANUP_REFUSED"):
                self.controller.recover()
        self.assertEqual("HOLD", self.controller.read_state()["state"])

    def test_recover_refuses_live_state_pid_without_run_directory(self):
        self.controller.ensure_roots()
        run_id = "11111111-1111-4111-8111-111111111111"
        self.controller.write_state("RUNNING", run_id=run_id, qemu_pid=5678)
        with mock.patch.object(mod, "_pid_alive", side_effect=lambda pid: pid == 5678):
            with self.assertRaisesRegex(mod.DragonflyError, "LIVE_STATE_PID_REFUSED"):
                self.controller.recover()
        state = self.controller.read_state()
        self.assertEqual("HOLD", state["state"])
        self.assertEqual("RECOVERY_LIVE_STATE", state["reason"])
        self.assertEqual(run_id, state["run_id"])
        self.assertEqual(5678, state["qemu_pid"])

    def test_recover_always_converges_available_to_stopped(self):
        self.controller.ensure_roots()
        self.controller.write_state("AVAILABLE")
        result = self.controller.recover()
        self.assertEqual("STOPPED", result["state"])
        state = self.controller.read_state()
        self.assertEqual("STOPPED", state["state"])
        self.assertEqual("RECOVERED", state["reason"])

    def test_successful_recovery_converges_failed_to_stopped(self):
        self.controller.ensure_roots()
        self.controller.write_state("FAILED", reason="SMOKE_FAILED")
        result = self.controller.recover()
        self.assertEqual("STOPPED", result["state"])
        state = self.controller.read_state()
        self.assertEqual("STOPPED", state["state"])
        self.assertEqual("RECOVERED", state["reason"])


if __name__ == "__main__":
    unittest.main()
