import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("canary_executor", ROOT / "canary_executor.py")
executor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor)


class FakeProcess:
    def __init__(self):
        self.pid = 4242
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        self._alive = False
        return 0

    def terminate(self):
        self._alive = False

    def kill(self):
        self._alive = False


class UnkillableProcess:
    def __init__(self):
        self.pid = 5252

    def poll(self):
        return None

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired("qemu", timeout or 1)

    def terminate(self):
        return None

    def kill(self):
        return None


def fake_controller_module(root: Path, *, state="AVAILABLE"):
    module = types.SimpleNamespace(
        GUEST_CPUS=2,
        GUEST_MEMORY_MIB=2048,
        _set_parent_death_signal=lambda: None,
        cleanup_calls=0,
        last_controller=None,
    )
    module.resource_snapshot = lambda _: {
        "mem_available_mib": 16384,
        "load_fraction": 0.01,
        "free_disk_gib": 64,
        "visible_cpus": 12,
    }
    module.assert_admission = lambda _: None

    @contextlib.contextmanager
    def file_lock(_, *, blocking=False):
        yield object()

    module._file_lock = file_lock

    class Controller:
        def __init__(self, *, data_root=None, state_root=None):
            self.state_root = Path(state_root or root / "state")
            self.data_root = Path(data_root or root / "data")
            self.base_path = self.data_root / "base" / "debian.qcow2"
            self.runs_root = self.state_root / "runs"
            self.guest_lock_path = self.state_root / "guest.lock"
            self.state_lock_path = self.state_root / "state.lock"
            self._state = state
            self.last_kwargs = {}
            module.last_controller = self

        def ensure_roots(self):
            self.runs_root.mkdir(parents=True, exist_ok=True)
            self.base_path.parent.mkdir(parents=True, exist_ok=True)
            self.base_path.write_bytes(b"base")

        def verify_base(self):
            return {"ok": True}

        def read_state(self):
            return {"state": self._state, "run_id": self.last_kwargs.get("run_id"), "qemu_pid": self.last_kwargs.get("qemu_pid")}

        def write_state(self, state_value, **kwargs):
            self._state = state_value
            self.last_kwargs = dict(kwargs)
            return {"state": state_value, **kwargs}

        def _run_dirs(self):
            return [path for path in self.runs_root.iterdir() if path.is_dir()]

        def _new_run(self):
            run_id = "11111111-1111-4111-8111-111111111111"
            directory = self.runs_root / run_id
            directory.mkdir()
            return (
                run_id,
                directory,
                directory / "guest.qcow2",
                directory / "seed.img",
                directory / "user-data",
                directory / "qemu.pid",
                directory / "ownership.json",
            )

        def _write_manifest(self, run_id, run_dir, overlay, seed, pidfile, qemu_pid=None):
            (run_dir / "ownership.json").write_text(
                json.dumps({"run_id": run_id, "overlay": str(overlay), "seed": str(seed), "pidfile": str(pidfile), "qemu_pid": qemu_pid}),
                encoding="utf-8",
            )
            if qemu_pid is not None:
                pidfile.write_text(str(qemu_pid), encoding="ascii")

        def _validate_manifest(self, run_dir):
            return json.loads((run_dir / "ownership.json").read_text(encoding="utf-8"))

        def _cleanup_owned_run(self, run_dir):
            module.cleanup_calls += 1
            for child in list(run_dir.iterdir()):
                child.unlink()
            run_dir.rmdir()

    module.Controller = Controller
    return module


class CanaryExecutorTests(unittest.TestCase):
    def payload_and_summary(self):
        payload = {
            "dispatch_id": "11111111-1111-4111-8111-111111111111",
            "target_host": "dragonfly-redrix-01",
            "profile_id": executor.PROFILE_ID,
            "repository": "LowcountryDigitalWorks/infrastructure-tools",
            "workflow": ".github/workflows/dragonfly-jit-canary.yml",
            "run_id": 123,
            "run_attempt": 2,
            "job_id": 456,
            "head_sha": "a" * 40,
            "job_name": "dragonfly-canary",
            "labels": ["self-hosted","Linux","X64","dragonfly","jit","ldw-ephemeral","synthetic-only","dragonfly-run-123","dragonfly-attempt-2"],
            "issued_at": "2026-10-29T08:00:00Z",
            "expires_at": "2026-10-29T08:04:00Z",
            "opaque_bootstrap": "QUJDREVGR0g=",
        }
        summary = {key: value for key, value in payload.items() if key != "opaque_bootstrap"}
        summary["bootstrap_present"] = True
        return payload, summary

    def test_pins_current_controller_and_guest_assets(self):
        self.assertTrue(hasattr(executor._load_controller(), "Controller"))
        assets = executor._load_guest_assets(ROOT)
        self.assertIn("run.sh", assets["run-one.sh"])
        self.assertIn("ExecStopPost", assets["ci7-runner.service"])

    def test_user_data_never_contains_plaintext_bootstrap(self):
        assets = {name: "synthetic guest asset" for name in executor.ASSET_SPECS}
        bootstrap = "QUJDREVGR0g="
        user_data = executor.build_user_data(bootstrap=bootstrap, run_id="run-123", assets=assets)
        self.assertNotIn(bootstrap, user_data)
        self.assertIn(base64.b64encode(bootstrap.encode()).decode(), user_data)

    def test_execution_inputs_require_exact_summary_binding(self):
        payload, summary = self.payload_and_summary()
        self.assertEqual(executor._validate_execution_inputs(payload, summary), payload["opaque_bootstrap"])
        summary["job_id"] += 1
        with self.assertRaisesRegex(executor.CanaryExecutorError, "CANARY_IDENTITY_MISMATCH"):
            executor._validate_execution_inputs(payload, summary)

    @staticmethod
    def fake_run(command, **kwargs):
        if command[0] == "qemu-img":
            Path(command[-2]).write_bytes(b"overlay")
        elif command[0] == "cloud-localds":
            Path(command[1]).write_bytes(b"seed")
        return types.SimpleNamespace(returncode=0)

    def test_mocked_one_guest_execution_cleans_owned_run_and_stops(self):
        payload, summary = self.payload_and_summary()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            with mock.patch.object(executor.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(executor, "_load_guest_assets", return_value={name: "synthetic asset" for name in executor.ASSET_SPECS}), \
                 mock.patch.object(executor.subprocess, "run", side_effect=self.fake_run), \
                 mock.patch.object(executor.subprocess, "Popen", return_value=FakeProcess()):
                result = executor.execute_canary(payload, summary, state_root=root / "state", data_root=root / "data", controller_module=module, source_root=ROOT)
            self.assertEqual(result["state"], "STOPPED")
            self.assertEqual(list((root / "state" / "runs").iterdir()), [])

    def test_manifest_precedes_bootstrap_and_failure_is_recoverably_cleaned(self):
        payload, summary = self.payload_and_summary()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            with mock.patch.object(executor.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(executor, "_load_guest_assets", return_value={name: "synthetic asset" for name in executor.ASSET_SPECS}), \
                 mock.patch.object(executor, "build_user_data", side_effect=RuntimeError("interrupt-after-manifest")):
                with self.assertRaisesRegex(RuntimeError, "interrupt-after-manifest"):
                    executor.execute_canary(payload, summary, state_root=root / "state", data_root=root / "data", controller_module=module, source_root=ROOT)
            self.assertEqual(module.cleanup_calls, 1)
            self.assertEqual(list((root / "state" / "runs").iterdir()), [])
            self.assertEqual(module.last_controller._state, "STOPPED")

    def test_unconfirmed_guest_termination_preserves_ownership_and_holds(self):
        payload, summary = self.payload_and_summary()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            process = UnkillableProcess()
            with mock.patch.object(executor.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(executor, "_load_guest_assets", return_value={name: "synthetic asset" for name in executor.ASSET_SPECS}), \
                 mock.patch.object(executor.subprocess, "run", side_effect=self.fake_run), \
                 mock.patch.object(executor.subprocess, "Popen", return_value=process):
                with self.assertRaisesRegex(executor.CanaryExecutorError, "CANARY_GUEST_TERMINATION_UNCERTAIN"):
                    executor.execute_canary(payload, summary, state_root=root / "state", data_root=root / "data", controller_module=module, source_root=ROOT, timeout_seconds=1)
            runs = list((root / "state" / "runs").iterdir())
            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0] / "ownership.json").exists())
            self.assertTrue((runs[0] / "qemu.pid").exists())
            self.assertTrue((runs[0] / "guest.qcow2").exists())
            self.assertFalse((runs[0] / "user-data").exists())
            self.assertFalse((runs[0] / "seed.img").exists())
            manifest = module.last_controller._validate_manifest(runs[0])
            self.assertEqual(manifest["qemu_pid"], process.pid)
            for value in (json.dumps(manifest), json.dumps(module.last_controller.read_state()), json.dumps(summary)):
                self.assertNotIn(payload["opaque_bootstrap"], value)
                self.assertNotIn(base64.b64encode(payload["opaque_bootstrap"].encode()).decode(), value)
            self.assertEqual(module.cleanup_calls, 0)
            self.assertEqual(module.last_controller._state, "HOLD")
            self.assertEqual(module.last_controller.last_kwargs.get("qemu_pid"), process.pid)

    def test_prelaunch_not_available_creates_no_run(self):
        payload, summary = self.payload_and_summary()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root, state="STOPPED")
            with mock.patch.object(executor.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(executor, "_load_guest_assets", return_value={name: "synthetic asset" for name in executor.ASSET_SPECS}):
                with self.assertRaisesRegex(executor.CanaryExecutorError, "CANARY_HOST_NOT_AVAILABLE"):
                    executor.execute_canary(payload, summary, state_root=root / "state", data_root=root / "data", controller_module=module, source_root=ROOT)
            self.assertEqual(list((root / "state" / "runs").iterdir()), [])

    def test_sensitive_unlink_preserves_ownership_and_refuses_wrong_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            controller = module.Controller()
            controller.ensure_roots()
            run_id, directory, overlay, seed, user, pidfile, manifest = controller._new_run()
            controller._write_manifest(run_id, directory, overlay, seed, pidfile, qemu_pid=5252)
            overlay.write_bytes(b"overlay")
            seed.write_bytes(b"synthetic bootstrap-equivalent seed")
            user.write_bytes(b"synthetic bootstrap-equivalent user-data")
            saved_manifest = manifest.read_bytes()
            saved_pid = pidfile.read_bytes()
            executor._remove_owned_bootstrap_material(controller, run_id, directory)
            executor._remove_owned_bootstrap_material(controller, run_id, directory)
            self.assertFalse(seed.exists())
            self.assertFalse(user.exists())
            self.assertEqual(manifest.read_bytes(), saved_manifest)
            self.assertEqual(pidfile.read_bytes(), saved_pid)
            self.assertTrue(overlay.exists())
            self.assertEqual(module.cleanup_calls, 0)
            outside = root / "outside-seed"
            outside.write_bytes(b"must survive")
            record = json.loads(saved_manifest)
            record["seed"] = str(outside)
            manifest.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(executor.CanaryExecutorError, "OWNERSHIP_INVALID"):
                executor._remove_owned_bootstrap_material(controller, run_id, directory)
            self.assertEqual(outside.read_bytes(), b"must survive")

    def test_unconfirmed_guest_with_sensitive_unlink_failure_still_holds(self):
        payload, summary = self.payload_and_summary()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            with mock.patch.object(executor.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(executor, "_load_guest_assets", return_value={name: "synthetic asset" for name in executor.ASSET_SPECS}), \
                 mock.patch.object(executor.subprocess, "run", side_effect=self.fake_run), \
                 mock.patch.object(executor.subprocess, "Popen", return_value=UnkillableProcess()), \
                 mock.patch.object(executor, "_remove_owned_bootstrap_material", side_effect=OSError("synthetic unlink failure")):
                with self.assertRaisesRegex(executor.CanaryExecutorError, "CANARY_GUEST_TERMINATION_UNCERTAIN"):
                    executor.execute_canary(payload, summary, controller_module=module, timeout_seconds=1)
            self.assertEqual(module.cleanup_calls, 0)
            self.assertEqual(module.last_controller._state, "HOLD")
            self.assertEqual(module.last_controller.last_kwargs["reason"], "CANARY_SENSITIVE_CLEANUP_UNCERTAIN")
            self.assertEqual(len(module.last_controller._run_dirs()), 1)

    @unittest.skipIf(os.name == "nt", "POSIX open-FD unlink semantics require Linux")
    def test_sensitive_seed_unlink_keeps_open_fd_and_ownership_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = fake_controller_module(root)
            controller = module.Controller()
            controller.ensure_roots()
            run_id, directory, overlay, seed, user, pidfile, manifest = controller._new_run()
            controller._write_manifest(run_id, directory, overlay, seed, pidfile, qemu_pid=5252)
            overlay.write_bytes(b"overlay")
            seed.write_bytes(b"synthetic seed")
            with seed.open("rb") as guest_fd:
                executor._remove_owned_bootstrap_material(controller, run_id, directory)
                self.assertFalse(seed.exists())
                self.assertEqual(guest_fd.read(), b"synthetic seed")
            self.assertTrue(overlay.exists())
            self.assertTrue(pidfile.exists())
            self.assertEqual(controller._validate_manifest(directory)["qemu_pid"], 5252)
            self.assertEqual(module.cleanup_calls, 0)


if __name__ == "__main__":
    unittest.main()
