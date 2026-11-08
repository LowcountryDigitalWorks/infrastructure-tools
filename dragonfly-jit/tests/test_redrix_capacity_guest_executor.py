#!/usr/bin/env python3
"""Synthetic executor tests; no real QEMU."""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import json
import sys
import tempfile
from unittest import mock
from io import StringIO
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "redrix_capacity_guest_executor.py"
CONTROLLER = ROOT / "dragonfly_jit.py"


def load():
    spec = importlib.util.spec_from_file_location("redrix_capacity_guest_executor", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


exe = load()


def clean_preflight(**overrides) -> exe.PreflightObservation:
    base = exe.PreflightObservation(
        mem_available_mib=[9400, 9400, 9400],
        psi_some_full=[(0.0, 0.0), (0.0, 0.0), (0.0, 0.0)],
        balloon_inflate=[100, 100, 100],
        oom_before=(0, 0),
        load_fraction=0.1,
        free_disk_gib=32,
        kvm_rw=True,
        qemu_present=False,
        controller_state="STOPPED",
        lock_busy=False,
        residue_runs=0,
        symlink_refused=False,
        controller_blob=exe.EXPECTED_CONTROLLER_BLOB,
        base_sha512=exe.EXPECTED_BASE_SHA512,
        uid=1000,
        memory_events_path="/sys/fs/cgroup/user.slice/memory.events",
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


class FakeProcess:
    def __init__(self, *, serial_path: Path, nonce: str, rss: int = 400_000, exit_code: int = 0):
        self.pid = 4242
        self.starttime = 99
        self._serial_path = serial_path
        self._nonce = nonce
        self._rss = rss
        self._exit_code = exit_code
        self._done = False

    def poll(self) -> int | None:
        if self._done:
            return self._exit_code
        self._done = True
        line = f"{exe.SUCCESS_PREFIX} nonce={self._nonce}\n"
        self._serial_path.write_text(line, encoding="utf-8")
        return self._exit_code

    def terminate(self) -> None:
        self._done = True

    def kill(self) -> None:
        self._done = True
        self._exit_code = 137

    def wait(self, timeout: float | None = None) -> int:
        return self._exit_code


class SilentProcess(FakeProcess):
    def poll(self) -> int | None:
        if self._done:
            return self._exit_code
        self._done = True
        return self._exit_code


def make_ctx(
    tmp: Path,
    *,
    preflight: exe.PreflightObservation | None = None,
    process: FakeProcess | None = None,
    lock_busy: bool = False,
) -> exe.RunContext:
    @contextlib.contextmanager
    def _lock(_path: Path):
        if lock_busy:
            raise exe.GuestLockBusy
        yield

    (tmp / "runs").mkdir(exist_ok=True)
    (tmp / "status.json").write_text(
        json.dumps(
            {
                "schema": exe.CONTROLLER_STATE_SCHEMA,
                "marker": exe.CONTROLLER_STATE_MARKER,
                "state": "STOPPED",
                "updated_at": None,
                "run_id": None,
                "qemu_pid": None,
                "reason": None,
            }
        ),
        encoding="utf-8",
    )

    def _prep(_ctx, work_root, overlay, seed, user_data, serial_path, nonce_hex):
        del work_root, overlay, seed, user_data, serial_path, nonce_hex
        return None

    proc = process

    def _factory(_argv):
        assert proc is not None
        return proc

    hooks = exe.ExecutorHooks(
        uid=lambda: 1000,
        sleep=lambda _s: None,
        now=lambda: 0.0,
        make_work_root=lambda: tmp,
        acquire_guest_lock=_lock,
        prepare_guest_artifacts=_prep,
        read_proc_status=lambda _pid: proc._rss if proc else None,
        read_proc_starttime=lambda _pid: proc.starttime if proc else None,
        read_oom=lambda _path: (0, 0),
        workload_host_check=lambda: None,
    )
    return exe.RunContext(
        hooks=hooks,
        guest_lock_path=tmp / "guest.lock",
        state_lock_path=tmp / "state.lock",
        controller_path=CONTROLLER,
        base_image_path=tmp / "base.qcow2",
        state_path=tmp / "status.json",
        runs_root=tmp / "runs",
        qemu_factory=_factory,
        preflight_observation=preflight or clean_preflight(),
    )


class GuestExecutorTests(unittest.TestCase):
    def assert_never_admits(self, report: dict) -> None:
        self.assertFalse(report["jit_admission_authorized"])
        self.assertFalse(report["provider_admission_authorized"])
        self.assertFalse(report["production_policy_changed"])
        self.assertEqual(report["production_reserve_mib"], 8192)

    def test_controller_pin_matches_live_source(self):
        identity = exe.read_controller_identity(CONTROLLER)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["blob"], exe.EXPECTED_CONTROLLER_BLOB)

    def test_cli_refuses_extra_argv_and_default(self):
        buf = StringIO()
        import sys
        from contextlib import redirect_stdout

        with redirect_stdout(buf):
            self.assertEqual(exe.main([]), 2)
        self.assertIn("CLI_REFUSED", buf.getvalue())
        with redirect_stdout(buf := StringIO()):
            self.assertEqual(exe.main(["--run-once-local", "--evil"]), 2)

    def test_main_run_once_is_no_start(self):
        buf = StringIO()
        from contextlib import redirect_stdout

        with redirect_stdout(buf):
            self.assertEqual(exe.main(["--run-once-local"]), 2)
        self.assertIn("RUNTIME_NO_START", buf.getvalue())

    def test_no_subprocess_import_at_module_level(self):
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imports = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        self.assertNotIn("subprocess", imports)

    def test_discover_cgroup_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as root:
            cgroup = Path(root) / "proc-self-cgroup"
            cgroup.write_text("0::/../../etc\n", encoding="ascii")
            self.assertIsNone(
                exe.discover_memory_events_path(cgroup, Path(root) / "sys-fs-cgroup")
            )

    def test_discover_cgroup_ignores_v1_lines(self):
        with tempfile.TemporaryDirectory() as root:
            cgroup = Path(root) / "proc-self-cgroup"
            cgroup.write_text("1:memory:/user.slice\n", encoding="ascii")
            self.assertIsNone(exe.discover_memory_events_path(cgroup, Path(root) / "cgroup"))

    def test_finite_load_rejects_nan(self):
        self.assertIsNone(exe._finite_load(float("nan")))
        obs = clean_preflight(load_fraction=float("nan"))
        self.assertEqual(exe.assess_preflight(obs), "CAPACITY_CPU")

    def test_balloon_nonmonotonic_hold(self):
        obs = clean_preflight(balloon_inflate=[5, 4, 4])
        self.assertEqual(exe.assess_preflight(obs), "BALLOON_NONMONOTONIC")

    def test_balloon_inflation_rejected(self):
        obs = clean_preflight(balloon_inflate=[1, 1, 2])
        self.assertEqual(exe.assess_preflight(obs), "BALLOON_INFLATION")

    def test_preflight_matrix(self):
        cases = (
            ({"uid": 0}, "UID_REFUSED"),
            ({"symlink_refused": True}, "SYMLINK_REFUSED"),
            ({"controller_blob": "0" * 40}, "CONTROLLER_BLOB_MISMATCH"),
            ({"qemu_present": True}, "QEMU_ALREADY_PRESENT"),
            ({"controller_state": "RUNNING"}, "CONTROLLER_STATE_REFUSED"),
            ({"residue_runs": 1}, "CONTROLLER_RUNS_RESIDUE"),
            ({"mem_available_mib": [8000, 9000, 9000]}, "RESEARCH_MEMORY_FLOOR"),
            ({"psi_some_full": [(0.0, 0.0), (0.1, 0.0), (0.0, 0.0)]}, "PSI_UNSTABLE"),
            ({"memory_events_path": ""}, "OOM_COUNTER_UNAVAILABLE"),
            ({"kvm_rw": False}, "KVM_NOT_READY"),
        )
        for overrides, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(exe.assess_preflight(clean_preflight(**overrides)), reason)

    def test_fixed_qemu_argv_has_no_network(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            overlay = base / "guest.qcow2"
            seed = base / "seed.img"
            serial = base / "serial.log"
            overlay.touch()
            seed.touch()
            serial.touch()
            argv = exe.fixed_qemu_argv(overlay, seed, serial)
            self.assertIsNotNone(argv)
            self.assertIn("-nic", argv)
            self.assertEqual(argv[argv.index("-nic") + 1], "none")
            self.assertNotIn("-netdev", argv)

    def test_success_marker_requires_exact_nonce_line(self):
        nonce = "aa" * 16
        good = f"{exe.SUCCESS_PREFIX} nonce={nonce}\n"
        self.assertTrue(exe.parse_success_line(good, nonce))
        self.assertFalse(exe.parse_success_line(good + good, nonce))
        self.assertFalse(exe.parse_success_line("LDW_REDRIX_GUEST_BENCH_OK nonce=x", nonce))

    def test_workload_touches_each_page_and_ttys0(self):
        script = exe.guest_workload_shell_body("abcd")
        self.assertIn("page[i]=1", script)
        self.assertIn("/dev/ttyS0", script)
        config = exe.build_cloud_config("c" * 32)
        self.assertIn("write_files:", config)
        self.assertNotIn("python3, -c", config)

    def test_mocked_run_success_not_authorized(self):
        with tempfile.TemporaryDirectory() as root:
            tmp = Path(root)
            nonce = "b" * 32
            serial = tmp / "serial.log"
            proc = FakeProcess(serial_path=serial, nonce=nonce, rss=900_000)
            ctx = make_ctx(tmp, process=proc)
            clock = {"t": 0.0}

            def _now() -> float:
                clock["t"] += 0.2
                return clock["t"]

            ctx.hooks.now = _now
            (tmp / "guest.qcow2").touch()
            (tmp / "seed.img").touch()
            (tmp / "user-data").touch()
            with mock.patch.object(exe.secrets, "token_hex", return_value=nonce):
                report = exe.run_once_local(ctx)
            self.assertEqual(report["classification"], "LOCAL_SYNTHETIC_MEASURED_NOT_AUTHORIZED")
            self.assertTrue(report["physical_guest_executed"])
            self.assert_never_admits(report)

    def test_serial_spoof_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            tmp = Path(root)
            serial = tmp / "serial.log"
            nonce = "c" * 32

            def _prep(_ctx, _w, _o, _s, _u, serial_path, _nonce_hex):
                serial_path.write_text(f"{exe.SUCCESS_PREFIX} nonce=deadbeef\n", encoding="utf-8")
                return None

            proc = SilentProcess(serial_path=serial, nonce=nonce, rss=900_000)
            ctx = make_ctx(tmp, process=proc)
            ctx.hooks.prepare_guest_artifacts = _prep
            (tmp / "guest.qcow2").touch()
            (tmp / "seed.img").touch()
            with mock.patch.object(exe.secrets, "token_hex", return_value=nonce):
                report = exe.run_once_local(ctx)
            self.assertEqual(report["reason"], "SUCCESS_MARKER_MISSING")

    def test_rss_insufficient_hold(self):
        with tempfile.TemporaryDirectory() as root:
            tmp = Path(root)
            serial = tmp / "serial.log"
            nonce = "d" * 32
            proc = FakeProcess(serial_path=serial, nonce=nonce, rss=1000, exit_code=0)
            ctx = make_ctx(tmp, process=proc)
            (tmp / "guest.qcow2").touch()
            (tmp / "seed.img").touch()
            (tmp / "user-data").touch()
            with mock.patch.object(exe.secrets, "token_hex", return_value=nonce):
                report = exe.run_once_local(ctx)
            self.assertEqual(report["reason"], "QEMU_RSS_INSUFFICIENT")

    def test_guest_lock_busy(self):
        with tempfile.TemporaryDirectory() as root:
            ctx = make_ctx(Path(root), lock_busy=True)
            self.assertEqual(exe.run_once_local(ctx)["reason"], "GUEST_LOCK_BUSY")

    def test_executor_port_missing_without_factory(self):
        with tempfile.TemporaryDirectory() as root:
            ctx = make_ctx(Path(root))
            ctx.qemu_factory = None
            self.assertEqual(exe.run_once_local(ctx)["reason"], "EXECUTOR_PORT_NOT_LIVE")

    def test_controller_state_unavailable_on_missing(self):
        with tempfile.TemporaryDirectory() as root:
            tmp = Path(root)
            self.assertEqual(
                exe.read_controller_runtime_state(tmp / "missing.json", tmp / "runs"),
                "CONTROLLER_STATE_UNAVAILABLE",
            )

    def test_cleanup_refuses_symlink_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            tmp = Path(root)
            (tmp / "evil").touch()
            try:
                (tmp / "link").symlink_to(tmp / "evil")
                self.assertFalse(exe.cleanup_work_root(tmp))
            except OSError:
                self.skipTest("symlink privilege unavailable")

    def test_json_has_no_runner_tokens(self):
        report = exe._report()
        blob = json.dumps(report).lower()
        self.assertNotIn("github_token", blob)
        self.assertNotIn("jitconfig", blob)
        self.assertNotIn("admission_token", blob)


if __name__ == "__main__":
    unittest.main()
