import importlib.util
import io
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "bridge_adapter.py"
SPEC = importlib.util.spec_from_file_location("bridge_adapter", MODULE_PATH)
ba = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ba)


def git_blob_sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


class Completed:
    def __init__(self, *, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class BridgeAdapterTests(unittest.TestCase):
    def request(self, op, args=None):
        return {"operation": op, "arguments": {} if args is None else args}

    def make_controller(self, root: Path, data=b"synthetic-controller"):
        home = root / "home"
        controller = home / ba.INSTALL_RELATIVE
        controller.parent.mkdir(parents=True)
        controller.write_bytes(data)
        return home, controller, data

    def invoke(self, request, **kwargs):
        return ba._invoke_with_dependencies(
            request,
            python_path=ba.PYTHON_PATH,
            **kwargs,
        )

    def test_public_invoke_has_no_runtime_override_surface(self):
        self.assertEqual(list(inspect.signature(ba.invoke).parameters), ["request"])

    def test_closed_operation_set_and_empty_arguments(self):
        self.assertEqual(
            set(ba.OPERATIONS),
            {
                "dragonfly.runner.status",
                "dragonfly.runner.start",
                "dragonfly.runner.drain",
            },
        )
        for op in ba.OPERATIONS:
            parsed = ba.read_request(io.BytesIO(json.dumps(self.request(op)).encode()))
            self.assertEqual(parsed["operation"], op)
        with self.assertRaisesRegex(ba.AdapterError, "OPERATION_INVALID"):
            ba.read_request(io.BytesIO(json.dumps(self.request("smoke")).encode()))
        with self.assertRaisesRegex(ba.AdapterError, "ARGUMENTS_INVALID"):
            ba.read_request(
                io.BytesIO(
                    json.dumps(
                        self.request("dragonfly.runner.status", {"x": 1})
                    ).encode()
                )
            )

    def test_request_bounds_and_unknown_fields_fail_closed(self):
        with self.assertRaisesRegex(ba.AdapterError, "REQUEST_FIELDS_INVALID"):
            ba.read_request(
                io.BytesIO(
                    b'{"operation":"dragonfly.runner.status","arguments":{},"x":1}'
                )
            )
        with self.assertRaisesRegex(ba.AdapterError, "REQUEST_TOO_LARGE"):
            ba.read_request(io.BytesIO(b"x" * (ba.MAX_REQUEST_BYTES + 1)))

    def test_runtime_uses_fixed_argv_no_shell_and_sanitized_env(self):
        with tempfile.TemporaryDirectory() as td:
            home, controller, data = self.make_controller(Path(td))
            old = ba.EXPECTED_CONTROLLER_BLOB
            ba.EXPECTED_CONTROLLER_BLOB = git_blob_sha(data)
            calls = []

            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                return Completed(
                    out=json.dumps(
                        {
                            "marker": ba.CONTROLLER_MARKER,
                            "state": "AVAILABLE",
                            "reason": None,
                        }
                    )
                )

            try:
                result = self.invoke(
                    self.request("dragonfly.runner.start"),
                    controller_path=controller,
                    home=home,
                    runner=runner,
                )
            finally:
                ba.EXPECTED_CONTROLLER_BLOB = old
            self.assertEqual(
                result,
                {
                    "marker": ba.MARKER,
                    "operation": "dragonfly.runner.start",
                    "state": "AVAILABLE",
                    "reason": None,
                },
            )
            argv, kwargs = calls[0]
            self.assertEqual(argv, ["/usr/bin/python3", str(controller), "start"])
            self.assertNotIn("shell", kwargs)
            self.assertEqual(
                kwargs["env"],
                {
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
            )
            self.assertEqual(kwargs["timeout"], 10)

    def test_status_projects_only_allowlisted_fields(self):
        with tempfile.TemporaryDirectory() as td:
            home, controller, data = self.make_controller(Path(td))
            old = ba.EXPECTED_CONTROLLER_BLOB
            ba.EXPECTED_CONTROLLER_BLOB = git_blob_sha(data)

            def runner(argv, **kwargs):
                return Completed(
                    out=json.dumps(
                        {
                            "marker": ba.CONTROLLER_MARKER,
                            "state": "STOPPED",
                            "reason": None,
                            "visible_cpus": 12,
                            "mem_available_mib": 12000,
                            "free_disk_gib": 81,
                            "load_fraction": 0.01,
                            "residue_count": 0,
                            "base_present": True,
                            "qemu_pid": 999,
                            "run_id": "secretish",
                            "private_path": "/home/eddie/private",
                        }
                    )
                )

            try:
                result = self.invoke(
                    self.request("dragonfly.runner.status"),
                    controller_path=controller,
                    home=home,
                    runner=runner,
                )
            finally:
                ba.EXPECTED_CONTROLLER_BLOB = old
            self.assertEqual(
                set(result),
                {
                    "marker",
                    "operation",
                    "state",
                    "reason",
                    "visible_cpus",
                    "mem_available_mib",
                    "free_disk_gib",
                    "load_fraction",
                    "residue_count",
                    "base_present",
                },
            )
            self.assertNotIn("qemu_pid", result)
            self.assertNotIn("run_id", result)
            self.assertNotIn("private_path", result)

    def test_controller_symlink_and_identity_mismatch_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            target = root / "target.py"
            target.write_text("x")
            controller = home / ba.INSTALL_RELATIVE
            controller.parent.mkdir(parents=True)
            controller.symlink_to(target)
            runner = mock.Mock()
            with self.assertRaisesRegex(ba.AdapterError, "CONTROLLER_PATH_SYMLINK"):
                self.invoke(
                    self.request("dragonfly.runner.status"),
                    controller_path=controller,
                    home=home,
                    runner=runner,
                )
            runner.assert_not_called()
        with tempfile.TemporaryDirectory() as td:
            home, controller, _ = self.make_controller(Path(td), b"wrong")
            runner = mock.Mock()
            with self.assertRaisesRegex(ba.AdapterError, "CONTROLLER_IDENTITY_MISMATCH"):
                self.invoke(
                    self.request("dragonfly.runner.status"),
                    controller_path=controller,
                    home=home,
                    runner=runner,
                )
            runner.assert_not_called()

    def test_controller_errors_are_bounded_and_paths_not_forwarded(self):
        with tempfile.TemporaryDirectory() as td:
            home, controller, data = self.make_controller(Path(td))
            old = ba.EXPECTED_CONTROLLER_BLOB
            ba.EXPECTED_CONTROLLER_BLOB = git_blob_sha(data)
            try:
                with self.assertRaisesRegex(ba.AdapterError, "^HOST_NOT_AVAILABLE$"):
                    self.invoke(
                        self.request("dragonfly.runner.start"),
                        controller_path=controller,
                        home=home,
                        runner=lambda *a, **k: Completed(
                            rc=2,
                            err="ERROR:HOST_NOT_AVAILABLE\n",
                        ),
                    )
                with self.assertRaisesRegex(ba.AdapterError, "^CONTROLLER_FAILED$"):
                    self.invoke(
                        self.request("dragonfly.runner.start"),
                        controller_path=controller,
                        home=home,
                        runner=lambda *a, **k: Completed(
                            rc=2,
                            err="ERROR:SYMLINK_PATH_REFUSED:/home/eddie/private\n",
                        ),
                    )
            finally:
                ba.EXPECTED_CONTROLLER_BLOB = old

    def test_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            home, controller, data = self.make_controller(Path(td))
            old = ba.EXPECTED_CONTROLLER_BLOB
            ba.EXPECTED_CONTROLLER_BLOB = git_blob_sha(data)

            def runner(argv, **kwargs):
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

            try:
                with self.assertRaisesRegex(ba.AdapterError, "CONTROLLER_TIMEOUT"):
                    self.invoke(
                        self.request("dragonfly.runner.drain"),
                        controller_path=controller,
                        home=home,
                        runner=runner,
                    )
            finally:
                ba.EXPECTED_CONTROLLER_BLOB = old

    def test_invalid_controller_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            home, controller, data = self.make_controller(Path(td))
            old = ba.EXPECTED_CONTROLLER_BLOB
            ba.EXPECTED_CONTROLLER_BLOB = git_blob_sha(data)
            try:
                with self.assertRaisesRegex(ba.AdapterError, "CONTROLLER_OUTPUT_INVALID"):
                    self.invoke(
                        self.request("dragonfly.runner.status"),
                        controller_path=controller,
                        home=home,
                        runner=lambda *a, **k: Completed(out="not-json /home/eddie"),
                    )
                bad = {
                    "marker": ba.CONTROLLER_MARKER,
                    "state": "STOPPED",
                    "reason": "/home/eddie/private",
                    "visible_cpus": 12,
                    "mem_available_mib": 100,
                    "free_disk_gib": 1,
                    "load_fraction": 0.1,
                    "residue_count": 0,
                    "base_present": True,
                }
                with self.assertRaisesRegex(ba.AdapterError, "CONTROLLER_OUTPUT_INVALID"):
                    self.invoke(
                        self.request("dragonfly.runner.status"),
                        controller_path=controller,
                        home=home,
                        runner=lambda *a, **k: Completed(out=json.dumps(bad)),
                    )
            finally:
                ba.EXPECTED_CONTROLLER_BLOB = old

    def test_source_contains_no_network_provider_or_forbidden_controller_commands(self):
        source = MODULE_PATH.read_text()
        for token in (
            "socket",
            "requests",
            "urllib",
            "httpx",
            "websocket",
            "GITHUB_TOKEN",
            "gh api",
            "registration-token",
            "jitconfig",
        ):
            self.assertNotIn(token, source)
        self.assertNotIn('"smoke"', source)
        self.assertNotIn('"recover"', source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
