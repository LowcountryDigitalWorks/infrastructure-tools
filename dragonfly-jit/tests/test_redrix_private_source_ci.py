"""Synthetic contract tests: no GitHub clone, provider API, VM, or credentials."""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "redrix_private_source_ci.py"
SPEC = importlib.util.spec_from_file_location("redrix_private_source_ci", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
HEAD = "a" * 40


class TestPrivateSourceContract(unittest.TestCase):
    def test_sha_exact(self):
        self.assertEqual(probe.validate_source_sha(HEAD), HEAD)
        for invalid in ("", "a" * 39, "a" * 41, "A" * 40,
                        "a" * 39 + "\n", "b" * 39 + ";", 12, None):
            with self.subTest(value=invalid), self.assertRaises(probe.ProbeRefused):
                probe.validate_source_sha(invalid)

    def test_environment_ignores_inherited_secrets_and_git_overrides(self):
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.dict(os.environ, {
                "GITHUB_TOKEN": "not-used", "SSH_AUTH_SOCK": "not-used",
                "AWS_SECRET_ACCESS_KEY": "not-used",
                "GIT_CONFIG_COUNT": "3", "PYTHONPATH": "/untrusted",
            }):
                env = probe.minimal_environment(Path(root))
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("SSH_AUTH_SOCK", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("GIT_CONFIG_COUNT", env)
            self.assertNotIn("PYTHONPATH", env)
            self.assertEqual(env["PATH"], "/usr/bin:/bin")
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_private_source_accepts_regular_owned_files(self):
        with tempfile.TemporaryDirectory() as root:
            top = Path(root) / "source"
            nested = top / "tests"
            nested.mkdir(parents=True)
            path = nested / "test_probe.py"
            path.write_text("print('test')", encoding="utf-8")
            top.chmod(0o700)
            nested.chmod(0o700)
            path.chmod(0o600)
            probe.assert_private_source_tree(top)

    def test_private_source_refuses_group_write(self):
        with tempfile.TemporaryDirectory() as root:
            top = Path(root) / "source"
            top.mkdir(mode=0o700)
            f = top / "module.py"
            f.write_text("test", encoding="utf-8")
            f.chmod(0o660)
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_PRIVATE_MODE_REQUIRED"):
                probe.assert_private_source_tree(top)

    def test_private_source_refuses_symlink_even_to_regular_owned_file(self):
        with tempfile.TemporaryDirectory() as root:
            top = Path(root) / "source"
            top.mkdir()
            target = Path(root) / "target"
            target.write_text("private", encoding="utf-8")
            (top / "alias.py").symlink_to(target)
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_ENTRY_UNSAFE"):
                probe.assert_private_source_tree(top)

    def test_private_source_refuses_fifo_without_opening(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("Linux POSIX FIFO only")
        with tempfile.TemporaryDirectory() as root:
            top = Path(root) / "source"
            top.mkdir()
            os.mkfifo(top / "fifo")
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_ENTRY_UNSAFE"):
                probe.assert_private_source_tree(top)

    def test_result_strict(self):
        self.assertEqual(probe.parse_test_result(0, "Ran 136 tests in 0.08s\n\nOK\n"), 136)
        for rc, output in (
            (1, "Ran 136 tests in 1s\n\nOK\n"),
            (0, "Ran 0 tests in 1s\n\nOK\n"),
            (0, "Ran 136 tests in 1s\n\nFAILED\n"),
            (0, "OK\n"),
            (0, "x" * 65537),
        ):
            with self.subTest(rc=rc, length=len(output)), self.assertRaises(probe.ProbeRefused):
                probe.parse_test_result(rc, output)

    def _fake_run(self, calls, *, sha=HEAD, clone_ok=True, test_ok=True):
        def fake_run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            self.assertNotIn("shell", kwargs)
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
            self.assertEqual(kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
            if "clone" in argv:
                if not clone_ok:
                    return subprocess.CompletedProcess(argv, 1, "", "DENIED:SECRET")
                root = Path(argv[-1]) / "dragonfly-jit" / "tests"
                root.mkdir(parents=True)
                top = root.parent
                top.chmod(0o700)
                root.chmod(0o700)
                src = top / "dragonfly_jit.py"
                src.write_text("synthetic", encoding="utf-8")
                src.chmod(0o600)
                return subprocess.CompletedProcess(argv, 0, "", "")
            if "rev-parse" in argv:
                return subprocess.CompletedProcess(argv, 0, sha + "\n", "")
            if "unittest" in argv:
                return subprocess.CompletedProcess(argv, 0 if test_ok else 1,
                                                   "", "Ran 136 tests in 0.01s\n\n"
                                                   + ("OK" if test_ok else "FAILED"))
            raise AssertionError("unexpected command")

        return fake_run

    @unittest.skipUnless(os.name == "posix", "normal-user Crostini Linux only")
    def test_clone_test_and_cleanup_one_shot(self):
        calls = []
        with mock.patch.object(probe.subprocess, "run", side_effect=self._fake_run(calls)):
            result = probe.run_source_probe(HEAD)
        self.assertEqual(result["classification"], "LOCAL_PRIVATE_SOURCE_CI_PASS_NOT_JIT")
        self.assertEqual(result["tests_passed"], 136)
        self.assertFalse(result["ci_dispatch_authorized"])
        self.assertFalse(result["jit_admission_authorized"])
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][0][-2], probe.SOURCE_URL)
        self.assertTrue(all(arg[0] in (probe.GIT, probe.PYTHON) for arg, _ in calls))
        self.assertFalse(Path(calls[0][0][-1]).exists(), "fixture checkout must be removed")

    @unittest.skipUnless(os.name == "posix", "normal-user Crostini Linux only")
    def test_sha_drift_refuses_before_test_execution(self):
        calls = []
        with mock.patch.object(probe.subprocess, "run",
                               side_effect=self._fake_run(calls, sha="b" * 40)):
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_SHA_MISMATCH"):
                probe.run_source_probe(HEAD)
        self.assertEqual(len(calls), 2)

    @unittest.skipUnless(os.name == "posix", "normal-user Crostini Linux only")
    def test_clone_failure_never_leaks_raw_git_error(self):
        calls = []
        with mock.patch.object(probe.subprocess, "run",
                               side_effect=self._fake_run(calls, clone_ok=False)):
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_CLONE_FAILED") as raised:
                probe.run_source_probe(HEAD)
        self.assertNotIn("DENIED:SECRET", str(raised.exception))
        self.assertEqual(len(calls), 1)

    @unittest.skipUnless(os.name == "posix", "normal-user Crostini Linux only")
    def test_test_failure_refuses_and_does_not_register_runner(self):
        calls = []
        with mock.patch.object(probe.subprocess, "run",
                               side_effect=self._fake_run(calls, test_ok=False)):
            with self.assertRaisesRegex(probe.ProbeRefused, "SOURCE_TEST_FAILED"):
                probe.run_source_probe(HEAD)
        self.assertEqual(len(calls), 3)

    def test_cli_sanitizes_errors(self):
        out = StringIO()
        with mock.patch.object(probe, "run_source_probe",
                               side_effect=probe.ProbeRefused("SOURCE_TEST_FAILED")),              redirect_stdout(out):
            code = probe.main(["--expected-sha", HEAD])
        self.assertEqual(code, 2)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["reason"], "SOURCE_TEST_FAILED")
        self.assertFalse(parsed["ci_dispatch_authorized"])
        self.assertFalse(parsed["jit_admission_authorized"])


if __name__ == "__main__":
    unittest.main()
