"""Deterministic synthetic tests for REDRIX one-shot private source CI."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "redrix_native_source_ci.py"
SPEC = importlib.util.spec_from_file_location("redrix_native_source_ci", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("TEST_SOURCE_MISSING")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)
HEAD = "a" * 40
GOOD = subprocess.CompletedProcess((), 0, "", "")
PASSED = subprocess.CompletedProcess((), 0, "", "Ran 136 tests in 0.18s\n\nOK\n")


class PrivateSourceCiTests(unittest.TestCase):
    def test_rejects_non_hex_or_partial_head_before_external_call(self):
        for value in ("", "A" * 40, "a" * 39, "x" * 40, "a" * 40 + "\n"):
            with self.subTest(value=value):
                with mock.patch.object(ci, "git") as g:
                    answer = ci.proof(value)
                    self.assertEqual(answer["reason"], "INPUT_OR_PLATFORM_REFUSED")
                    self.assertFalse(answer["no_jit_authority"] is False)
                    g.assert_not_called()

    def test_environment_excludes_auth_and_user_settings(self):
        with mock.patch.dict(os.environ, {
            "GITHUB_TOKEN": "DO_NOT_ECHO",
            "GIT_ASKPASS": "DO_NOT_ECHO",
            "PYTHONPATH": "DO_NOT_ECHO",
            "HTTP_PROXY": "DO_NOT_ECHO",
        }):
            env = ci.environment(Path("/tmp/private"))
        self.assertNotIn("DO_NOT_ECHO", str(env))
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "https")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("PYTHONPATH", env)

    def test_fixed_commands_have_no_shell_or_provider_writes(self):
        self.assertIn("unittest", ci.TEST_COMMAND)
        self.assertTrue(ci.REPO.startswith("https://github.com/LowcountryDigitalWorks/"))
        for prohibited in ("workflow_dispatch", "gh api", "jitconfig", "sudo", "ssh "):
            self.assertNotIn(prohibited, " ".join(ci.TEST_COMMAND))

    def test_main_remote_exactly_matching_ref(self):
        proc = subprocess.CompletedProcess((), 0, HEAD + "\trefs/heads/main\n", "")
        with mock.patch.object(ci, "git", return_value=proc) as git:
            self.assertEqual(ci.remote_main(cwd=Path("/tmp"), env={}), HEAD)
            self.assertEqual(git.call_args.args[0][0], "ls-remote")

    def test_remote_ref_failure_or_extra_records_refused(self):
        for proc in (
            subprocess.CompletedProcess((), 1, "", ""),
            subprocess.CompletedProcess((), 0, "bad\n", ""),
            subprocess.CompletedProcess((), 0, HEAD + "\trefs/heads/other\n", ""),
            subprocess.CompletedProcess((), 0, HEAD + "\trefs/heads/main\n" * 2, ""),
        ):
            with mock.patch.object(ci, "git", return_value=proc):
                with self.assertRaises(ci.SourceCiHold):
                    ci.remote_main(cwd=Path("/tmp"), env={})

    def test_source_private_permissions_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in ci.SOURCE_PATHS:
                p = root / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("synthetic")
                p.chmod(0o600)
            self.assertTrue(ci.private_sources(root))

    def test_group_write_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in ci.SOURCE_PATHS:
                p = root / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("synthetic")
                p.chmod(0o600)
            (root / ci.SOURCE_PATHS[0]).chmod(0o664)
            self.assertFalse(ci.private_sources(root))

    def test_symlink_source_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in ci.SOURCE_PATHS:
                p = root / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("synthetic")
                p.chmod(0o600)
            p = root / ci.SOURCE_PATHS[-1]
            p.unlink()
            p.symlink_to(root / ci.SOURCE_PATHS[0])
            self.assertFalse(ci.private_sources(root))

    @staticmethod
    def git_ok(args, **kwargs):
        if args[0] == "rev-parse":
            return subprocess.CompletedProcess((), 0, HEAD + "\n", "")
        return GOOD

    def test_positive_exact_main_stays_source_only(self):
        with mock.patch.object(ci, "remote_main", side_effect=[HEAD, HEAD]) as remote, \
             mock.patch.object(ci, "git", side_effect=self.git_ok), \
             mock.patch.object(ci, "private_sources", return_value=True), \
             mock.patch.object(ci, "run", return_value=PASSED) as run:
            result = ci.proof(HEAD)
        self.assertEqual(result["result"], "PASS_SOURCE_ONLY")
        self.assertEqual(result["tests_passed"], 136)
        self.assertTrue(result["no_runner"])
        self.assertTrue(result["no_jit_authority"])
        self.assertEqual(remote.call_count, 2)
        self.assertEqual(run.call_args.args[0], ci.TEST_COMMAND)

    def test_pre_checkout_main_movement_refused(self):
        with mock.patch.object(ci, "remote_main", return_value="b" * 40), \
             mock.patch.object(ci, "git") as git:
            result = ci.proof(HEAD)
            self.assertEqual(result["reason"], "MAIN_MOVED")
            git.assert_not_called()

    def test_post_test_main_movement_invalidates_pass(self):
        with mock.patch.object(ci, "remote_main", side_effect=[HEAD, "b" * 40]), \
             mock.patch.object(ci, "git", side_effect=self.git_ok), \
             mock.patch.object(ci, "private_sources", return_value=True), \
             mock.patch.object(ci, "run", return_value=PASSED):
            result = ci.proof(HEAD)
        self.assertEqual(result["result"], "HOLD")
        self.assertEqual(result["reason"], "MAIN_MOVED")

    def test_unparsable_tests_or_nonzero_fail_closed_without_logs(self):
        for failure in (
            subprocess.CompletedProcess((), 1, "SENSITIVE_DETAILS", ""),
            subprocess.CompletedProcess((), 0, "", "no unittest count"),
        ):
            with mock.patch.object(ci, "remote_main", return_value=HEAD), \
                 mock.patch.object(ci, "git", side_effect=self.git_ok), \
                 mock.patch.object(ci, "private_sources", return_value=True), \
                 mock.patch.object(ci, "run", return_value=failure):
                result = ci.proof(HEAD)
            self.assertEqual(result["reason"], "SOURCE_TESTS_FAILED")
            self.assertNotIn("SENSITIVE_DETAILS", str(result))

    def test_git_arguments_are_fixed_without_shell(self):
        with mock.patch.object(ci, "run", return_value=GOOD) as run:
            ci.git(("status",), cwd=Path("/tmp"), env={})
        args = run.call_args.args[0]
        self.assertEqual(args[0], "/usr/bin/git")
        self.assertIn("core.hooksPath=/dev/null", args)

    def test_umask_is_restored_after_success_and_hold(self):
        original = os.umask(0o022)
        os.umask(original)
        with mock.patch.object(ci, "remote_main", return_value="b" * 40):
            ci.proof(HEAD)
        current = os.umask(original)
        os.umask(current)
        self.assertEqual(current, original)


if __name__ == "__main__":
    unittest.main()
