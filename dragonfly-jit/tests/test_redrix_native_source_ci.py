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

    def test_exact_head_fetch_keeps_ancestry_without_other_refs(self):
        """The accepted one-shot proof fetches the exact current SHA + reachable ancestry."""
        seen = []
        def record_git(args, **kwargs):
            seen.append(tuple(args))
            return self.git_ok(args, **kwargs)

        with mock.patch.object(ci, "remote_main", side_effect=[HEAD, HEAD]), \
             mock.patch.object(ci, "git", side_effect=record_git), \
             mock.patch.object(ci, "private_sources", return_value=True), \
             mock.patch.object(ci, "run", return_value=PASSED):
            result = ci.proof(HEAD)
        self.assertEqual(result["result"], "PASS_SOURCE_ONLY")
        fetches = [args for args in seen if args[0] == "fetch"]
        self.assertEqual(fetches, [("fetch", "--quiet", "--no-tags", "origin", HEAD)])
        self.assertEqual(
            [args for args in seen if args[0] == "checkout"],
            [("checkout", "--quiet", "--detach", "FETCH_HEAD")],
        )
        self.assertNotIn("--depth=1", " ".join(map(str, seen)))
        self.assertNotIn("refs/heads/", " ".join(map(str, seen)))

    def test_exact_commit_fetch_retains_prior_immutable_blob_in_private_fixture(self):
        """Local file-remote integration: history is data, never executable source."""
        with tempfile.TemporaryDirectory(prefix="ldw-native-ci-history-") as td:
            root = Path(td)
            origin = root / "origin"
            dest = root / "private-checkout"
            origin.mkdir()
            dest.mkdir()
            env = ci.environment(root)
            # Only this synthetic test uses a local file Git transport; production
            # environment() remains HTTPS-only and cannot fetch caller-selected URLs.
            env["GIT_ALLOW_PROTOCOL"] = "file"

            def git(cwd, *args):
                completed = subprocess.run(
                    ["git", "-C", str(cwd), *args],
                    cwd=root, env=env, capture_output=True, text=True,
                    timeout=20, check=False,
                )
                self.assertEqual(completed.returncode, 0, msg="SYNTHETIC_GIT_FAILED")
                return completed.stdout.strip()

            git(origin, "init", "-q")
            original = origin / "historical-source.txt"
            original.write_text("immutable accepted historic source\n", encoding="utf-8")
            git(origin, "add", "historical-source.txt")
            git(origin, "-c", "user.name=Fixture", "-c",
                "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                "commit", "-q", "-m", "historical")
            prior_blob = git(origin, "rev-parse", "HEAD:historical-source.txt")
            original.write_text("new current source\n", encoding="utf-8")
            git(origin, "add", "historical-source.txt")
            git(origin, "-c", "user.name=Fixture", "-c",
                "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                "commit", "-q", "-m", "current")
            head = git(origin, "rev-parse", "HEAD")
            self.assertRegex(head, r"^[a-f0-9]{40}$")

            git(dest, "init", "-q")
            git(dest, "remote", "add", "origin", str(origin))
            git(dest, "fetch", "--quiet", "--no-tags", "origin", head)
            git(dest, "checkout", "--quiet", "--detach", "FETCH_HEAD")
            self.assertEqual(git(dest, "rev-parse", "HEAD"), head)
            historical_bytes = subprocess.run(
                ["git", "-C", str(dest), "cat-file", "-p", prior_blob],
                cwd=root, env=env, capture_output=True, timeout=20, check=False,
            )
            self.assertEqual(historical_bytes.returncode, 0)
            self.assertEqual(historical_bytes.stdout,
                             b"immutable accepted historic source\n")

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


    def test_all_profile_runs_each_fixed_suite_in_one_checkout(self):
        counts = (136, 68, 6)
        fixtures = [
            subprocess.CompletedProcess((), 0, "", f"Ran {count} tests in 0.1s\n\nOK\n")
            for count in counts
        ]
        with (
            mock.patch.object(ci, "remote_main", side_effect=[HEAD, HEAD]) as remote,
            mock.patch.object(ci, "git", side_effect=self.git_ok) as git,
            mock.patch.object(ci, "private_sources", return_value=True) as private,
            mock.patch.object(ci, "run", side_effect=fixtures) as runner,
        ):
            result = ci.proof(HEAD, suite="all")
        self.assertEqual(result["result"], "PASS_SOURCE_ONLY")
        self.assertEqual(result["suite"], "all")
        self.assertEqual(result["tests_passed"], sum(counts))
        self.assertEqual(result["suite_counts"], dict(zip(ci.ALL_SUITE_ORDER, counts)))
        self.assertTrue(result["private_checkout"])
        self.assertTrue(result["no_runner"] and result["no_jit_authority"])
        self.assertEqual(remote.call_count, 2)
        self.assertEqual(git.call_count, 5)
        self.assertEqual(private.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in runner.call_args_list],
            [ci.SUITE_PROFILES[name][0] for name in ci.ALL_SUITE_ORDER],
        )
        self.assertEqual(
            [call.kwargs["paths"] if "paths" in call.kwargs else call.args[1]
             for call in private.call_args_list],
            [ci.SUITE_PROFILES[name][1] for name in ci.ALL_SUITE_ORDER],
        )

    def test_all_profile_bad_source_fails_before_running_any_suite(self):
        with (
            mock.patch.object(ci, "remote_main", return_value=HEAD) as remote,
            mock.patch.object(ci, "git", side_effect=self.git_ok),
            mock.patch.object(ci, "private_sources", side_effect=[True, False]),
            mock.patch.object(ci, "run") as runner,
        ):
            result = ci.proof(HEAD, suite="all")
        self.assertEqual(result["result"], "HOLD")
        self.assertEqual(result["reason"], "PRIVATE_SOURCE_REQUIRED")
        self.assertNotIn("tests_passed", result)
        self.assertNotIn("suite_counts", result)
        remote.assert_called_once()
        runner.assert_not_called()

    def test_all_profile_second_suite_failure_cannot_emit_partial_pass(self):
        failed = subprocess.CompletedProcess((), 1, "SENSITIVE_DETAILS", "Ran 68 tests in 0.1s")
        with (
            mock.patch.object(ci, "remote_main", return_value=HEAD) as remote,
            mock.patch.object(ci, "git", side_effect=self.git_ok),
            mock.patch.object(ci, "private_sources", return_value=True),
            mock.patch.object(ci, "run", side_effect=[PASSED, failed]) as runner,
        ):
            result = ci.proof(HEAD, suite="all")
        self.assertEqual(result["result"], "HOLD")
        self.assertEqual(result["reason"], "SOURCE_TESTS_FAILED")
        self.assertNotIn("suite_counts", result)
        self.assertNotIn("tests_passed", result)
        self.assertNotIn("SENSITIVE_DETAILS", str(result))
        self.assertEqual(runner.call_count, 2)
        remote.assert_called_once()

    def test_all_profile_main_movement_after_tests_refuses_pass(self):
        with (
            mock.patch.object(ci, "remote_main", side_effect=[HEAD, "b" * 40]) as remote,
            mock.patch.object(ci, "git", side_effect=self.git_ok),
            mock.patch.object(ci, "private_sources", return_value=True),
            mock.patch.object(ci, "run", return_value=PASSED) as runner,
        ):
            result = ci.proof(HEAD, suite="all")
        self.assertEqual(result["reason"], "MAIN_MOVED")
        self.assertEqual(result["result"], "HOLD")
        self.assertNotIn("suite_counts", result)
        self.assertNotIn("tests_passed", result)
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(remote.call_count, 2)

    def test_suite_registry_is_closed_fixed_python_only(self):
        self.assertEqual(set(ci.SUITE_PROFILES), {"dragonfly", "chat-relay", "browser-static"})
        self.assertEqual(ci.ALL_SUITE_ORDER, ("dragonfly", "chat-relay", "browser-static"))
        self.assertEqual(ci.SUITE_CHOICES, (*ci.ALL_SUITE_ORDER, "all"))
        for name, (command, paths) in ci.SUITE_PROFILES.items():
            with self.subTest(suite=name):
                self.assertEqual(command[0], "/usr/bin/python3")
                self.assertEqual(command[1:4], ("-m", "unittest", "discover"))
                self.assertEqual(command[-3:], ("-p", "test_*.py", "-q"))
                self.assertTrue(paths)
                self.assertTrue(all(not p.startswith("/") and ".." not in Path(p).parts
                                    and "\\x00" not in p for p in paths))
        self.assertEqual(ci.SUITE_PROFILES["dragonfly"][0], ci.TEST_COMMAND)
        self.assertEqual(ci.SUITE_PROFILES["dragonfly"][1], ci.SOURCE_PATHS)

    def test_unknown_suite_fails_before_any_git_or_test(self):
        for candidate in ("", "other", "../../etc/passwd", "dragonfly;whoami", None):
            with self.subTest(candidate=candidate), \
                 mock.patch.object(ci, "git") as git, \
                 mock.patch.object(ci, "run") as run, \
                 mock.patch.object(ci, "remote_main") as remote:
                report = ci.proof(HEAD, suite=candidate)
                self.assertEqual(report["result"], "HOLD")
                self.assertEqual(report["reason"], "SUITE_NOT_ALLOWLISTED")
                self.assertTrue(report["no_runner"] and report["no_jit_authority"])
                self.assertEqual(report["suite"], "INVALID")
                git.assert_not_called()
                run.assert_not_called()
                remote.assert_not_called()

    def test_each_new_suite_uses_fixed_commands_and_selected_private_sources(self):
        for name in ("chat-relay", "browser-static"):
            with self.subTest(suite=name), \
                 mock.patch.object(ci, "remote_main", side_effect=[HEAD, HEAD]), \
                 mock.patch.object(ci, "git", side_effect=self.git_ok), \
                 mock.patch.object(ci, "private_sources", return_value=True) as private, \
                 mock.patch.object(ci, "run", return_value=PASSED) as run:
                outcome = ci.proof(HEAD, suite=name)
                self.assertEqual(outcome["result"], "PASS_SOURCE_ONLY")
                self.assertEqual(outcome["suite"], name)
                self.assertTrue(outcome["no_runner"] and outcome["no_jit_authority"])
                self.assertEqual(run.call_args.args[0], ci.SUITE_PROFILES[name][0])
                self.assertEqual(private.call_args.args[1], ci.SUITE_PROFILES[name][1])

    def test_chat_relay_selected_source_group_write_refused(self):
        paths = ci.SUITE_PROFILES["chat-relay"][1]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in paths:
                file = root / relative
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("source-only", encoding="utf-8")
                file.chmod(0o600)
            self.assertTrue(ci.private_sources(root, paths))
            (root / paths[-1]).chmod(0o664)
            self.assertFalse(ci.private_sources(root, paths))

    def test_browser_static_selected_source_symlink_refused(self):
        paths = ci.SUITE_PROFILES["browser-static"][1]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "target"
            target.write_text("fixture", encoding="utf-8")
            source = root / paths[0]
            source.parent.mkdir(parents=True, exist_ok=True)
            source.symlink_to(target)
            self.assertFalse(ci.private_sources(root, paths))


if __name__ == "__main__":
    unittest.main()
