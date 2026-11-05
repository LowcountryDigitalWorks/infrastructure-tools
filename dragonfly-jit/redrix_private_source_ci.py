#!/usr/bin/env python3
"""Manual, secretless, normal-user REDRIX Crostini source-CI proof.

This is NOT a GitHub Actions runner, JIT admission, host service, or scheduler.
It clones only the fixed public LDW repository, requires an exact accepted HEAD,
and runs one vetted Python source-test suite in a disposable private checkout.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

SOURCE_URL = "https://github.com/LowcountryDigitalWorks/infrastructure-tools.git"
GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
TEST_COUNT = re.compile(r"(?m)^Ran ([1-9][0-9]*) tests? in ")
PASS_LINE = re.compile(r"(?m)^OK\s*$")
CLONE_TIMEOUT_SECONDS = 90
SUITE_TIMEOUT_SECONDS = 60


class ProbeRefused(RuntimeError):
    pass


def validate_source_sha(value: str) -> str:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise ProbeRefused("EXPECTED_SHA_INVALID")
    return value


def minimal_environment(workspace: Path) -> dict[str, str]:
    """Do not pass the owner session's tokens, Git/SSH config or credential env."""
    return {
        "HOME": str(workspace / "home"),
        "TMPDIR": str(workspace / "tmp"),
        "XDG_CACHE_HOME": str(workspace / "cache"),
        "XDG_STATE_HOME": str(workspace / "state"),
        "XDG_DATA_HOME": str(workspace / "data"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def assert_private_source_tree(root: Path) -> None:
    """Refuse symlinks, unsafe modes, unexpected ownership and missing source."""
    if not root.is_dir() or root.is_symlink():
        raise ProbeRefused("SOURCE_ROOT_UNSAFE")
    for parent, dirs, files in os.walk(root, topdown=True, followlinks=False):
        for entry in [Path(parent), *(Path(parent) / name for name in dirs + files)]:
            try:
                mode = entry.lstat()
            except OSError as exc:
                raise ProbeRefused("SOURCE_STAT_FAILED") from exc
            if not (stat.S_ISDIR(mode.st_mode) or stat.S_ISREG(mode.st_mode)):
                raise ProbeRefused("SOURCE_ENTRY_UNSAFE")
            if mode.st_uid != os.getuid() or mode.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ProbeRefused("SOURCE_PRIVATE_MODE_REQUIRED")


def parse_test_result(return_code: int, output: str) -> int:
    if return_code != 0 or len(output) > 65536:
        raise ProbeRefused("SOURCE_TEST_FAILED")
    match = TEST_COUNT.search(output)
    if match is None or PASS_LINE.search(output) is None:
        raise ProbeRefused("SOURCE_TEST_RESULT_UNVERIFIED")
    return int(match.group(1))


def run_source_probe(expected_sha: str) -> dict[str, object]:
    validate_source_sha(expected_sha)
    if os.name != "posix" or not Path(GIT).is_file() or not Path(PYTHON).is_file():
        raise ProbeRefused("REDRIX_LINUX_RUNTIME_REQUIRED")

    # umask is process-local and restored, even on any exception. This tool is
    # single-threaded; the private mask is inherited by the Git checkout.
    prior_mask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="ldw-redrix-source-ci-") as private_root:
            workspace = Path(private_root)
            for name in ("home", "tmp", "cache", "state", "data"):
                (workspace / name).mkdir(mode=0o700)
            checkout = workspace / "source"
            env = minimal_environment(workspace)

            clone = subprocess.run(
                [GIT, "-c", "credential.helper=", "-c", "core.fsmonitor=false",
                 "-c", "core.hooksPath=/dev/null", "clone", "--quiet",
                 "--depth", "1", "--no-tags", "--", SOURCE_URL, str(checkout)],
                env=env, cwd=workspace, capture_output=True, text=True,
                timeout=CLONE_TIMEOUT_SECONDS, check=False,
            )
            if clone.returncode != 0:
                raise ProbeRefused("SOURCE_CLONE_FAILED")

            resolved = subprocess.run(
                [GIT, "-C", str(checkout), "rev-parse", "HEAD"],
                env=env, cwd=workspace, capture_output=True, text=True,
                timeout=10, check=False,
            )
            if resolved.returncode != 0 or resolved.stdout.strip() != expected_sha:
                raise ProbeRefused("SOURCE_SHA_MISMATCH")

            assert_private_source_tree(checkout / "dragonfly-jit")
            started = time.monotonic()
            tests = subprocess.run(
                [PYTHON, "-B", "-m", "unittest", "discover",
                 "-s", "dragonfly-jit/tests", "-p", "test_*.py", "-q"],
                env=env, cwd=checkout, capture_output=True, text=True,
                timeout=SUITE_TIMEOUT_SECONDS, check=False,
            )
            count = parse_test_result(tests.returncode, tests.stdout + tests.stderr)
            elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
            return {
                "classification": "LOCAL_PRIVATE_SOURCE_CI_PASS_NOT_JIT",
                "expected_sha": expected_sha,
                "tests_passed": count,
                "elapsed_ms": elapsed_ms,
                "temporary_private_checkout": True,
                "github_runner_registered": False,
                "ci_dispatch_authorized": False,
                "jit_admission_authorized": False,
            }
    finally:
        os.umask(prior_mask)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args(argv)
    try:
        result = run_source_probe(args.expected_sha)
    except ProbeRefused as exc:
        # Never print subprocess output, credentials, paths, or exception internals.
        print(json.dumps({"classification": "HOLD", "reason": str(exc),
                          "ci_dispatch_authorized": False,
                          "jit_admission_authorized": False}, sort_keys=True))
        return 2
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        print(json.dumps({"classification": "HOLD", "reason": "LOCAL_PROBE_FAILED",
                          "ci_dispatch_authorized": False,
                          "jit_admission_authorized": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
