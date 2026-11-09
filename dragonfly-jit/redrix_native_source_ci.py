#!/usr/bin/env python3
"""One-shot, public-main-only REDRIX source CI proof; never GitHub JIT admission.

This script does not configure a GitHub runner, guest, credential or scheduler.
Only an explicitly supplied, still-current infrastructure-tools/main SHA is
executable, under a private umask and a throwaway checkout.
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

REPO = "https://github.com/LowcountryDigitalWorks/infrastructure-tools.git"
REF = "refs/heads/main"
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
COUNT_RE = re.compile(r"Ran\s+(\d+)\s+tests?\s+in\s+", re.MULTILINE)
SOURCE_PATHS = (
    "dragonfly-jit/dragonfly_jit.py",
    "dragonfly-jit/handoff_contract.py",
    "dragonfly-jit/canary_executor.py",
    "dragonfly-jit/ssh_forced_receiver.py",
)
TEST_COMMAND = (
    "/usr/bin/python3", "-m", "unittest", "discover",
    "-s", "dragonfly-jit/tests", "-p", "test_*.py", "-q",
)

# Closed, source-reviewed suites only. A caller chooses one *name*, never a
# repository, file path, command line, shell fragment, URL or environment.
# Chat Relay tests bind ONLY 127.0.0.1 on ephemeral ports and shut down in
# the unittest fixture; no public listener or standing server is installed.
SUITE_PROFILES = {
    "dragonfly": (TEST_COMMAND, SOURCE_PATHS),
    "chat-relay": (
        ("/usr/bin/python3", "-m", "unittest", "discover",
         "-s", "chat-relay", "-p", "test_*.py", "-q"),
        ("chat-relay/relay.py", "chat-relay/group_relay.py",
         "chat-relay/mcp_local.py"),
    ),
    "browser-static": (
        ("/usr/bin/python3", "-m", "unittest", "discover",
         "-s", "browser-isolation", "-p", "test_*.py", "-q"),
        ("browser-isolation/run_canary.py",),
    ),
}

# Exactly these reviewed profiles, in fixed order. This is one source-only
# checkout, not an arbitrary test selector or JIT/workflow admission.
ALL_SUITE_ORDER = ("dragonfly", "chat-relay", "browser-static")
SUITE_CHOICES = (*ALL_SUITE_ORDER, "all")


class SourceCiHold(RuntimeError):
    """Reason is one fixed public-safe code; no raw process output is exposed."""


def environment(home: Path) -> dict[str, str]:
    """No inherited GitHub auth, agents, user Git/Python settings, or proxies."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def run(command: tuple[str, ...], *, cwd: Path, env: dict[str, str],
        timeout: int = 45) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceCiHold("PROCESS_UNAVAILABLE") from exc


def git(args: tuple[str, ...], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run((
        "/usr/bin/git", "-c", "core.hooksPath=/dev/null",
        "-c", "init.templateDir=/dev/null", *args,
    ), cwd=cwd, env=env)


def remote_main(*, cwd: Path, env: dict[str, str]) -> str:
    result = git(("ls-remote", REPO, REF), cwd=cwd, env=env)
    if result.returncode != 0:
        raise SourceCiHold("MAIN_UNAVAILABLE")
    parts = result.stdout.strip().split()
    if len(parts) != 2 or parts[1] != REF or SHA_RE.fullmatch(parts[0]) is None:
        raise SourceCiHold("MAIN_IDENTITY_INVALID")
    return parts[0]


def private_sources(root: Path, paths: tuple[str, ...] = SOURCE_PATHS) -> bool:
    for relative in paths:
        path = root / relative
        try:
            if any(part.is_symlink() for part in (root, *path.parents)) or path.is_symlink():
                return False
            mode = path.stat()
            if (not stat.S_ISREG(mode.st_mode) or mode.st_uid != os.geteuid()
                    or mode.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                return False
        except OSError:
            return False
    return True


def proof(head: str, suite: str = "dragonfly") -> dict[str, object]:
    result: dict[str, object] = {
        "schema": 1,
        "marker": "LDW_REDRIX_NATIVE_SOURCE_CI",
        "result": "HOLD",
        "no_runner": True,
        "no_jit_authority": True,
        "no_guest": True,
        "no_persistent_install": True,
        "source_head": head if SHA_RE.fullmatch(head) else "INVALID",
        "suite": suite if suite in SUITE_CHOICES else "INVALID",
    }
    if suite not in SUITE_CHOICES:
        result["reason"] = "SUITE_NOT_ALLOWLISTED"
        return result
    if SHA_RE.fullmatch(head) is None or not sys.platform.startswith("linux") or os.geteuid() == 0:
        result["reason"] = "INPUT_OR_PLATFORM_REFUSED"
        return result
    # This umask applies only within this short-lived Python process and its
    # children; it never changes a user's login/default Crostini settings.
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="ldw-redrix-native-ci-") as directory:
            root = Path(directory)
            env = environment(root)
            if remote_main(cwd=root, env=env) != head:
                raise SourceCiHold("MAIN_MOVED")
            for args in (
                ("init", "-q", str(root)),
                ("remote", "add", "origin", REPO),
                ("fetch", "--quiet", "--depth=1", "origin", head),
                ("checkout", "--quiet", "--detach", "FETCH_HEAD"),
            ):
                if git(args, cwd=root, env=env).returncode != 0:
                    raise SourceCiHold("CHECKOUT_REFUSED")
            recorded = git(("rev-parse", "HEAD"), cwd=root, env=env)
            if recorded.returncode != 0 or recorded.stdout.strip() != head:
                raise SourceCiHold("HEAD_MISMATCH")
            selected = ALL_SUITE_ORDER if suite == "all" else (suite,)
            # Verify every selected source file before running any profile.
            # Unknown suites never become reachable through this fixed order.
            for name in selected:
                if not private_sources(root, SUITE_PROFILES[name][1]):
                    raise SourceCiHold("PRIVATE_SOURCE_REQUIRED")
            counts: dict[str, int] = {}
            for name in selected:
                command = SUITE_PROFILES[name][0]
                tests = run(command, cwd=root, env=env, timeout=120)
                match = COUNT_RE.search(tests.stderr + "\n" + tests.stdout)
                if tests.returncode != 0 or match is None or int(match.group(1)) < 1:
                    raise SourceCiHold("SOURCE_TESTS_FAILED")
                counts[name] = int(match.group(1))
            if remote_main(cwd=root, env=env) != head:
                raise SourceCiHold("MAIN_MOVED")
            result["result"] = "PASS_SOURCE_ONLY"
            result["tests_passed"] = sum(counts.values())
            if suite == "all":
                result["suite_counts"] = counts
            result["private_checkout"] = True
    except SourceCiHold as exc:
        result["reason"] = str(exc)
    except (OSError, UnicodeError, ValueError):
        result["reason"] = "LOCAL_PROOF_UNAVAILABLE"
    finally:
        os.umask(previous)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, help="Exact accepted public main commit SHA")
    parser.add_argument("--suite", choices=SUITE_CHOICES, default="dragonfly",
                        help="One of the fixed, reviewed source-only test profiles")
    args = parser.parse_args(argv)
    report = proof(args.head, args.suite)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["result"] == "PASS_SOURCE_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
