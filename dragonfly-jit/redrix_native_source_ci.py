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


def private_sources(root: Path) -> bool:
    for relative in SOURCE_PATHS:
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


def proof(head: str) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": 1,
        "marker": "LDW_REDRIX_NATIVE_SOURCE_CI",
        "result": "HOLD",
        "no_runner": True,
        "no_jit_authority": True,
        "no_guest": True,
        "no_persistent_install": True,
        "source_head": head if SHA_RE.fullmatch(head) else "INVALID",
    }
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
            if not private_sources(root):
                raise SourceCiHold("PRIVATE_SOURCE_REQUIRED")
            tests = run(TEST_COMMAND, cwd=root, env=env, timeout=120)
            match = COUNT_RE.search(tests.stderr + "\n" + tests.stdout)
            if tests.returncode != 0 or match is None or int(match.group(1)) < 1:
                raise SourceCiHold("SOURCE_TESTS_FAILED")
            if remote_main(cwd=root, env=env) != head:
                raise SourceCiHold("MAIN_MOVED")
            result["result"] = "PASS_SOURCE_ONLY"
            result["tests_passed"] = int(match.group(1))
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
    args = parser.parse_args(argv)
    report = proof(args.head)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["result"] == "PASS_SOURCE_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
