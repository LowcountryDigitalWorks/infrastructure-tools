#!/usr/bin/env python3
"""Install/verify/rollback the reviewed REDRIX Bridge system unit.

Source-only until a separate owner/security gate authorizes runtime use. The helper
never enables or starts the service and refuses to mutate an active/enabled unit.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

SUDO = "/usr/bin/sudo"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
INSTALL = "/usr/bin/install"
RM = "/usr/bin/rm"
UNIT_NAME = "ldw-operations-bridge-dragonfly.service"
UNIT_DESTINATION = Path("/etc/systemd/system") / UNIT_NAME
UNIT_SOURCE = Path(__file__).resolve().parents[1] / "systemd" / UNIT_NAME
EXPECTED_UNIT_SHA256 = "9a72afaaaa34bb510e8a693d3377b08ffc55ffcf0880d17d8b3b71ae949fba9a"
BINARY = Path("/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload/LDW.OperationsBridge.Runner")
CONFIG = Path("/home/eddie/.config/ldw/operations-bridge/dragonfly/config.json")
CREDENTIAL = Path("/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred")


class ServiceError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(args: list[str], classification: str, *, sudo: bool = False) -> subprocess.CompletedProcess[str]:
    command = [SUDO, "-n", *args] if sudo else args
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=15,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise ServiceError(classification)
    return result


def _is_active_or_enabled() -> bool:
    for verb in ("is-active", "is-enabled"):
        result = subprocess.run(
            [SUDO, "-n", SYSTEMCTL, verb, "--quiet", UNIT_NAME],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={},
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return True
    return False


def _verify_source() -> None:
    if not UNIT_SOURCE.is_file() or UNIT_SOURCE.is_symlink() or _sha256(UNIT_SOURCE) != EXPECTED_UNIT_SHA256:
        raise ServiceError("SERVICE_UNIT_SOURCE_INVALID")


def _verify_dependency(path: Path, classification: str, *, executable: bool = False) -> None:
    try:
        path.lstat()
    except FileNotFoundError as exc:
        raise ServiceError(classification) from exc
    if path.is_symlink() or not path.is_file():
        raise ServiceError(classification)
    if executable and not os.access(path, os.X_OK):
        raise ServiceError(classification)


def _verify_credential_metadata() -> None:
    result = _run(["/usr/bin/stat", "-Lc", "%u:%g:%a:%F", str(CREDENTIAL)], "BRIDGE_CREDENTIAL_ARTIFACT_INVALID", sudo=True)
    if result.stdout.strip() != "0:0:600:regular file":
        raise ServiceError("BRIDGE_CREDENTIAL_ARTIFACT_INVALID")


def _verify_installed_unit() -> None:
    result = _run(["/usr/bin/stat", "-Lc", "%u:%g:%a:%F", str(UNIT_DESTINATION)], "SERVICE_UNIT_METADATA_INVALID", sudo=True)
    if result.stdout.strip() != "0:0:644:regular file":
        raise ServiceError("SERVICE_UNIT_METADATA_INVALID")
    digest = _run(["/usr/bin/sha256sum", str(UNIT_DESTINATION)], "SERVICE_UNIT_HASH_INVALID", sudo=True).stdout.split()[0]
    if digest != EXPECTED_UNIT_SHA256:
        raise ServiceError("SERVICE_UNIT_HASH_INVALID")


def preflight() -> None:
    _verify_source()
    _verify_dependency(BINARY, "BRIDGE_BINARY_INVALID", executable=True)
    _verify_dependency(CONFIG, "BRIDGE_CONFIG_INVALID")
    _verify_credential_metadata()
    if _is_active_or_enabled():
        raise ServiceError("SERVICE_MUST_BE_INACTIVE_AND_DISABLED")


def install() -> None:
    preflight()
    if UNIT_DESTINATION.exists() or UNIT_DESTINATION.is_symlink():
        _verify_installed_unit()
        return
    _run([INSTALL, "-o", "root", "-g", "root", "-m", "0644", str(UNIT_SOURCE), str(UNIT_DESTINATION)], "SERVICE_UNIT_INSTALL_FAILED", sudo=True)
    _run([SYSTEMCTL, "daemon-reload"], "SERVICE_DAEMON_RELOAD_FAILED", sudo=True)
    _verify_installed_unit()
    if _is_active_or_enabled():
        raise ServiceError("SERVICE_UNEXPECTEDLY_ACTIVE_OR_ENABLED")


def verify() -> None:
    preflight()
    _verify_installed_unit()
    _run([SYSTEMD_ANALYZE, "verify", str(UNIT_DESTINATION)], "SERVICE_UNIT_VERIFY_FAILED", sudo=True)


def rollback() -> None:
    if _is_active_or_enabled():
        raise ServiceError("SERVICE_MUST_BE_INACTIVE_AND_DISABLED")
    if not (UNIT_DESTINATION.exists() or UNIT_DESTINATION.is_symlink()):
        return
    _verify_installed_unit()
    _run([RM, "-f", str(UNIT_DESTINATION)], "SERVICE_UNIT_ROLLBACK_FAILED", sudo=True)
    _run([SYSTEMCTL, "daemon-reload"], "SERVICE_DAEMON_RELOAD_FAILED", sudo=True)
    if UNIT_DESTINATION.exists() or UNIT_DESTINATION.is_symlink():
        raise ServiceError("SERVICE_UNIT_ROLLBACK_FAILED")


def main() -> int:
    if os.geteuid() != 1000 or os.environ.get("USER") not in (None, "eddie"):
        print("SYSTEMD_BRIDGE_SERVICE=HOLD")
        print("CLASSIFICATION=OWNER_IDENTITY_INVALID")
        return 1
    if len(sys.argv) != 2 or sys.argv[1] not in {"preflight", "install", "verify", "rollback"}:
        print("usage: redrix-systemd-bridge-service.py preflight|install|verify|rollback", file=sys.stderr)
        return 2
    try:
        {"preflight": preflight, "install": install, "verify": verify, "rollback": rollback}[sys.argv[1]]()
        print("SYSTEMD_BRIDGE_SERVICE_" + sys.argv[1].upper() + "=PASS")
        print("SERVICE_ENABLED=no")
        print("SERVICE_STARTED=no")
        return 0
    except (ServiceError, OSError, subprocess.SubprocessError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "SYSTEMD_BRIDGE_SERVICE_FAILED"
        print("SYSTEMD_BRIDGE_SERVICE=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
