#!/usr/bin/env python3
"""Install/verify/rollback the reviewed REDRIX Bridge system unit.

Source-only until a separate owner/security gate authorizes runtime use. The helper
never enables or starts the service and refuses to mutate an active/enabled unit.
"""

from __future__ import annotations

import hashlib
import json
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
PACKAGE_ROOT = Path("/home/eddie/.local/lib/ldw/operations-bridge/dragonfly")
PACKAGE_MANIFEST = PACKAGE_ROOT / "manifest.json"
BINARY = PACKAGE_ROOT / "payload/LDW.OperationsBridge.Runner"
CONFIG = Path("/home/eddie/.config/ldw/operations-bridge/dragonfly/config.json")
CREDENTIAL = Path("/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


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


def _unit_state() -> tuple[str, str, str]:
    result = _run(
        [
            SYSTEMCTL,
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            UNIT_NAME,
        ],
        "SERVICE_STATE_UNAVAILABLE",
        sudo=True,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise ServiceError("SERVICE_STATE_AMBIGUOUS")
        key, value = line.split("=", 1)
        if key in values or key not in {"LoadState", "ActiveState", "UnitFileState"}:
            raise ServiceError("SERVICE_STATE_AMBIGUOUS")
        values[key] = value
    if set(values) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise ServiceError("SERVICE_STATE_AMBIGUOUS")
    return values["LoadState"], values["ActiveState"], values["UnitFileState"]


def _assert_safe_inactive_state(*, allow_not_found: bool) -> None:
    load, active, unit_file = _unit_state()
    if allow_not_found and load == "not-found" and active == "inactive" and unit_file in {"", "disabled"}:
        return
    if load == "loaded" and active == "inactive" and unit_file == "disabled":
        return
    raise ServiceError("SERVICE_MUST_BE_INACTIVE_AND_DISABLED")


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


def _verify_installed_package() -> None:
    _verify_dependency(PACKAGE_MANIFEST, "BRIDGE_PACKAGE_MANIFEST_INVALID")
    _verify_dependency(BINARY, "BRIDGE_BINARY_INVALID", executable=True)
    try:
        manifest = json.loads(PACKAGE_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID") from exc

    required = {
        "schemaVersion": 1,
        "artifact": "ldw-operations-bridge-dragonfly-linux-x64",
        "runtimeIdentifier": "linux-x64",
        "targetFramework": "net10.0",
        "selfContained": True,
        "requiresSystemDotnet": False,
        "installRoot": "~/.local/lib/ldw/operations-bridge/dragonfly",
        "entrypoint": "payload/LDW.OperationsBridge.Runner",
        "configurationPath": "~/.config/ldw/operations-bridge/dragonfly/config.json",
        "statePath": "~/.local/state/ldw/operations-bridge/dragonfly/health.json",
        "containsConfiguration": False,
        "containsCredential": False,
    }
    for key, expected in required.items():
        if manifest.get(key) != expected:
            raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID")
    if GIT_SHA_RE.fullmatch(str(manifest.get("sourceCommit", ""))) is None:
        raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID")

    records = manifest.get("files")
    if not isinstance(records, list):
        raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID")
    matches = [item for item in records if isinstance(item, dict) and item.get("path") == "LDW.OperationsBridge.Runner"]
    if len(matches) != 1 or set(matches[0]) != {"path", "sha256", "size"}:
        raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID")
    record = matches[0]
    if SHA256_RE.fullmatch(str(record.get("sha256", ""))) is None or not isinstance(record.get("size"), int) or isinstance(record.get("size"), bool) or record["size"] <= 0:
        raise ServiceError("BRIDGE_PACKAGE_MANIFEST_INVALID")
    if BINARY.stat().st_size != record["size"] or _sha256(BINARY) != record["sha256"]:
        raise ServiceError("BRIDGE_BINARY_PROVENANCE_INVALID")


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
    _verify_installed_package()
    _verify_dependency(CONFIG, "BRIDGE_CONFIG_INVALID")
    _verify_credential_metadata()
    _assert_safe_inactive_state(allow_not_found=True)


def install() -> None:
    preflight()
    if UNIT_DESTINATION.exists() or UNIT_DESTINATION.is_symlink():
        _verify_installed_unit()
        return
    _run([INSTALL, "-o", "root", "-g", "root", "-m", "0644", str(UNIT_SOURCE), str(UNIT_DESTINATION)], "SERVICE_UNIT_INSTALL_FAILED", sudo=True)
    _run([SYSTEMCTL, "daemon-reload"], "SERVICE_DAEMON_RELOAD_FAILED", sudo=True)
    _verify_installed_unit()
    _assert_safe_inactive_state(allow_not_found=False)


def verify() -> None:
    _verify_source()
    _verify_installed_package()
    _verify_dependency(CONFIG, "BRIDGE_CONFIG_INVALID")
    _verify_credential_metadata()
    _verify_installed_unit()
    _assert_safe_inactive_state(allow_not_found=False)
    _run([SYSTEMD_ANALYZE, "verify", str(UNIT_DESTINATION)], "SERVICE_UNIT_VERIFY_FAILED", sudo=True)


def rollback() -> None:
    _assert_safe_inactive_state(allow_not_found=True)
    if not (UNIT_DESTINATION.exists() or UNIT_DESTINATION.is_symlink()):
        return
    _verify_installed_unit()
    _run([RM, "-f", str(UNIT_DESTINATION)], "SERVICE_UNIT_ROLLBACK_FAILED", sudo=True)
    _run([SYSTEMCTL, "daemon-reload"], "SERVICE_DAEMON_RELOAD_FAILED", sudo=True)
    _assert_safe_inactive_state(allow_not_found=True)
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
