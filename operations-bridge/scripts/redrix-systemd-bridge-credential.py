#!/usr/bin/env python3
"""Bounded REDRIX Bridge credential migration helper.

This helper is source-only until a separate owner/security gate authorizes runtime use.
It never prints or persists plaintext bearer material and never deletes/changes the
accepted Secret Service item. Plaintext flows only through OS pipes between the
fixed Secret Service lookup and digest/systemd-creds processes.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SUDO = "/usr/bin/sudo"
SECRET_TOOL = "/usr/bin/secret-tool"
SYSTEMD_CREDS = "/usr/bin/systemd-creds"
SHA256SUM = "/usr/bin/sha256sum"
SYSTEMCTL = "/usr/bin/systemctl"
INSTALL = "/usr/bin/install"
RM = "/usr/bin/rm"
MKDIR = "/usr/bin/mkdir"

BRIDGE_ID = "dragonfly-redrix-01"
CREDENTIAL_NAME = "bridge-bearer"
CREDENTIAL_DIRECTORY = Path("/etc/ldw/operations-bridge/dragonfly")
CREDENTIAL_PATH = CREDENTIAL_DIRECTORY / "bridge-bearer.cred"
UNIT_NAME = "ldw-operations-bridge-dragonfly.service"
XDG_RUNTIME_DIR = "/run/user/1000"
DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class MigrationError(RuntimeError):
    pass


def _secret_env() -> dict[str, str]:
    return {
        "XDG_RUNTIME_DIR": XDG_RUNTIME_DIR,
        "DBUS_SESSION_BUS_ADDRESS": DBUS_SESSION_BUS_ADDRESS,
    }


def _secret_lookup() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [SECRET_TOOL, "lookup", "service", "ldw-operations-bridge", "bridge-id", BRIDGE_ID],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_secret_env(),
    )


def _digest_stream(producer: subprocess.Popen[bytes]) -> str:
    if producer.stdout is None:
        raise MigrationError("SECRET_PIPE_UNAVAILABLE")
    digest = subprocess.Popen(
        [SHA256SUM],
        stdin=producer.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        text=True,
    )
    producer.stdout.close()
    digest_stdout, _ = digest.communicate(timeout=15)
    producer.wait(timeout=15)
    if producer.returncode != 0 or digest.returncode != 0:
        raise MigrationError("CREDENTIAL_DIGEST_FAILED")
    value = digest_stdout.split()[0] if digest_stdout.split() else ""
    if DIGEST_RE.fullmatch(value) is None:
        raise MigrationError("CREDENTIAL_DIGEST_FAILED")
    return value


def secret_service_digest() -> str:
    return _digest_stream(_secret_lookup())


def encrypted_credential_digest() -> str:
    decrypt = subprocess.Popen(
        [
            SUDO,
            "-n",
            SYSTEMD_CREDS,
            "--no-ask-password",
            "--name=" + CREDENTIAL_NAME,
            "decrypt",
            str(CREDENTIAL_PATH),
            "-",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
    )
    return _digest_stream(decrypt)


def _run_sudo(args: list[str], classification: str) -> None:
    result = subprocess.run(
        [SUDO, "-n", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise MigrationError(classification)


def _service_is_active_or_enabled() -> bool:
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


def _verify_ciphertext_metadata() -> None:
    result = subprocess.run(
        [SUDO, "-n", "/usr/bin/stat", "-Lc", "%u:%g:%a:%F", str(CREDENTIAL_PATH)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=10,
        check=False,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "0:0:600:regular file":
        raise MigrationError("CREDENTIAL_ARTIFACT_METADATA_INVALID")


def migrate() -> None:
    if CREDENTIAL_PATH.exists() or CREDENTIAL_PATH.is_symlink():
        raise MigrationError("CREDENTIAL_ARTIFACT_EXISTS")

    source_digest = secret_service_digest()
    _run_sudo([MKDIR, "-p", "-m", "0700", str(CREDENTIAL_DIRECTORY)], "CREDENTIAL_DIRECTORY_CREATE_FAILED")

    temp_name = ".bridge-bearer.cred." + next(tempfile._get_candidate_names()) + ".tmp"
    temp_path = CREDENTIAL_DIRECTORY / temp_name
    lookup = _secret_lookup()
    if lookup.stdout is None:
        raise MigrationError("SECRET_PIPE_UNAVAILABLE")
    encrypt = subprocess.Popen(
        [
            SUDO,
            "-n",
            SYSTEMD_CREDS,
            "--no-ask-password",
            "--with-key=host",
            "--name=" + CREDENTIAL_NAME,
            "encrypt",
            "-",
            str(temp_path),
        ],
        stdin=lookup.stdout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={},
    )
    lookup.stdout.close()
    encrypt.wait(timeout=20)
    lookup.wait(timeout=20)
    try:
        if lookup.returncode != 0 or encrypt.returncode != 0:
            raise MigrationError("CREDENTIAL_ENCRYPT_FAILED")
        _run_sudo(
            [INSTALL, "-o", "root", "-g", "root", "-m", "0600", str(temp_path), str(CREDENTIAL_PATH)],
            "CREDENTIAL_ARTIFACT_INSTALL_FAILED",
        )
    finally:
        _run_sudo([RM, "-f", str(temp_path)], "CREDENTIAL_TEMP_CLEANUP_FAILED")

    _verify_ciphertext_metadata()
    if encrypted_credential_digest() != source_digest:
        _run_sudo([RM, "-f", str(CREDENTIAL_PATH)], "CREDENTIAL_ARTIFACT_ROLLBACK_FAILED")
        raise MigrationError("CREDENTIAL_VERIFY_MISMATCH")


def verify() -> None:
    _verify_ciphertext_metadata()
    if encrypted_credential_digest() != secret_service_digest():
        raise MigrationError("CREDENTIAL_VERIFY_MISMATCH")


def rollback() -> None:
    if _service_is_active_or_enabled():
        raise MigrationError("SERVICE_MUST_BE_INACTIVE_AND_DISABLED")
    verify()
    _run_sudo([RM, "-f", str(CREDENTIAL_PATH)], "CREDENTIAL_ARTIFACT_ROLLBACK_FAILED")
    if CREDENTIAL_PATH.exists() or CREDENTIAL_PATH.is_symlink():
        raise MigrationError("CREDENTIAL_ARTIFACT_ROLLBACK_FAILED")


def main() -> int:
    if os.geteuid() != 1000 or os.environ.get("USER") not in (None, "eddie"):
        print("SYSTEMD_BRIDGE_CREDENTIAL=HOLD")
        print("CLASSIFICATION=OWNER_IDENTITY_INVALID")
        return 1
    if len(sys.argv) != 2 or sys.argv[1] not in {"migrate", "verify", "rollback"}:
        print("usage: redrix-systemd-bridge-credential.py migrate|verify|rollback", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "migrate":
            migrate()
            print("SYSTEMD_BRIDGE_CREDENTIAL_MIGRATION=PASS")
            print("SECRET_SERVICE_PRESERVED=yes")
        elif sys.argv[1] == "verify":
            verify()
            print("SYSTEMD_BRIDGE_CREDENTIAL_VERIFY=PASS")
            print("SECRET_SERVICE_PRESERVED=yes")
        else:
            rollback()
            print("SYSTEMD_BRIDGE_CREDENTIAL_ROLLBACK=PASS")
            print("SECRET_SERVICE_PRESERVED=yes")
        return 0
    except (MigrationError, OSError, subprocess.SubprocessError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "SYSTEMD_BRIDGE_CREDENTIAL_FAILED"
        print("SYSTEMD_BRIDGE_CREDENTIAL=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
