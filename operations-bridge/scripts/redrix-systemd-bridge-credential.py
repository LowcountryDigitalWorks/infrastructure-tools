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
import secrets
import subprocess
import sys
from pathlib import Path

SUDO = "/usr/bin/sudo"
SECRET_TOOL = "/usr/bin/secret-tool"
SYSTEMD_CREDS = "/usr/bin/systemd-creds"
SHA256SUM = "/usr/bin/sha256sum"
SYSTEMCTL = "/usr/bin/systemctl"
TEST = "/usr/bin/test"
CHMOD = "/usr/bin/chmod"
CHOWN = "/usr/bin/chown"
LN = "/usr/bin/ln"
RM = "/usr/bin/rm"
MKDIR = "/usr/bin/mkdir"
STAT = "/usr/bin/stat"

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


def _kill_process(process: subprocess.Popen[object]) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _digest_stream(producer: subprocess.Popen[bytes]) -> str:
    if producer.stdout is None:
        _kill_process(producer)
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
    try:
        digest_stdout, _ = digest.communicate(timeout=15)
        producer.wait(timeout=15)
    except subprocess.TimeoutExpired as exc:
        _kill_process(digest)
        _kill_process(producer)
        raise MigrationError("CREDENTIAL_DIGEST_TIMEOUT") from exc
    finally:
        if digest.poll() is None:
            _kill_process(digest)
        if producer.poll() is None:
            _kill_process(producer)
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


def _sudo_result(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [SUDO, "-n", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=15,
        check=False,
    )


def _run_sudo(args: list[str], classification: str) -> None:
    if _sudo_result(args).returncode != 0:
        raise MigrationError(classification)


def _artifact_present_privileged() -> bool:
    exists_result = _sudo_result([TEST, "-e", str(CREDENTIAL_PATH)])
    link_result = _sudo_result([TEST, "-L", str(CREDENTIAL_PATH)])
    if exists_result.returncode not in {0, 1} or link_result.returncode not in {0, 1}:
        raise MigrationError("CREDENTIAL_ARTIFACT_STATE_UNAVAILABLE")
    return exists_result.returncode == 0 or link_result.returncode == 0


def _assert_service_safe_for_credential_mutation() -> None:
    result = subprocess.run(
        [
            SUDO,
            "-n",
            SYSTEMCTL,
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            UNIT_NAME,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=10,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise MigrationError("SERVICE_STATE_UNAVAILABLE")
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise MigrationError("SERVICE_STATE_AMBIGUOUS")
        key, value = line.split("=", 1)
        if key in values or key not in {"LoadState", "ActiveState", "UnitFileState"}:
            raise MigrationError("SERVICE_STATE_AMBIGUOUS")
        values[key] = value
    if set(values) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise MigrationError("SERVICE_STATE_AMBIGUOUS")
    safe_not_found = values["LoadState"] == "not-found" and values["ActiveState"] == "inactive" and values["UnitFileState"] in {"", "disabled"}
    safe_disabled = values["LoadState"] == "loaded" and values["ActiveState"] == "inactive" and values["UnitFileState"] == "disabled"
    if not (safe_not_found or safe_disabled):
        raise MigrationError("SERVICE_MUST_BE_INACTIVE_AND_DISABLED")


def _verify_directory_metadata() -> None:
    result = subprocess.run(
        [SUDO, "-n", STAT, "-Lc", "%u:%g:%a:%F", str(CREDENTIAL_DIRECTORY)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={},
        timeout=10,
        check=False,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "0:0:700:directory":
        raise MigrationError("CREDENTIAL_DIRECTORY_METADATA_INVALID")


def _verify_ciphertext_metadata() -> None:
    _verify_directory_metadata()
    result = subprocess.run(
        [SUDO, "-n", STAT, "-Lc", "%u:%g:%a:%F", str(CREDENTIAL_PATH)],
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
    _assert_service_safe_for_credential_mutation()
    if _artifact_present_privileged():
        raise MigrationError("CREDENTIAL_ARTIFACT_EXISTS")

    source_digest = secret_service_digest()
    _run_sudo([MKDIR, "-p", "-m", "0700", str(CREDENTIAL_DIRECTORY)], "CREDENTIAL_DIRECTORY_CREATE_FAILED")
    _verify_directory_metadata()

    temp_path = CREDENTIAL_DIRECTORY / (".bridge-bearer.cred." + secrets.token_hex(12) + ".tmp")
    lookup = _secret_lookup()
    if lookup.stdout is None:
        _kill_process(lookup)
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
    try:
        try:
            encrypt.wait(timeout=20)
            lookup.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            _kill_process(encrypt)
            _kill_process(lookup)
            raise MigrationError("CREDENTIAL_ENCRYPT_TIMEOUT") from exc
        if lookup.returncode != 0 or encrypt.returncode != 0:
            raise MigrationError("CREDENTIAL_ENCRYPT_FAILED")
        _run_sudo([CHOWN, "root:root", str(temp_path)], "CREDENTIAL_TEMP_METADATA_FAILED")
        _run_sudo([CHMOD, "0600", str(temp_path)], "CREDENTIAL_TEMP_METADATA_FAILED")
        # Atomic exclusive publication: hard-link fails if the final path already exists.
        _run_sudo([LN, str(temp_path), str(CREDENTIAL_PATH)], "CREDENTIAL_ARTIFACT_EXISTS")
    finally:
        _kill_process(encrypt)
        _kill_process(lookup)
        _run_sudo([RM, "-f", str(temp_path)], "CREDENTIAL_TEMP_CLEANUP_FAILED")

    try:
        _verify_ciphertext_metadata()
        if encrypted_credential_digest() != source_digest:
            raise MigrationError("CREDENTIAL_VERIFY_MISMATCH")
    except Exception as verify_error:
        try:
            _run_sudo([RM, "-f", str(CREDENTIAL_PATH)], "CREDENTIAL_ARTIFACT_ROLLBACK_FAILED")
        except Exception as rollback_error:
            raise MigrationError("CREDENTIAL_ARTIFACT_ROLLBACK_FAILED") from rollback_error
        raise verify_error


def verify() -> None:
    _verify_ciphertext_metadata()
    if encrypted_credential_digest() != secret_service_digest():
        raise MigrationError("CREDENTIAL_VERIFY_MISMATCH")


def rollback() -> None:
    _assert_service_safe_for_credential_mutation()
    verify()
    _run_sudo([RM, "-f", str(CREDENTIAL_PATH)], "CREDENTIAL_ARTIFACT_ROLLBACK_FAILED")
    if _artifact_present_privileged():
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
