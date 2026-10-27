#!/usr/bin/env python3
"""Source-only contract for the future LDW01 -> REDRIX forced-command SSH handoff.

This module does not open a socket, invoke ssh, read a private key, write known_hosts,
or mutate either host. It validates the owner-local transport configuration shape and
builds the exact OpenSSH argv plan that a later reviewed runtime may execute only after
the #115 REDRIX capability/security gate is accepted.
"""

from __future__ import annotations

from pathlib import PureWindowsPath
import re

MARKER = "DRAGONFLY-JIT-TRANSPORT-001"
SCHEMA = 1
TARGET_HOST = "dragonfly-redrix-01"
REMOTE_USER = "eddie"
# An absolute path that must not exist on REDRIX. The later server-side forced-command
# rule replaces it with the reviewed receiver. If that rule is missing, this request
# fails closed instead of resolving an executable from the remote user's PATH.
REMOTE_SENTINEL = "/nonexistent/ldw-dragonfly-jit-handoff-v1"
SSH_PORT = 22
MAX_ENDPOINT_CHARS = 253
SSH_EXECUTABLE = PureWindowsPath(r"C:\Windows\System32\OpenSSH\ssh.exe")
PRIVATE_ROOT_RELATIVE = PureWindowsPath("LDW", "CI-JIT", "DragonflyTransport")
PRIVATE_KEY_NAME = "id_ed25519"
KNOWN_HOSTS_NAME = "known_hosts"
_CONFIG_FIELDS = {
    "schema",
    "target_host",
    "private_endpoint",
    "host_key_fingerprint",
}
_ENDPOINT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


class TransportContractError(ValueError):
    """Fail-closed source-contract validation error."""


def _validate_endpoint(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ENDPOINT_CHARS:
        raise TransportContractError("PRIVATE_ENDPOINT_INVALID")
    if not _ENDPOINT_RE.fullmatch(value):
        raise TransportContractError("PRIVATE_ENDPOINT_INVALID")
    if ".." in value or value.startswith(".") or value.endswith("."):
        raise TransportContractError("PRIVATE_ENDPOINT_INVALID")
    return value


def _validate_fingerprint(value: object) -> str:
    if not isinstance(value, str) or not _FINGERPRINT_RE.fullmatch(value):
        raise TransportContractError("HOST_KEY_FINGERPRINT_INVALID")
    return value


def validate_transport_config(payload: object) -> dict:
    """Validate the non-secret owner-local transport config.

    Reachability/private-network classification is intentionally *not* inferred from
    the endpoint string here. #115 requires that property to be established from live,
    sanitized REDRIX/LDW01 evidence before runtime enablement.
    """
    if not isinstance(payload, dict) or set(payload) != _CONFIG_FIELDS:
        raise TransportContractError("TRANSPORT_CONFIG_FIELDS_INVALID")
    if type(payload["schema"]) is not int or payload["schema"] != SCHEMA:
        raise TransportContractError("TRANSPORT_CONFIG_SCHEMA_INVALID")
    if payload["target_host"] != TARGET_HOST:
        raise TransportContractError("TARGET_HOST_INVALID")

    return {
        "schema": SCHEMA,
        "target_host": TARGET_HOST,
        "private_endpoint": _validate_endpoint(payload["private_endpoint"]),
        "host_key_fingerprint": _validate_fingerprint(payload["host_key_fingerprint"]),
    }


def _absolute_local_app_data(value: object) -> PureWindowsPath:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TransportContractError("LOCAL_APP_DATA_INVALID")
    path = PureWindowsPath(value)
    if not path.is_absolute():
        raise TransportContractError("LOCAL_APP_DATA_INVALID")
    return path


def build_openssh_plan(payload: object, *, local_app_data: str) -> dict:
    """Return the exact future OpenSSH invocation plan without executing it.

    The capsule itself is never represented in argv. A later runtime must stream the
    already-validated bounded V6 capsule on stdin.
    """
    config = validate_transport_config(payload)
    private_root = _absolute_local_app_data(local_app_data) / PRIVATE_ROOT_RELATIVE
    key_path = private_root / PRIVATE_KEY_NAME
    known_hosts_path = private_root / KNOWN_HOSTS_NAME

    args = (
        "-T",
        "-p",
        str(SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_path}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "-o",
        "LogLevel=ERROR",
        "-i",
        str(key_path),
        f"{REMOTE_USER}@{config['private_endpoint']}",
        REMOTE_SENTINEL,
    )

    return {
        "marker": MARKER,
        "schema": SCHEMA,
        "target_host": TARGET_HOST,
        "executable": str(SSH_EXECUTABLE),
        "arguments": list(args),
        "private_root": str(private_root),
        "private_key_path": str(key_path),
        "known_hosts_path": str(known_hosts_path),
        "expected_host_key_fingerprint": config["host_key_fingerprint"],
        "stdin_capsule_only": True,
        "opens_network": False,
    }
