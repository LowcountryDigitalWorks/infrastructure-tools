#!/usr/bin/env python3
"""Offline reconciliation of two injected REDRIX continuity receipts.

This module accepts dictionaries only. It does not read files, open sockets,
run commands, or authorize CI, JIT, login, or failover. A matching pair is
DATA_ONLY_NOT_AUTHORIZED, never a live channel or readiness claim.
"""
from __future__ import annotations

import datetime as dt

SCHEMA = "ldw.redrix-continuity-reconcile.v1"
SCHEMA_VERSION = 1
FIXED_DEVICE_ID = "synthetic-redrix-continuity-fixture"
LOCAL_SOURCE_ID = "redrix-crostini-health-receipt"
REMOTE_SOURCE_ID = "ldw01-reachability-receipt"
TRUST_PROVENANCE = "injected-synthetic"
MAX_SKEW_SECONDS = 30
MAX_TTL_SECONDS = 300

LOCAL_KEYS = {
    "schema", "schema_version", "role", "source_id", "device_id", "boot_id",
    "nonce", "observed_at", "ttl_seconds", "classification", "reasons",
    "ci_dispatch_authorized", "qemu_absent", "a4_process_visibility",
    "chromeos_session",
}
REMOTE_KEYS = {
    "schema", "schema_version", "role", "source_id", "device_id", "boot_id",
    "nonce", "observed_at", "ttl_seconds", "reachability", "owner_session",
    "chromeos_evidence", "provider_api", "tailscale_peer", "trust_provenance",
    "confidence", "vm_posture", "controller_lease", "provider_verified_simulation",
}
PACKET_KEYS = {"schema", "schema_version", "now", "local", "remote"}
LOCAL_CLASSIFICATIONS = {
    "LOCAL_SERVICES_HEALTHY_UNVERIFIED",
    "DEGRADED_HOST",
    "DEGRADED_SERVICE",
    "DEGRADED_NETWORK",
    "HOLD",
}
LOCAL_REASONS = {
    "EXTERNAL_PEER_AND_PRIVILEGED_PROCESS_PROOF_REQUIRED",
    "KVM_NOT_READ_WRITE",
    "REQUIRED_SERVICE_NOT_READY",
    "TAILSCALE_SELF_OR_HEALTH_NOT_STABLE",
    "INSUFFICIENT_SAMPLES",
    "JIT_STATE_OR_QEMU_UNSAFE",
    "SAMPLE_FAILED",
}
TOKEN = r"abcdefghijklmnopqrstuvwxyz0123456789-"


class _Reject(Exception):
    def __init__(self, classification: str, reason: str) -> None:
        self.classification = classification
        self.reason = reason


def _result(classification: str, reason: str, peer: str = "UNVERIFIED") -> dict:
    return {
        "classification": classification,
        "reasons": [reason],
        "ci_dispatch_authorized": False,
        "process_visibility": "UNVERIFIED",
        "peer_side_corroboration": peer,
        "chromeos_login_claimed": False,
        "runtime_authorized": False,
    }


def _exact(value: dict, allowed: set[str], label: str) -> None:
    del label
    if not isinstance(value, dict) or set(value) != allowed:
        raise _Reject("HOLD", "SCHEMA_INVALID" if not isinstance(value, dict) else "UNKNOWN_FIELD")
    version = value.get("schema_version")
    if value.get("schema") != SCHEMA or type(version) is not int or version != SCHEMA_VERSION:
        raise _Reject("HOLD", "VERSION_UNSUPPORTED")


def _token(value: object, min_len: int = 8, max_len: int = 40) -> bool:
    return (
        isinstance(value, str)
        and min_len <= len(value) <= max_len
        and all(ch in TOKEN for ch in value)
    )


def _time(value: object) -> dt.datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise _Reject("HOLD", "SCHEMA_INVALID")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise _Reject("HOLD", "SCHEMA_INVALID") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def _ttl(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_TTL_SECONDS:
        raise _Reject("HOLD", "SCHEMA_INVALID")
    return value


def _text_choice(value: object, allowed: set[str], overclaim: set[str] | None = None) -> str:
    if type(value) is not str or value not in allowed:
        if type(value) is str and value in (overclaim or set()):
            raise _Reject("HOLD", "USER_CONFIDENCE_REJECTED")
        raise _Reject("HOLD", "SCHEMA_INVALID")
    return value


def _flag(value: object) -> bool:
    if type(value) is not bool:
        raise _Reject("HOLD", "SCHEMA_INVALID")
    return value


def _reasons(value: object) -> None:
    if type(value) is not list or not 1 <= len(value) <= 4:
        raise _Reject("HOLD", "SCHEMA_INVALID")
    if any(type(item) is not str or item not in LOCAL_REASONS for item in value):
        raise _Reject("HOLD", "SCHEMA_INVALID")
    if len(set(value)) != len(value):
        raise _Reject("HOLD", "SCHEMA_INVALID")


def _history(seen_nonces: object) -> set[str]:
    if seen_nonces is None:
        return set()
    if type(seen_nonces) not in (list, tuple) or len(seen_nonces) > 16:
        raise _Reject("HOLD", "SCHEMA_INVALID")
    cleaned: list[str] = []
    for item in seen_nonces:
        if not _token(item, max_len=32):
            raise _Reject("HOLD", "SCHEMA_INVALID")
        cleaned.append(item)
    if len(set(cleaned)) != len(cleaned):
        raise _Reject("HOLD", "SCHEMA_INVALID")
    return set(cleaned)


def canonical_packet() -> dict:
    """One sanitized correlated pair. Mutate copies in tests; do not treat it as live evidence."""
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "now": "2026-11-08T05:01:00Z",
        "local": {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "role": "local_crostini_health",
            "source_id": LOCAL_SOURCE_ID,
            "device_id": FIXED_DEVICE_ID,
            "boot_id": "boot-synthetic-001",
            "nonce": "nonce-synthetic-001",
            "observed_at": "2026-11-08T05:00:20Z",
            "ttl_seconds": 120,
            "classification": "LOCAL_SERVICES_HEALTHY_UNVERIFIED",
            "reasons": ["EXTERNAL_PEER_AND_PRIVILEGED_PROCESS_PROOF_REQUIRED"],
            "ci_dispatch_authorized": False,
            "qemu_absent": True,
            "a4_process_visibility": "UNVERIFIED",
            "chromeos_session": "NOT_OBSERVED",
        },
        "remote": {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "role": "ldw01_reachability",
            "source_id": REMOTE_SOURCE_ID,
            "device_id": FIXED_DEVICE_ID,
            "boot_id": "boot-synthetic-001",
            "nonce": "nonce-synthetic-001",
            "observed_at": "2026-11-08T05:00:40Z",
            "ttl_seconds": 120,
            "reachability": "SIMULATED_UNVERIFIED",
            "owner_session": "NOT_SUPPLIED",
            "chromeos_evidence": "ABSENT",
            "provider_api": "OK",
            "tailscale_peer": "PRESENT_UNVERIFIED",
            "trust_provenance": TRUST_PROVENANCE,
            "confidence": "NONE",
            "vm_posture": "NOT_SUPPLIED",
            "controller_lease": "NONE",
            "provider_verified_simulation": False,
        },
    }


def _check_identity(local: dict, remote: dict) -> None:
    if local["role"] != "local_crostini_health" or remote["role"] != "ldw01_reachability":
        raise _Reject("HOLD", "SCHEMA_INVALID")
    if local["source_id"] != LOCAL_SOURCE_ID or remote["source_id"] != REMOTE_SOURCE_ID:
        raise _Reject("HOLD", "SOURCE_IDENTITY_MISMATCH")
    if local["device_id"] != FIXED_DEVICE_ID or remote["device_id"] != FIXED_DEVICE_ID:
        raise _Reject("HOLD", "DEVICE_IDENTITY_MISMATCH")
    if remote["trust_provenance"] != TRUST_PROVENANCE:
        raise _Reject("HOLD", "TRUST_PROVENANCE_MISMATCH")
    if not _token(local["boot_id"]) or not _token(local["nonce"]):
        raise _Reject("HOLD", "SCHEMA_INVALID")
    if local["boot_id"] != remote["boot_id"]:
        raise _Reject("HOLD", "BOOT_DISCRIMINATOR_MISMATCH")
    if local["nonce"] != remote["nonce"]:
        raise _Reject("HOLD", "NONCE_MISMATCH")


def _check_time(local: dict, remote: dict, now: dt.datetime, seen_nonces: set[str]) -> None:
    if local["nonce"] in seen_nonces:
        raise _Reject("HOLD", "DUPLICATE_OR_REPLAY")
    local_at = _time(local["observed_at"])
    remote_at = _time(remote["observed_at"])
    if remote_at < local_at:
        raise _Reject("HOLD", "TIME_ORDER_INVALID")
    if (remote_at - local_at).total_seconds() > MAX_SKEW_SECONDS:
        raise _Reject("HOLD", "CLOCK_SKEW")
    for observed, ttl in ((local_at, _ttl(local["ttl_seconds"])), (remote_at, _ttl(remote["ttl_seconds"]))):
        if observed > now:
            raise _Reject("HOLD", "CLOCK_SKEW")
        if (now - observed).total_seconds() > ttl:
            raise _Reject("HOLD", "TTL_EXPIRED")


def _check_claims(local: dict, remote: dict) -> str:
    if _flag(local["ci_dispatch_authorized"]) is not False:
        raise _Reject("HOLD", "USER_CONFIDENCE_REJECTED")
    _text_choice(local["chromeos_session"], {"NOT_OBSERVED"}, {"LOGGED_IN"})
    _text_choice(local["a4_process_visibility"], {"UNVERIFIED"}, {"VERIFIED"})
    _reasons(local["reasons"])
    classification = _text_choice(local["classification"], LOCAL_CLASSIFICATIONS)
    qemu_absent = _flag(local["qemu_absent"])
    allowed_remote = {
        "reachability": {"SIMULATED_UNVERIFIED"},
        "owner_session": {"NOT_SUPPLIED", "REMOTE_CLAIM"},
        "chromeos_evidence": {"ABSENT", "SIMULATED_UNVERIFIED"},
        "provider_api": {"OK", "FAILED"},
        "tailscale_peer": {"PRESENT_UNVERIFIED", "STALE", "ABSENT"},
        "confidence": {"NONE"},
        "vm_posture": {"NOT_SUPPLIED", "UNAVAILABLE"},
        "controller_lease": {"NONE", "AMBIGUOUS"},
    }
    overclaim = {"AUTHENTICATED", "ONLINE", "HIGH", "CONFIRMED", "LOGGED_IN", "JIT_READY", "ONLINE_READY"}
    for key, allowed in allowed_remote.items():
        value = remote[key]
        if type(value) is not str or value not in allowed:
            raise _Reject("HOLD", "USER_CONFIDENCE_REJECTED" if type(value) is str and value in overclaim else "SCHEMA_INVALID")
    if _flag(remote["provider_verified_simulation"]) not in (True, False):
        raise _Reject("HOLD", "SCHEMA_INVALID")
    if remote["provider_api"] == "FAILED":
        raise _Reject("HOLD", "PROVIDER_API_FAILURE")
    if remote["controller_lease"] == "AMBIGUOUS":
        raise _Reject("HOLD", "SPLIT_BRAIN")
    if remote["chromeos_evidence"] == "ABSENT" and remote["owner_session"] == "REMOTE_CLAIM":
        raise _Reject("UNVERIFIED", "OWNER_SESSION_WITHOUT_CHROMEOS")
    if remote["vm_posture"] == "UNAVAILABLE":
        raise _Reject("UNVERIFIED", "LOGIN_OR_VM_UNAVAILABLE")
    if remote["tailscale_peer"] == "STALE":
        raise _Reject("DEGRADED", "TAILSCALE_STALE")
    if remote["tailscale_peer"] == "ABSENT":
        raise _Reject("DEGRADED", "TAILSCALE_ABSENT")
    if qemu_absent is not True:
        raise _Reject("DEGRADED", "QEMU_RESIDUE")
    if classification == "HOLD":
        raise _Reject("HOLD", "LOCAL_HOLD")
    if classification.startswith("DEGRADED_"):
        raise _Reject("DEGRADED", "LOCAL_DEGRADED")
    peer = "SIMULATED_FIELD_ONLY" if remote["provider_verified_simulation"] is True else "UNVERIFIED"
    return peer


def reconcile(packet: dict, seen_nonces: list[str] | None = None) -> dict:
    """Reconcile injected receipts. seen_nonces is caller history and is not stored."""
    try:
        if not isinstance(packet, dict):
            raise _Reject("HOLD", "SCHEMA_INVALID")
        if ("local" not in packet or "remote" not in packet) and set(packet) <= PACKET_KEYS:
            raise _Reject("HOLD", "MISSING_SIDE")
        if set(packet) != PACKET_KEYS:
            raise _Reject("HOLD", "UNKNOWN_FIELD")
        _exact(packet, PACKET_KEYS, "")
        local, remote = packet["local"], packet["remote"]
        if not isinstance(local, dict) or not isinstance(remote, dict):
            raise _Reject("HOLD", "SCHEMA_INVALID")
        if isinstance(local, dict) and "a4_process_visibility" not in local and set(local) == LOCAL_KEYS - {"a4_process_visibility"}:
            raise _Reject("HOLD", "MISSING_A4")
        if set(local) != LOCAL_KEYS or set(remote) != REMOTE_KEYS:
            raise _Reject("HOLD", "UNKNOWN_FIELD")
        _exact(local, LOCAL_KEYS, "local")
        _exact(remote, REMOTE_KEYS, "remote")
        history = _history(seen_nonces)
        _check_identity(local, remote)
        _check_time(local, remote, _time(packet["now"]), history)
        peer = _check_claims(local, remote)
    except _Reject as rejected:
        return _result(rejected.classification, rejected.reason)
    except (TypeError, ValueError):
        return _result("HOLD", "SCHEMA_INVALID")
    return _result("DATA_ONLY_NOT_AUTHORIZED", "BOTH_VIEWS_CORRELATED_NOT_A_CHANNEL", peer)
