"""Source-only, non-authorizing Windows Sandbox policy change/rollback packet.

This pure module consumes a sanitized result from the *existing* read-only
Gate C device-policy audit. It never reads a host, writes policy, invokes a
Windows API, launches a guest or represents approval, even for all-deny data.
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

SCHEMA = "ldw.commander.gate_c.policy_change_packet.v1"
SOURCE_SCHEMA = "ldw.commander.gate_c.sandbox_policy.v1"
SOURCE_CLASSIFICATION = "POLICY_DATA_ONLY_GUEST_NOT_ADMITTED"
CLASSIFICATION = "CHANGE_PACKET_DATA_ONLY_NOT_AUTHORIZED"
POLICIES = (
    "AllowMappedFolders",
    "AllowNetworking",
    "AllowClipboardRedirection",
    "AllowAudioInput",
    "AllowVideoInput",
    "AllowPrinterRedirection",
    "AllowVGPU",
)
ALLOWED_STATES = frozenset((
    "EXPLICIT_DENY", "ALLOWED", "NOT_CONFIGURED", "INVALID",
    "UNAVAILABLE", "NOT_INSPECTED",
))
MANAGEMENT_SOURCES = frozenset(("LOCAL_GPO", "DOMAIN_GPO", "MDM"))
OBSERVATION_KEYS = frozenset((
    "schema", "classification", "windows_platform_observed",
    "mapped_folder_policy_build_supported", "policy_states",
    "all_required_policies_explicitly_deny", "runtime_policy_enforcement_verified",
    "post_start_mutation_denial_verified", "guest_isolation_verified",
    "hardware_owner_presence_verified", "admin_session_authorized",
))
NEGATIVE_FLAGS = (
    "runtime_policy_enforcement_verified", "post_start_mutation_denial_verified",
    "guest_isolation_verified", "hardware_owner_presence_verified",
    "admin_session_authorized",
)


def _acceptable_observation(observation: object) -> bool:
    """Strict schema validation, not authentication of a local observation."""
    if type(observation) is not dict or set(observation) != OBSERVATION_KEYS:
        return False
    if (observation["schema"] != SOURCE_SCHEMA
            or observation["classification"] != SOURCE_CLASSIFICATION
            or observation["windows_platform_observed"] is not True
            or observation["mapped_folder_policy_build_supported"] is not True
            or any(observation[key] is not False for key in NEGATIVE_FLAGS)):
        return False
    states = observation["policy_states"]
    if type(states) is not dict or set(states) != set(POLICIES):
        return False
    if any(type(value) is not str or value not in ALLOWED_STATES
           for value in states.values()):
        return False
    actual_all_deny = all(states[name] == "EXPLICIT_DENY" for name in POLICIES)
    return observation["all_required_policies_explicitly_deny"] is actual_all_deny


def build_change_packet(
    observation: object,
    *,
    management_source: object = "UNKNOWN",
) -> dict[str, Any]:
    """Propose an exact fixed-name change and preimage-aware rollback *intent*.

    The caller's declared management source is never proof that it owns the
    effective setting. The output contains no executable registry commands,
    host selector, security credential or permission to perform a change.
    """
    packet: dict[str, Any] = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "disposition": "HOLD_OBSERVATION_INVALID",
        "management_source_claim": None,
        "management_source_verified": False,
        "changes": [],
        "rollback_intents": [],
        "plan_sha256": None,
        "machine_policy_changed": False,
        "runtime_enforcement_verified": False,
        "owner_presence_verified": False,
        "guest_isolation_verified": False,
        "admin_session_authorized": False,
    }
    if not _acceptable_observation(observation):
        return packet
    states = observation["policy_states"]
    if any(states[name] in ("INVALID", "UNAVAILABLE", "NOT_INSPECTED")
           for name in POLICIES):
        packet["disposition"] = "HOLD_PREIMAGE_UNAVAILABLE"
        return packet
    if type(management_source) is not str or management_source not in MANAGEMENT_SOURCES:
        packet["disposition"] = "HOLD_POLICY_PROVENANCE_UNKNOWN"
        return packet
    packet["management_source_claim"] = management_source
    changes: list[dict[str, str]] = []
    rollback: list[dict[str, str]] = []
    for name in POLICIES:
        prior = states[name]
        if prior == "EXPLICIT_DENY":
            continue
        changes.append({
            "policy": name,
            "desired_state": "EXPLICIT_DENY",
            "intent": "SET_DENY_VIA_VERIFIED_MANAGEMENT_SOURCE",
        })
        rollback.append({
            "policy": name,
            "prior_state": prior,
            "intent": (
                "RESTORE_NOT_CONFIGURED_VIA_SAME_MANAGEMENT_SOURCE"
                if prior == "NOT_CONFIGURED" else
                "RESTORE_ALLOWED_VIA_SAME_MANAGEMENT_SOURCE"
            ),
        })
    if not changes:
        packet["disposition"] = "NO_SOURCE_CHANGE_OBSERVED_RUNTIME_UNVERIFIED"
        return packet
    packet["changes"] = changes
    packet["rollback_intents"] = rollback
    # Unauthenticated correlation digest only: NOT a signature or approved token.
    digest_input = {
        "schema": SCHEMA,
        "management_source_claim": management_source,
        "changes": changes,
        "rollback_intents": rollback,
    }
    blob = json.dumps(digest_input, sort_keys=True, separators=(",", ":"))
    packet["plan_sha256"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    packet["disposition"] = "PLAN_ONLY_NOT_AUTHORIZED"
    return packet


def main() -> None:
    # No CLI flag, host, key, file path or privileged operation is accepted.
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(build_change_packet(None), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
