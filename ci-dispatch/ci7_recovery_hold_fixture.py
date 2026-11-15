#!/usr/bin/env python3
"""CI7 incident recovery evidence *non-authorizing* design fixture.

Synthetic in-memory values only. NEVER checks live host, provider, ACL, locks,
release or runner state; NEVER recommends or performs destructive operations.
"""
from __future__ import annotations

from typing import Any

MARKER = "LDW_CI7_RECOVERY_HOLD_FIXTURE_V1"
INCIDENT_RUN_ID = 42462196528
INCIDENT_JOB_ID = 128673684689
INCIDENT_ATTEMPT = 1
ORIGINAL_PR_HEAD = "eb84ba430a358f2776ef92f1a751e38d7a92d50e"

_REASON_CODES = frozenset({
    "HOLD_INPUT_UNTRUSTED", "HOLD_PROVIDER_IDENTITY_MISMATCH",
    "HOLD_PRESERVE_ACTIVE_PROVIDER_JOB", "HOLD_PROVIDER_TERMINAL_NOT_PROVEN",
    "HOLD_LOCAL_TUPLE_NOT_PROVEN", "HOLD_RUNNER_REGISTRATION_NOT_EXHAUSTIVE",
    "HOLD_RUNNER_REGISTRATION_PRESENT", "HOLD_CONTROLLER_LOCK_AUTHORITY_UNVERIFIED",
    "HOLD_RELEASE_MANIFEST_NOT_PROVEN", "HOLD_ACTIVE_GENERATION_UNATTESTED",
    "HOLD_PARENT_ACL_NOT_TRUSTED", "HOLD_OPERATION_AUTHORITY_NOT_ACCEPTED",
    "HOLD_SEPARATE_PHYSICAL_TRANSACTION_REQUIRED",
})


def _strict_bool(value: Any) -> bool:
    return type(value) is bool


def _exact_fields(record: Any, fields: frozenset[str]) -> bool:
    return type(record) is dict and frozenset(record) == fields


def _report(reason: str) -> dict[str, object]:
    assert reason in _REASON_CODES
    return {
        "marker": MARKER,
        "schema": 1,
        "classification": "HOLD_NO_ACTION",
        "reason": reason,
        "input_provenance": "SYNTHETIC_NOT_ATTESTED",
        "owner_approved_cleanup_authorized": False,
        "controller_release_authorized": False,
        "provider_cancel_authorized": False,
        "runner_deregister_authorized": False,
        "local_guest_remove_authorized": False,
        "jit_dispatch_authorized": False,
        "mutations_performed": False,
    }


def assess(snapshot: object) -> dict[str, object]:
    """Return only closed HOLD codes; ignore any caller's assertions of authority.

    The schema intentionally accepts evidence classifications instead of paths,
    tokens, runner identifiers, child process output, lock handles, credentials,
    or private run IDs. All supplied booleans are *hypotheses* to test: this
    fixture does not attest their truth or act upon any result.
    """
    top = frozenset({"marker", "schema", "mode", "local", "provider", "runner", "locks", "release", "approval"})
    local_keys = frozenset({"unique_ci7_vm", "vm_off", "owned_tuple_exact", "state_phase_running", "last_evidence_cleanup_failed"})
    provider_keys = frozenset({"run_id", "job_id", "attempt", "original_head", "run_status", "run_conclusion", "job_status", "job_conclusion"})
    runner_keys = frozenset({"recorded_positive_id", "matching_repository_runners", "inventory_scope", "pagination_complete", "original_registration_repository_scoped"})
    locks_keys = frozenset({"global_lock_artifact_regular", "run_lock_artifact_regular", "exclusive_current_lock_owner_proven"})
    release_keys = frozenset({"accepted_manifest_hash_exact", "active_generation_attested", "protected_root_acl_trusted"})
    approval_keys = frozenset({"exact_local_operation_security_reviewed", "owner_approved_this_exact_transaction"})

    if not _exact_fields(snapshot, top):
        return _report("HOLD_INPUT_UNTRUSTED")
    assert isinstance(snapshot, dict)
    if (snapshot["marker"] != MARKER or type(snapshot["schema"]) is not int
            or snapshot["schema"] != 1 or snapshot["mode"] != "SYNTHETIC_SOURCE_ONLY"):
        return _report("HOLD_INPUT_UNTRUSTED")
    l, p, r, k, s, a = (snapshot[n] for n in ("local", "provider", "runner", "locks", "release", "approval"))
    if not all((_exact_fields(l, local_keys), _exact_fields(p, provider_keys),
                _exact_fields(r, runner_keys), _exact_fields(k, locks_keys),
                _exact_fields(s, release_keys), _exact_fields(a, approval_keys))):
        return _report("HOLD_INPUT_UNTRUSTED")
    if not all(_strict_bool(v) for sub in (l, k, s, a) for v in sub.values()):
        return _report("HOLD_INPUT_UNTRUSTED")
    if not all(_strict_bool(r[key]) for key in ("recorded_positive_id", "pagination_complete", "original_registration_repository_scoped")):
        return _report("HOLD_INPUT_UNTRUSTED")
    if (type(r["matching_repository_runners"]) is not int or r["matching_repository_runners"] not in (0, 1)
            or type(r["inventory_scope"]) is not str or r["inventory_scope"] not in ("REPOSITORY", "PARTIAL_REPOSITORY", "REPOSITORY_EXACT_NAME_FILTER")):
        return _report("HOLD_INPUT_UNTRUSTED")
    if (type(p["run_id"]) is not int or type(p["job_id"]) is not int
            or type(p["attempt"]) is not int or type(p["original_head"]) is not str
            or type(p["run_status"]) is not str or type(p["job_status"]) is not str
            or (p["run_conclusion"] is not None and type(p["run_conclusion"]) is not str)
            or (p["job_conclusion"] is not None and type(p["job_conclusion"]) is not str)):
        return _report("HOLD_INPUT_UNTRUSTED")
    if (p["run_id"] != INCIDENT_RUN_ID or p["job_id"] != INCIDENT_JOB_ID
            or p["attempt"] != INCIDENT_ATTEMPT or p["original_head"] != ORIGINAL_PR_HEAD):
        return _report("HOLD_PROVIDER_IDENTITY_MISMATCH")
    if p["run_status"] in ("queued", "in_progress", "waiting", "requested", "pending") or p["job_status"] in ("queued", "in_progress", "waiting", "requested", "pending"):
        return _report("HOLD_PRESERVE_ACTIVE_PROVIDER_JOB")
    if (p["run_status"] != "completed" or p["job_status"] != "completed"
            or p["run_conclusion"] != "cancelled" or p["job_conclusion"] != "cancelled"):
        return _report("HOLD_PROVIDER_TERMINAL_NOT_PROVEN")
    if not all(l.values()):
        return _report("HOLD_LOCAL_TUPLE_NOT_PROVEN")
    # A first-page-only listing is NOT proof of absent runner registration.
    # A provider exact-name-filtered query with total_count=0 is complete for
    # that name, but the input itself is still UNTRUSTED and not authority.
    # Original CI7 registration is repository-scoped via generate-jitconfig.
    if (not r["recorded_positive_id"] or not r["pagination_complete"] or
            r["inventory_scope"] not in ("REPOSITORY", "REPOSITORY_EXACT_NAME_FILTER") or not r["original_registration_repository_scoped"]):
        return _report("HOLD_RUNNER_REGISTRATION_NOT_EXHAUSTIVE")
    if r["matching_repository_runners"] != 0:
        return _report("HOLD_RUNNER_REGISTRATION_PRESENT")
    if (not k["global_lock_artifact_regular"] or not k["run_lock_artifact_regular"] or
            not k["exclusive_current_lock_owner_proven"]):
        return _report("HOLD_CONTROLLER_LOCK_AUTHORITY_UNVERIFIED")
    if not s["accepted_manifest_hash_exact"]:
        return _report("HOLD_RELEASE_MANIFEST_NOT_PROVEN")
    if not s["active_generation_attested"]:
        return _report("HOLD_ACTIVE_GENERATION_UNATTESTED")
    if not s["protected_root_acl_trusted"]:
        return _report("HOLD_PARENT_ACL_NOT_TRUSTED")
    if not all(a.values()):
        return _report("HOLD_OPERATION_AUTHORITY_NOT_ACCEPTED")
    # Deliberately still HOLD: even maximal synthetic evidence cannot
    # authorize any operation, nor replace fresh actual provider/host checks.
    return _report("HOLD_SEPARATE_PHYSICAL_TRANSACTION_REQUIRED")
