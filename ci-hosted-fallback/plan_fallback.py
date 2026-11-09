"""GitHub-hosted fallback eligibility planner (business-operations #552).

Pure deterministic classifier: never dispatches, cancels, or reruns workflows.
Returns execute=false always with HOSTED_CLEAN_ELIGIBLE or an explicit HOLD reason.
"""
from __future__ import annotations

from typing import Any, Mapping

SCHEMA_VERSION = "1.0"
WORKLOAD_CLASS_ALLOWED = "SECRETLESS_DETERMINISTIC_VALIDATION"

ALLOWED_WORKFLOW_IDS = frozenset(
    {
        "validate-documentation",
    }
)
ALLOWED_PROFILE_IDS = frozenset(
    {
        "bo-docs-validation",
    }
)
ALLOWED_REPOSITORIES = frozenset(
    {
        "LowcountryDigitalWorks/business-operations",
    }
)
PROTECTED_WORKFLOW_MARKERS = frozenset(
    {
        "secret-scan",
        "betterleaks",
        "ldw secret scan",
        "wqt",
        "royal",
        "dragonfly-jit",
        "security-codeql",
        "jit-validation",
        "isolated",
    }
)
STANDARD_HOSTED_RUNNER_LABELS = frozenset(
    {
        "ubuntu-latest",
        "windows-latest",
    }
)
CLEAN_DATA_CLASSIFICATIONS = frozenset(
    {
        "CLEAN_SECRETLESS",
    }
)

REQUIRED_FIELDS = (
    "schema_version",
    "workload_class",
    "workflow_id",
    "profile_id",
    "repository",
    "pull_request_number",
    "head_sha",
    "run_id",
    "run_attempt",
    "job_id",
    "job_status",
    "queued_within_approved_timeout",
    "runner_assigned",
    "private_capacity_blocked",
    "active_duplicate_local_or_jit_job",
    "data_classification",
    "requested_hosted_runner_label",
    "billing_read_status",
    "included_compute_remaining",
    "bounded_required_cost",
    "overage_allowed",
    "pr_head_matches_run",
    "job_is_live_queued_attempt",
)

FORBIDDEN_UNTRUSTED_KEYS = frozenset(
    {
        "callback_url",
        "dispatch_url",
        "arbitrary_path",
        "arbitrary_url",
        "model_suggested_execute",
        "api_key",
        "access_token",
        "workflow_dispatch_input",
    }
)

ROUTE_HOSTED_CLEAN_ELIGIBLE = "HOSTED_CLEAN_ELIGIBLE"
HOLD_BILLING_UNKNOWN = "HOLD_BILLING_UNKNOWN"
HOLD_BILLING_INSUFFICIENT = "HOLD_BILLING_INSUFFICIENT"
HOLD_ISOLATED_JIT = "HOLD_ISOLATED_JIT"
HOLD_STALE_OR_DUPLICATE = "HOLD_STALE_OR_DUPLICATE"
HOLD_PROVIDER_CAPACITY = "HOLD_PROVIDER_CAPACITY"
HOLD_WORKLOAD_NOT_ELIGIBLE = "HOLD_WORKLOAD_NOT_ELIGIBLE"
HOLD_DATA_CLASSIFICATION = "HOLD_DATA_CLASSIFICATION"
HOLD_METADATA_INCOMPLETE = "HOLD_METADATA_INCOMPLETE"
HOLD_UNTRUSTED_INPUT = "HOLD_UNTRUSTED_INPUT"
HOLD_PROTECTED_WORKFLOW = "HOLD_PROTECTED_WORKFLOW"
HOLD_OVERAGE_POLICY = "HOLD_OVERAGE_POLICY"
HOLD_RUNNER_NOT_BLOCKED = "HOLD_RUNNER_NOT_BLOCKED"
HOLD_NONSTANDARD_RUNNER = "HOLD_NONSTANDARD_RUNNER"
HOLD_PARALLEL_ACTIVE_JOB = "HOLD_PARALLEL_ACTIVE_JOB"
HOLD_PR_HEAD_STALE = "HOLD_PR_HEAD_STALE"
HOLD_CANCELLED_NOT_REPLAYABLE = "HOLD_CANCELLED_NOT_REPLAYABLE"
HOLD_JOB_NOT_QUEUED = "HOLD_JOB_NOT_QUEUED"


def _hold(reason: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "execute": False,
        "recommended_route": reason,
        "detail": detail,
    }


def _eligible(detail: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "execute": False,
        "recommended_route": ROUTE_HOSTED_CLEAN_ELIGIBLE,
        "detail": detail,
    }


def _workflow_is_protected(workflow_id: str) -> bool:
    lowered = workflow_id.casefold()
    return any(marker in lowered for marker in PROTECTED_WORKFLOW_MARKERS)


def plan_fallback(payload: Mapping[str, Any]) -> dict[str, Any]:
    if type(payload) is not dict:
        return _hold(HOLD_UNTRUSTED_INPUT, "payload must be a closed dict")

    for key in FORBIDDEN_UNTRUSTED_KEYS:
        if key in payload:
            return _hold(HOLD_UNTRUSTED_INPUT, f"forbidden field present: {key}")

    # Owner override text is advisory only — never elevates to execute.
    if payload.get("owner_override_text"):
        pass

    missing = [field for field in REQUIRED_FIELDS if field not in payload]
    if missing:
        return _hold(HOLD_METADATA_INCOMPLETE, f"missing fields: {','.join(missing)}")

    if payload["schema_version"] != SCHEMA_VERSION:
        return _hold(HOLD_METADATA_INCOMPLETE, "schema_version mismatch")

    if payload["workload_class"] != WORKLOAD_CLASS_ALLOWED:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "workload_class not allowlisted")

    workflow_id = payload["workflow_id"]
    if type(workflow_id) is not str or not workflow_id:
        return _hold(HOLD_METADATA_INCOMPLETE, "workflow_id required")
    if _workflow_is_protected(workflow_id):
        return _hold(HOLD_PROTECTED_WORKFLOW, "protected or isolated workflow")
    if workflow_id not in ALLOWED_WORKFLOW_IDS:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "workflow_id not in source allowlist")

    profile_id = payload["profile_id"]
    if profile_id not in ALLOWED_PROFILE_IDS:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "profile_id not in source allowlist")

    repository = payload["repository"]
    if repository not in ALLOWED_REPOSITORIES:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "repository not in source allowlist")

    if not payload["pr_head_matches_run"]:
        return _hold(HOLD_PR_HEAD_STALE, "run head does not match current PR head")

    if not payload["job_is_live_queued_attempt"]:
        return _hold(HOLD_CANCELLED_NOT_REPLAYABLE, "job is not a live queued attempt")

    if payload["job_status"] != "queued":
        return _hold(HOLD_JOB_NOT_QUEUED, "job_status must be queued")

    if not payload["queued_within_approved_timeout"]:
        return _hold(HOLD_STALE_OR_DUPLICATE, "queued beyond approved timeout window")

    if payload["runner_assigned"]:
        return _hold(HOLD_PROVIDER_CAPACITY, "runner already assigned to job")

    if not payload["private_capacity_blocked"]:
        return _hold(HOLD_RUNNER_NOT_BLOCKED, "private capacity not provider-positive blocked")

    if payload["active_duplicate_local_or_jit_job"]:
        return _hold(HOLD_PARALLEL_ACTIVE_JOB, "duplicate active local or JIT job")

    if payload["data_classification"] not in CLEAN_DATA_CLASSIFICATIONS:
        return _hold(HOLD_DATA_CLASSIFICATION, "data classification not clean secretless")

    label = payload["requested_hosted_runner_label"]
    if label not in STANDARD_HOSTED_RUNNER_LABELS:
        return _hold(HOLD_NONSTANDARD_RUNNER, "requested hosted runner label not standard")

    billing_status = payload["billing_read_status"]
    if billing_status in {"UNKNOWN", "FORBIDDEN_403", "403"}:
        return _hold(HOLD_BILLING_UNKNOWN, "billing read unavailable")
    if billing_status != "OK":
        return _hold(HOLD_BILLING_UNKNOWN, "billing read status not OK")

    if payload["overage_allowed"] is not False:
        return _hold(HOLD_OVERAGE_POLICY, "overage_allowed must be false")

    remaining = payload["included_compute_remaining"]
    required = payload["bounded_required_cost"]
    if type(remaining) not in (int, float) or type(required) not in (int, float):
        return _hold(HOLD_BILLING_UNKNOWN, "billing amounts must be numeric")
    if remaining <= 0:
        return _hold(HOLD_BILLING_INSUFFICIENT, "no included compute remaining")
    if remaining < required:
        return _hold(HOLD_BILLING_INSUFFICIENT, "included headroom below bounded required cost")

    return _eligible(
        "secretless deterministic validation may use standard GitHub-hosted runner; "
        "planner does not dispatch"
    )
