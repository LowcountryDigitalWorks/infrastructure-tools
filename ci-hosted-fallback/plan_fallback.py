"""GitHub-hosted fallback eligibility planner (business-operations #552).

Pure deterministic classifier: never dispatches, cancels, or reruns workflows.
Returns execute=false always with a plan route or explicit HOLD reason.

Billing/cost fields are TRUSTED_ORCHESTRATOR_ATTESTATION only when
billing_evidence_source is an accepted provenance marker. Model- or
caller-invented ``billing_read_status=OK`` without that provenance is rejected.
"""
from __future__ import annotations

import math
import re
from typing import Any, Mapping

SCHEMA_VERSION = "1.1"
WORKLOAD_CLASS_ALLOWED = "SECRETLESS_DETERMINISTIC_VALIDATION"
TRUSTED_BILLING_EVIDENCE_SOURCE = "GITHUB_ORG_ADMIN_READ"

ALLOWED_WORKFLOW_PROFILE_REPOSITORY = frozenset(
    {
        (
            "validate-documentation",
            "bo-docs-validation",
            "LowcountryDigitalWorks/business-operations",
        ),
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

APPROVED_BOUNDED_REQUIRED_COST_CAP_USD = 2.0

REQUIRED_FIELDS = frozenset(
    {
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
        "billing_evidence_source",
        "billing_read_status",
        "included_compute_remaining_usd",
        "organization_actions_budget_usd",
        "organization_actions_prevent_further_usage",
        "bounded_required_cost",
        "overage_allowed",
        "pr_head_matches_run",
        "job_is_live_queued_attempt",
    }
)

ROUTE_HOSTED_CLEAN_ELIGIBLE = "HOSTED_CLEAN_ELIGIBLE"
ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED = "HOSTED_CLEAN_PLAN_BUDGET_CAPPED"
HOLD_BILLING_UNKNOWN = "HOLD_BILLING_UNKNOWN"
HOLD_BILLING_INSUFFICIENT = "HOLD_BILLING_INSUFFICIENT"
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
HOLD_UNTRUSTED_BILLING = "HOLD_UNTRUSTED_BILLING"

_HEAD_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _hold(reason: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "execute": False,
        "recommended_route": reason,
        "detail": detail,
    }


def _plan(route: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "execute": False,
        "recommended_route": route,
        "detail": detail,
    }


def _workflow_is_protected(workflow_id: str) -> bool:
    lowered = workflow_id.casefold()
    return any(marker in lowered for marker in PROTECTED_WORKFLOW_MARKERS)


def _is_exact_bool(value: object) -> bool:
    return type(value) is bool


def _positive_int(value: object) -> int | None:
    if type(value) is not int or isinstance(value, bool):
        return None
    if value <= 0:
        return None
    return value


def _valid_head_sha(value: object) -> str | None:
    if type(value) is not str:
        return None
    if not _HEAD_SHA_RE.fullmatch(value):
        return None
    if set(value) == {"0"}:
        return None
    return value


def _finite_nonbool_number(value: object) -> float | None:
    if type(value) not in (int, float) or isinstance(value, bool):
        return None
    as_float = float(value)
    if not math.isfinite(as_float):
        return None
    return as_float


def _nullable_finite_nonnegative_usd(value: object) -> float | None | str:
    if value is None:
        return None
    parsed = _finite_nonbool_number(value)
    if parsed is None:
        return "invalid"
    if parsed < 0:
        return "invalid"
    return parsed


def _closed_payload(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    if type(payload) is not dict:
        return None
    if len(payload) != len(REQUIRED_FIELDS):
        return None
    if set(payload.keys()) != REQUIRED_FIELDS:
        return None
    return dict(payload)


def _billing_trusted(payload: dict[str, Any]) -> bool:
    return payload["billing_evidence_source"] == TRUSTED_BILLING_EVIDENCE_SOURCE


def _budget_hard_stop_capped(payload: dict[str, Any]) -> bool:
    budget = _finite_nonbool_number(payload["organization_actions_budget_usd"])
    if budget is None or budget != 0:
        return False
    if not _is_exact_bool(payload["organization_actions_prevent_further_usage"]):
        return False
    return payload["organization_actions_prevent_further_usage"] is True


def _included_headroom_ok(payload: dict[str, Any], required: float) -> bool:
    remaining = _nullable_finite_nonnegative_usd(payload["included_compute_remaining_usd"])
    if remaining is None:
        return False
    if remaining == "invalid":
        return False
    if payload["billing_read_status"] != "OK":
        return False
    return remaining >= required


def plan_fallback(payload: Mapping[str, Any]) -> dict[str, Any]:
    closed = _closed_payload(payload)
    if closed is None:
        return _hold(
            HOLD_UNTRUSTED_INPUT,
            "payload must be a closed dict with exact required fields only",
        )

    if closed["schema_version"] != SCHEMA_VERSION:
        return _hold(HOLD_METADATA_INCOMPLETE, "schema_version mismatch")

    if closed["workload_class"] != WORKLOAD_CLASS_ALLOWED:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "workload_class not allowlisted")

    workflow_id = closed["workflow_id"]
    profile_id = closed["profile_id"]
    repository = closed["repository"]
    if type(workflow_id) is not str or not workflow_id:
        return _hold(HOLD_METADATA_INCOMPLETE, "workflow_id must be a non-empty string")
    if type(profile_id) is not str or type(repository) is not str:
        return _hold(HOLD_METADATA_INCOMPLETE, "profile_id and repository must be strings")

    if _workflow_is_protected(workflow_id):
        return _hold(HOLD_PROTECTED_WORKFLOW, "protected or isolated workflow")

    triple = (workflow_id, profile_id, repository)
    if triple not in ALLOWED_WORKFLOW_PROFILE_REPOSITORY:
        return _hold(HOLD_WORKLOAD_NOT_ELIGIBLE, "workflow/profile/repository triple not allowlisted")

    pr_number = _positive_int(closed["pull_request_number"])
    run_id = _positive_int(closed["run_id"])
    run_attempt = _positive_int(closed["run_attempt"])
    job_id = _positive_int(closed["job_id"])
    if pr_number is None or run_id is None or job_id is None:
        return _hold(HOLD_METADATA_INCOMPLETE, "pull_request_number, run_id, and job_id must be positive ints")
    if run_attempt is None:
        return _hold(HOLD_METADATA_INCOMPLETE, "run_attempt must be a positive int")

    head_sha = _valid_head_sha(closed["head_sha"])
    if head_sha is None:
        return _hold(HOLD_METADATA_INCOMPLETE, "head_sha must be 40-char lowercase hex with nonzero digest")

    for flag in (
        "queued_within_approved_timeout",
        "runner_assigned",
        "private_capacity_blocked",
        "active_duplicate_local_or_jit_job",
        "pr_head_matches_run",
        "job_is_live_queued_attempt",
        "overage_allowed",
    ):
        if not _is_exact_bool(closed[flag]):
            return _hold(HOLD_UNTRUSTED_INPUT, f"{flag} must be exact bool")

    if type(closed["job_status"]) is not str:
        return _hold(HOLD_METADATA_INCOMPLETE, "job_status must be string")

    if not closed["pr_head_matches_run"]:
        return _hold(HOLD_PR_HEAD_STALE, "run head does not match current PR head")

    if not closed["job_is_live_queued_attempt"]:
        return _hold(HOLD_CANCELLED_NOT_REPLAYABLE, "job is not a live queued attempt")

    if closed["job_status"] != "queued":
        return _hold(HOLD_JOB_NOT_QUEUED, "job_status must be queued")

    if not closed["queued_within_approved_timeout"]:
        return _hold(HOLD_STALE_OR_DUPLICATE, "queued beyond approved timeout window")

    if closed["runner_assigned"]:
        return _hold(HOLD_PROVIDER_CAPACITY, "runner already assigned to job")

    if not closed["private_capacity_blocked"]:
        return _hold(HOLD_RUNNER_NOT_BLOCKED, "private capacity not provider-positive blocked")

    if closed["active_duplicate_local_or_jit_job"]:
        return _hold(HOLD_PARALLEL_ACTIVE_JOB, "duplicate active local or JIT job")

    if closed["data_classification"] not in CLEAN_DATA_CLASSIFICATIONS:
        return _hold(HOLD_DATA_CLASSIFICATION, "data classification not clean secretless")

    label = closed["requested_hosted_runner_label"]
    if type(label) is not str or label not in STANDARD_HOSTED_RUNNER_LABELS:
        return _hold(HOLD_NONSTANDARD_RUNNER, "requested hosted runner label not standard")

    if closed["overage_allowed"] is not False:
        return _hold(HOLD_OVERAGE_POLICY, "overage_allowed must be false")

    if not _billing_trusted(closed):
        return _hold(HOLD_UNTRUSTED_BILLING, "billing attestation lacks trusted orchestrator provenance")

    billing_status = closed["billing_read_status"]

    required = _finite_nonbool_number(closed["bounded_required_cost"])
    if required is None:
        return _hold(HOLD_BILLING_UNKNOWN, "bounded_required_cost must be finite number")
    if not (0 < required <= APPROVED_BOUNDED_REQUIRED_COST_CAP_USD):
        return _hold(HOLD_BILLING_INSUFFICIENT, "bounded_required_cost outside approved cap")

    if _included_headroom_ok(closed, required):
        return _plan(
            ROUTE_HOSTED_CLEAN_ELIGIBLE,
            "included headroom with trusted admin read; planner does not dispatch",
        )

    if _budget_hard_stop_capped(closed):
        return _plan(
            ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED,
            "organization Actions $0 hard stop with trusted admin read; planner does not dispatch",
        )

    if billing_status in {"UNKNOWN", "FORBIDDEN_403", "403"}:
        return _hold(HOLD_BILLING_UNKNOWN, "billing read unavailable")

    if closed["included_compute_remaining_usd"] is None:
        return _hold(HOLD_BILLING_UNKNOWN, "included compute remaining unknown and budget cap path not satisfied")

    return _hold(HOLD_BILLING_INSUFFICIENT, "included headroom below bounded required cost")
