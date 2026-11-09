"""Trusted host-side GitHub provider read adapter for #552 (plan-only).

GET-only, fixed org/repo/workflow allowlist, no dispatch/mutation/credentials.
Produces a closed DTO suitable for :func:`plan_fallback` with
``billing_evidence_source=GITHUB_ORG_ADMIN_READ`` only when reads succeed.

``trusted_caller`` and request JSON cannot prove protected host identity.
Capacity attestations require injected :class:`TrustedHostEvidence` (not serializable in the request).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from plan_fallback import (
    APPROVED_BOUNDED_REQUIRED_COST_CAP_USD,
    SCHEMA_VERSION,
    STANDARD_HOSTED_RUNNER_LABELS,
    TRUSTED_BILLING_EVIDENCE_SOURCE,
    WORKLOAD_CLASS_ALLOWED,
    _HEAD_SHA_RE,
    plan_fallback,
)

READBACK_SCHEMA_VERSION = "1.2"
ALLOWED_ORGANIZATION = "LowcountryDigitalWorks"
ALLOWED_REPOSITORY = "LowcountryDigitalWorks/business-operations"
ALLOWED_WORKFLOW_ID = "validate-documentation"
ALLOWED_PROFILE_ID = "bo-docs-validation"
TRUSTED_CALLER_IDENTITIES = frozenset(
    {
        "LDW_HOST_GH_ADAPTER",
    }
)
V0_INJECTED_ATTESTATION_KINDS = frozenset(
    {
        "LDW_PROTECTED_HOST_SYNTHETIC",
    }
)


class TrustedHostEvidence:
    """Non-serializable host attestation supplied by protected orchestrator code (not the request body)."""

    __slots__ = (
        "attestation_kind",
        "private_capacity_blocked_attested",
        "active_duplicate_local_or_jit_job_attested",
    )

    def __init__(
        self,
        *,
        attestation_kind: str,
        private_capacity_blocked_attested: bool,
        active_duplicate_local_or_jit_job_attested: bool,
    ) -> None:
        self.attestation_kind = attestation_kind
        self.private_capacity_blocked_attested = private_capacity_blocked_attested
        self.active_duplicate_local_or_jit_job_attested = active_duplicate_local_or_jit_job_attested


READ_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "trusted_caller",
        "pull_request_number",
        "head_sha",
        "run_id",
        "run_attempt",
        "job_id",
        "bounded_required_cost",
        "requested_hosted_runner_label",
        "private_capacity_blocked",
        "active_duplicate_local_or_jit_job",
        "data_classification",
    }
)

MAX_API_BYTES = 262_144
QUEUED_TIMEOUT_MAX_SECONDS = 86_400
_RUN_CREATED_AT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)

GhRunner = Callable[[list[str]], tuple[int, str]]
UtcNow = Callable[[], datetime]

READ_GH_UNAVAILABLE = "READ_GH_UNAVAILABLE"
READ_GH_AUTH = "READ_GH_AUTH"
READ_GH_FORBIDDEN = "READ_GH_FORBIDDEN"
READ_GH_NOT_FOUND = "READ_GH_NOT_FOUND"
READ_GH_MALFORMED = "READ_GH_MALFORMED"
READ_GH_OVERSIZE = "READ_GH_OVERSIZE"
READ_UNTRUSTED_CALLER = "READ_UNTRUSTED_CALLER"
READ_UNTRUSTED_INPUT = "READ_UNTRUSTED_INPUT"
READ_STALE_IDENTITY = "READ_STALE_IDENTITY"
READ_JOB_NOT_ELIGIBLE = "READ_JOB_NOT_ELIGIBLE"
READ_CAPACITY_UNVERIFIED = "READ_CAPACITY_UNVERIFIED"

_LIVE_RUN_STATUSES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})


def _utc_now_default() -> datetime:
    return datetime.now(timezone.utc)


def _redacted_hold(code: str) -> dict[str, Any]:
    return {
        "schema_version": READBACK_SCHEMA_VERSION,
        "execute": False,
        "readback_code": code,
        "planner_input": None,
    }


def _default_gh_runner(argv: list[str]) -> tuple[int, str]:
    executable = shutil.which("gh")
    if executable is None:
        return 127, ""
    try:
        completed = subprocess.run(
            [executable, *argv],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    stdout = completed.stdout if isinstance(completed.stdout, str) else ""
    if len(stdout.encode("utf-8", errors="replace")) > MAX_API_BYTES:
        return 1, ""
    return completed.returncode, stdout


def _map_gh_failure(code: int, raw: str) -> str:
    if code == 0:
        return "OK"
    if code == 127:
        return READ_GH_UNAVAILABLE
    if code == 401:
        return READ_GH_AUTH
    if code == 403:
        return READ_GH_FORBIDDEN
    if code == 404:
        return READ_GH_NOT_FOUND
    if raw:
        try:
            if len(raw.encode("utf-8")) <= MAX_API_BYTES:
                parsed = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError):
            parsed = None
        else:
            if type(parsed) is dict:
                status = parsed.get("status")
                if type(status) is int:
                    if status == 401:
                        return READ_GH_AUTH
                    if status == 403:
                        return READ_GH_FORBIDDEN
                    if status == 404:
                        return READ_GH_NOT_FOUND
    return READ_GH_UNAVAILABLE


def _parse_json_bounded(raw: str) -> dict[str, Any] | list[Any] | None:
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError:
        return None
    if len(encoded) > MAX_API_BYTES:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if type(parsed) not in (dict, list):
        return None
    return parsed


def _positive_int(value: Any, *, allow_zero: bool = False) -> int | None:
    if type(value) is not int or isinstance(value, bool):
        return None
    if allow_zero:
        if value < 0:
            return None
    elif value <= 0:
        return None
    return value


def _exact_bool(value: Any) -> bool | None:
    if type(value) is bool:
        return value
    return None


def _bounded_cost(value: Any) -> float | None:
    if type(value) not in (int, float) or isinstance(value, bool):
        return None
    cost = float(value)
    if not (cost > 0.0) or not (cost <= APPROVED_BOUNDED_REQUIRED_COST_CAP_USD):
        return None
    return cost


def _head_sha(value: Any) -> str | None:
    if type(value) is not str:
        return None
    if not _HEAD_SHA_RE.match(value):
        return None
    if value == "0" * 40:
        return None
    return value


def _accept_trusted_host_evidence(value: Any) -> TrustedHostEvidence | None:
    if not isinstance(value, TrustedHostEvidence):
        return None
    if value.attestation_kind not in V0_INJECTED_ATTESTATION_KINDS:
        return None
    blocked = value.private_capacity_blocked_attested
    duplicate = value.active_duplicate_local_or_jit_job_attested
    if type(blocked) is not bool or type(duplicate) is not bool:
        return None
    return value


def _validate_read_request(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    if type(payload) is not dict:
        return None
    if len(payload) != len(READ_REQUEST_FIELDS):
        return None
    if set(payload.keys()) != READ_REQUEST_FIELDS:
        return None
    if payload["schema_version"] != READBACK_SCHEMA_VERSION:
        return None
    if type(payload["trusted_caller"]) is not str:
        return None
    pr_number = _positive_int(payload["pull_request_number"])
    run_id = _positive_int(payload["run_id"])
    job_id = _positive_int(payload["job_id"])
    run_attempt = _positive_int(payload["run_attempt"])
    head_sha = _head_sha(payload["head_sha"])
    bounded_cost = _bounded_cost(payload["bounded_required_cost"])
    if None in (pr_number, run_id, job_id, run_attempt, head_sha, bounded_cost):
        return None
    label = payload["requested_hosted_runner_label"]
    if type(label) is not str or label not in STANDARD_HOSTED_RUNNER_LABELS:
        return None
    if payload["data_classification"] != "CLEAN_SECRETLESS":
        return None
    priv = _exact_bool(payload["private_capacity_blocked"])
    dup = _exact_bool(payload["active_duplicate_local_or_jit_job"])
    if priv is None or dup is None:
        return None
    return {
        "schema_version": READBACK_SCHEMA_VERSION,
        "trusted_caller": payload["trusted_caller"],
        "pull_request_number": pr_number,
        "head_sha": head_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job_id": job_id,
        "bounded_required_cost": bounded_cost,
        "requested_hosted_runner_label": label,
        "private_capacity_blocked_claim": priv,
        "active_duplicate_local_or_jit_job_claim": dup,
        "data_classification": "CLEAN_SECRETLESS",
    }


def _org_actions_budget(payload: dict[str, Any] | list[Any]) -> tuple[float | None, bool | None, bool]:
    """Return (amount, prevent, schema_ok). schema_ok False when duplicate/malformed Actions org rows."""
    items: list[Any]
    if type(payload) is dict:
        items = payload.get("budgets")
        if type(items) is not list:
            return None, None, False
    elif type(payload) is list:
        items = payload
    else:
        return None, None, False

    actions_org: list[dict[str, Any]] = []
    for item in items:
        if type(item) is not dict:
            continue
        if item.get("budget_product_sku") != "actions":
            continue
        if item.get("budget_scope") != "organization":
            continue
        actions_org.append(item)

    if len(actions_org) != 1:
        if len(actions_org) == 0:
            return None, None, True
        return None, None, False

    row = actions_org[0]
    budget_amount = row.get("budget_amount")
    prevent = row.get("prevent_further_usage")
    budget_usd: float | None = None
    if type(budget_amount) in (int, float) and not isinstance(budget_amount, bool):
        budget_usd = float(budget_amount)
    elif type(budget_amount) is dict:
        value = budget_amount.get("value")
        if type(value) in (int, float) and not isinstance(value, bool):
            budget_usd = float(value)
    prevent_bool = prevent if type(prevent) is bool else None
    return budget_usd, prevent_bool, True


def _parse_run_created_at(value: Any) -> datetime | None:
    if type(value) is not str or not _RUN_CREATED_AT_RE.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _queued_within_timeout(created_at: datetime, *, utc_now: UtcNow) -> bool:
    now = utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if created_at > now:
        return False
    age = (now - created_at).total_seconds()
    return 0 <= age <= QUEUED_TIMEOUT_MAX_SECONDS


def _run_lists_pr(run_json: dict[str, Any], pr_number: int) -> bool:
    entries = run_json.get("pull_requests")
    if type(entries) is not list:
        return False
    for entry in entries:
        if type(entry) is not dict:
            continue
        number = entry.get("number")
        if type(number) is int and not isinstance(number, bool) and number == pr_number:
            return True
    return False


def _capacity_flags_for_planner(
    validated: dict[str, Any],
    *,
    trusted_host_evidence: TrustedHostEvidence | None,
) -> tuple[bool, bool, str | None]:
    """Map caller claims + injected host evidence to planner flags; fail closed on unverified TRUE claims."""
    if trusted_host_evidence is None:
        return False, False, READ_UNTRUSTED_CALLER

    attested_blocked = trusted_host_evidence.private_capacity_blocked_attested
    attested_dup = trusted_host_evidence.active_duplicate_local_or_jit_job_attested
    claim_blocked = validated["private_capacity_blocked_claim"]
    claim_dup = validated["active_duplicate_local_or_jit_job_claim"]

    if claim_blocked and not attested_blocked:
        return False, False, READ_CAPACITY_UNVERIFIED
    if claim_dup and not attested_dup:
        return False, False, READ_CAPACITY_UNVERIFIED

    return attested_blocked, attested_dup, None


def read_provider_readback(
    request: Mapping[str, Any],
    *,
    gh_runner: GhRunner | None = None,
    utc_now: UtcNow | None = None,
    trusted_host_evidence: TrustedHostEvidence | None = None,
) -> dict[str, Any]:
    """Fetch fixed GitHub metadata and return planner input or redacted HOLD code."""
    validated = _validate_read_request(request)
    if validated is None:
        return _redacted_hold(READ_UNTRUSTED_INPUT)

    if validated["trusted_caller"] not in TRUSTED_CALLER_IDENTITIES:
        return _redacted_hold(READ_UNTRUSTED_CALLER)

    accepted_evidence = _accept_trusted_host_evidence(trusted_host_evidence)
    if trusted_host_evidence is not None and accepted_evidence is None:
        return _redacted_hold(READ_UNTRUSTED_CALLER)

    capacity_blocked, capacity_dup, capacity_hold = _capacity_flags_for_planner(
        validated,
        trusted_host_evidence=accepted_evidence,
    )
    if capacity_hold is not None:
        return _redacted_hold(capacity_hold)

    runner = gh_runner or _default_gh_runner
    clock = utc_now or _utc_now_default

    budgets_code, budgets_raw = runner(
        ["api", f"/orgs/{ALLOWED_ORGANIZATION}/settings/billing/budgets?per_page=100"]
    )
    budgets_hold = _map_gh_failure(budgets_code, budgets_raw)
    if budgets_hold != "OK":
        return _redacted_hold(budgets_hold)

    budgets_json = _parse_json_bounded(budgets_raw)
    if budgets_json is None:
        return _redacted_hold(READ_GH_MALFORMED)
    budget_usd, prevent_usage, budget_schema_ok = _org_actions_budget(budgets_json)
    if not budget_schema_ok:
        return _redacted_hold(READ_GH_MALFORMED)

    job_id = validated["job_id"]
    run_id = validated["run_id"]
    pr_number = validated["pull_request_number"]
    repo_slug = ALLOWED_REPOSITORY

    job_path = f"/repos/{repo_slug}/actions/jobs/{job_id}"
    run_path = f"/repos/{repo_slug}/actions/runs/{run_id}"
    pr_path = f"/repos/{repo_slug}/pulls/{pr_number}"

    job_code, job_raw = runner(["api", job_path])
    job_hold = _map_gh_failure(job_code, job_raw)
    if job_hold != "OK":
        return _redacted_hold(READ_GH_NOT_FOUND if job_hold == READ_GH_NOT_FOUND else job_hold)
    job_json = _parse_json_bounded(job_raw)
    if type(job_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    run_code, run_raw = runner(["api", run_path])
    run_hold = _map_gh_failure(run_code, run_raw)
    if run_hold != "OK":
        return _redacted_hold(READ_GH_NOT_FOUND if run_hold == READ_GH_NOT_FOUND else run_hold)
    run_json = _parse_json_bounded(run_raw)
    if type(run_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    pr_code, pr_raw = runner(["api", pr_path])
    pr_hold = _map_gh_failure(pr_code, pr_raw)
    if pr_hold != "OK":
        return _redacted_hold(READ_GH_NOT_FOUND if pr_hold == READ_GH_NOT_FOUND else pr_hold)
    pr_json = _parse_json_bounded(pr_raw)
    if type(pr_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    job_api_id = job_json.get("id")
    job_api_run_id = job_json.get("run_id")
    if job_api_id != job_id or job_api_run_id != run_id:
        return _redacted_hold(READ_STALE_IDENTITY)

    run_api_id = run_json.get("id")
    if run_api_id != run_id:
        return _redacted_hold(READ_STALE_IDENTITY)
    if run_json.get("event") != "pull_request":
        return _redacted_hold(READ_STALE_IDENTITY)

    run_status = run_json.get("status")
    if type(run_status) is not str or run_status not in _LIVE_RUN_STATUSES:
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)
    if run_json.get("conclusion") is not None:
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)

    if not _run_lists_pr(run_json, pr_number):
        return _redacted_hold(READ_STALE_IDENTITY)

    expected_head = validated["head_sha"]
    run_head = run_json.get("head_sha")
    if type(run_head) is not str or run_head != expected_head:
        return _redacted_hold(READ_STALE_IDENTITY)

    run_attempt = run_json.get("run_attempt")
    if run_attempt != validated["run_attempt"]:
        return _redacted_hold(READ_STALE_IDENTITY)

    created_at = _parse_run_created_at(run_json.get("created_at"))
    if created_at is None or not _queued_within_timeout(created_at, utc_now=clock):
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)

    pr_state = pr_json.get("state")
    pr_num = pr_json.get("number")
    if pr_state != "open" or pr_num != pr_number:
        return _redacted_hold(READ_STALE_IDENTITY)

    pr_head = pr_json.get("head")
    if type(pr_head) is not dict:
        return _redacted_hold(READ_STALE_IDENTITY)
    pr_head_sha = pr_head.get("sha")
    if type(pr_head_sha) is not str or pr_head_sha != expected_head:
        return _redacted_hold(READ_STALE_IDENTITY)
    pr_repo = pr_head.get("repo")
    if type(pr_repo) is not dict:
        return _redacted_hold(READ_STALE_IDENTITY)
    full_name = pr_repo.get("full_name")
    if type(full_name) is not str or full_name != ALLOWED_REPOSITORY:
        return _redacted_hold(READ_STALE_IDENTITY)

    status = job_json.get("status")
    conclusion = job_json.get("conclusion")
    runner_id = job_json.get("runner_id")
    runner_name = job_json.get("runner_name")

    if status != "queued":
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)
    if conclusion is not None:
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)

    runner_assigned = False
    if type(runner_id) is int and not isinstance(runner_id, bool) and runner_id > 0:
        runner_assigned = True
    if type(runner_name) is str and runner_name:
        runner_assigned = True

    planner_input = {
        "schema_version": SCHEMA_VERSION,
        "workload_class": WORKLOAD_CLASS_ALLOWED,
        "workflow_id": ALLOWED_WORKFLOW_ID,
        "profile_id": ALLOWED_PROFILE_ID,
        "repository": ALLOWED_REPOSITORY,
        "pull_request_number": pr_number,
        "head_sha": expected_head,
        "run_id": run_id,
        "run_attempt": validated["run_attempt"],
        "job_id": job_id,
        "job_status": status,
        "queued_within_approved_timeout": True,
        "runner_assigned": runner_assigned,
        "private_capacity_blocked": capacity_blocked,
        "active_duplicate_local_or_jit_job": capacity_dup,
        "data_classification": "CLEAN_SECRETLESS",
        "requested_hosted_runner_label": validated["requested_hosted_runner_label"],
        "billing_evidence_source": TRUSTED_BILLING_EVIDENCE_SOURCE,
        "billing_read_status": "UNKNOWN",
        "included_compute_remaining_usd": None,
        "organization_actions_budget_usd": budget_usd,
        "organization_actions_prevent_further_usage": prevent_usage,
        "bounded_required_cost": validated["bounded_required_cost"],
        "overage_allowed": False,
        "pr_head_matches_run": True,
        "job_is_live_queued_attempt": True,
    }

    return {
        "schema_version": READBACK_SCHEMA_VERSION,
        "execute": False,
        "readback_code": "READ_OK",
        "planner_input": planner_input,
    }


def evaluate_provider_plan(
    request: Mapping[str, Any],
    *,
    gh_runner: GhRunner | None = None,
    utc_now: UtcNow | None = None,
    trusted_host_evidence: TrustedHostEvidence | None = None,
) -> dict[str, Any]:
    """Run trusted readback then :func:`plan_fallback` (still ``execute:false``)."""
    readback = read_provider_readback(
        request,
        gh_runner=gh_runner,
        utc_now=utc_now,
        trusted_host_evidence=trusted_host_evidence,
    )
    if readback["planner_input"] is None:
        return {
            "schema_version": READBACK_SCHEMA_VERSION,
            "execute": False,
            "readback_code": readback["readback_code"],
            "planner_result": None,
        }
    planner_result = plan_fallback(readback["planner_input"])
    return {
        "schema_version": READBACK_SCHEMA_VERSION,
        "execute": False,
        "readback_code": "READ_OK",
        "planner_result": planner_result,
    }
