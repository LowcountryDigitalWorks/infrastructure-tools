"""Trusted host-side GitHub provider read adapter for #552 (plan-only).

GET-only, fixed org/repo/workflow allowlist, no dispatch/mutation/credentials.
Produces a closed DTO suitable for :func:`plan_fallback` with
``billing_evidence_source=GITHUB_ORG_ADMIN_READ`` only when reads succeed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Callable, Mapping

from plan_fallback import (
    SCHEMA_VERSION,
    TRUSTED_BILLING_EVIDENCE_SOURCE,
    WORKLOAD_CLASS_ALLOWED,
    plan_fallback,
)

READBACK_SCHEMA_VERSION = "1.0"
ALLOWED_ORGANIZATION = "LowcountryDigitalWorks"
ALLOWED_REPOSITORY = "LowcountryDigitalWorks/business-operations"
ALLOWED_WORKFLOW_ID = "validate-documentation"
ALLOWED_PROFILE_ID = "bo-docs-validation"
TRUSTED_CALLER_IDENTITIES = frozenset(
    {
        "LDW_HOST_GH_ADAPTER",
    }
)

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
        "queued_within_approved_timeout",
        "data_classification",
    }
)

MAX_API_BYTES = 262_144
QUEUED_TIMEOUT_MAX_SECONDS = 86_400

GhRunner = Callable[[list[str]], tuple[int, str]]

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
    return completed.returncode, completed.stdout


def _parse_json_bounded(raw: str) -> dict[str, Any] | list[Any] | None:
    if len(raw.encode("utf-8")) > MAX_API_BYTES:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if type(parsed) not in (dict, list):
        return None
    return parsed


def _closed_read_request(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    if type(payload) is not dict:
        return None
    if len(payload) != len(READ_REQUEST_FIELDS):
        return None
    if set(payload.keys()) != READ_REQUEST_FIELDS:
        return None
    return dict(payload)


def _actions_budget_zero(payload: dict[str, Any] | list[Any]) -> tuple[float | None, bool | None]:
    items: list[dict[str, Any]]
    if type(payload) is dict:
        items = payload.get("budgets", [])  # type: ignore[assignment]
        if type(items) is not list:
            return None, None
    elif type(payload) is list:
        items = payload
    else:
        return None, None
    for item in items:
        if type(item) is not dict:
            continue
        sku = str(item.get("sku", "")).casefold()
        if sku != "actions":
            continue
        budget_amount = item.get("budget_amount", item.get("amount"))
        prevent = item.get("prevent_further_usage", item.get("prevent_overages"))
        budget_usd: float | None = None
        if type(budget_amount) in (int, float) and not isinstance(budget_amount, bool):
            budget_usd = float(budget_amount)
        elif type(budget_amount) is dict:
            value = budget_amount.get("value")
            if type(value) in (int, float) and not isinstance(value, bool):
                budget_usd = float(value)
        prevent_bool = prevent if type(prevent) is bool else None
        return budget_usd, prevent_bool
    return None, None


def read_provider_readback(
    request: Mapping[str, Any],
    *,
    gh_runner: GhRunner | None = None,
) -> dict[str, Any]:
    """Fetch fixed GitHub metadata and return planner input or redacted HOLD code."""
    closed = _closed_read_request(request)
    if closed is None:
        return _redacted_hold(READ_UNTRUSTED_INPUT)

    if closed["schema_version"] != READBACK_SCHEMA_VERSION:
        return _redacted_hold(READ_UNTRUSTED_INPUT)

    if closed["trusted_caller"] not in TRUSTED_CALLER_IDENTITIES:
        return _redacted_hold(READ_UNTRUSTED_CALLER)

    if closed["data_classification"] != "CLEAN_SECRETLESS":
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)

    runner = gh_runner or _default_gh_runner

    budgets_code, budgets_raw = runner(
        ["api", f"/orgs/{ALLOWED_ORGANIZATION}/settings/billing/budgets?per_page=100"]
    )
    if budgets_code == 127:
        return _redacted_hold(READ_GH_UNAVAILABLE)
    if budgets_code in {401, 403}:
        return _redacted_hold(READ_GH_FORBIDDEN if budgets_code == 403 else READ_GH_AUTH)
    if budgets_code == 404:
        return _redacted_hold(READ_GH_NOT_FOUND)
    if budgets_code != 0:
        return _redacted_hold(READ_GH_UNAVAILABLE)

    budgets_json = _parse_json_bounded(budgets_raw)
    if budgets_json is None:
        return _redacted_hold(READ_GH_MALFORMED)
    budget_usd, prevent_usage = _actions_budget_zero(budgets_json)

    repo_slug = ALLOWED_REPOSITORY
    job_id = closed["job_id"]
    run_id = closed["run_id"]
    pr_number = closed["pull_request_number"]

    job_code, job_raw = runner(["api", f"/repos/{repo_slug}/actions/jobs/{job_id}"])
    if job_code != 0:
        return _redacted_hold(READ_GH_NOT_FOUND if job_code == 404 else READ_GH_UNAVAILABLE)
    job_json = _parse_json_bounded(job_raw)
    if type(job_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    run_code, run_raw = runner(["api", f"/repos/{repo_slug}/actions/runs/{run_id}"])
    if run_code != 0:
        return _redacted_hold(READ_GH_NOT_FOUND if run_code == 404 else READ_GH_UNAVAILABLE)
    run_json = _parse_json_bounded(run_raw)
    if type(run_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    pr_code, pr_raw = runner(["api", f"/repos/{repo_slug}/pulls/{pr_number}"])
    if pr_code != 0:
        return _redacted_hold(READ_GH_NOT_FOUND if pr_code == 404 else READ_GH_UNAVAILABLE)
    pr_json = _parse_json_bounded(pr_raw)
    if type(pr_json) is not dict:
        return _redacted_hold(READ_GH_MALFORMED)

    expected_head = closed["head_sha"]
    pr_head = pr_json.get("head", {})
    run_head = run_json.get("head_sha")
    if type(pr_head) is not dict:
        return _redacted_hold(READ_STALE_IDENTITY)
    pr_head_sha = pr_head.get("sha")
    if type(pr_head_sha) is not str or type(run_head) is not str:
        return _redacted_hold(READ_STALE_IDENTITY)
    if pr_head_sha != expected_head or run_head != expected_head:
        return _redacted_hold(READ_STALE_IDENTITY)

    run_attempt = run_json.get("run_attempt")
    if run_attempt != closed["run_attempt"]:
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

    if not closed["queued_within_approved_timeout"]:
        return _redacted_hold(READ_JOB_NOT_ELIGIBLE)

    planner_input = {
        "schema_version": SCHEMA_VERSION,
        "workload_class": WORKLOAD_CLASS_ALLOWED,
        "workflow_id": ALLOWED_WORKFLOW_ID,
        "profile_id": ALLOWED_PROFILE_ID,
        "repository": ALLOWED_REPOSITORY,
        "pull_request_number": pr_number,
        "head_sha": expected_head,
        "run_id": run_id,
        "run_attempt": closed["run_attempt"],
        "job_id": job_id,
        "job_status": "queued",
        "queued_within_approved_timeout": True,
        "runner_assigned": runner_assigned,
        "private_capacity_blocked": closed["private_capacity_blocked"],
        "active_duplicate_local_or_jit_job": closed["active_duplicate_local_or_jit_job"],
        "data_classification": "CLEAN_SECRETLESS",
        "requested_hosted_runner_label": closed["requested_hosted_runner_label"],
        "billing_evidence_source": TRUSTED_BILLING_EVIDENCE_SOURCE,
        "billing_read_status": "UNKNOWN",
        "included_compute_remaining_usd": None,
        "organization_actions_budget_usd": budget_usd,
        "organization_actions_prevent_further_usage": prevent_usage,
        "bounded_required_cost": closed["bounded_required_cost"],
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


def evaluate_provider_plan(request: Mapping[str, Any], *, gh_runner: GhRunner | None = None) -> dict[str, Any]:
    """Run trusted readback then :func:`plan_fallback` (still ``execute:false``)."""
    readback = read_provider_readback(request, gh_runner=gh_runner)
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
