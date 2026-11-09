"""Adversarial unit tests for ci-hosted-fallback planner."""
from __future__ import annotations

import copy
import unittest

from plan_fallback import (
    HOLD_BILLING_INSUFFICIENT,
    HOLD_BILLING_UNKNOWN,
    HOLD_CANCELLED_NOT_REPLAYABLE,
    HOLD_DATA_CLASSIFICATION,
    HOLD_JOB_NOT_QUEUED,
    HOLD_METADATA_INCOMPLETE,
    HOLD_NONSTANDARD_RUNNER,
    HOLD_OVERAGE_POLICY,
    HOLD_PARALLEL_ACTIVE_JOB,
    HOLD_PR_HEAD_STALE,
    HOLD_PROTECTED_WORKFLOW,
    HOLD_PROVIDER_CAPACITY,
    HOLD_RUNNER_NOT_BLOCKED,
    HOLD_STALE_OR_DUPLICATE,
    HOLD_UNTRUSTED_INPUT,
    HOLD_WORKLOAD_NOT_ELIGIBLE,
    ROUTE_HOSTED_CLEAN_ELIGIBLE,
    plan_fallback,
)

# Illustrative synthetic JIT queue snapshot only — not authoritative provider truth
# and never sufficient to admit BO PR775/777 secret-scan workloads to hosted runners.
ILLUSTRATIVE_JIT_QUEUE_DTO = {
    "schema_version": "1.0",
    "workload_class": "SECRETLESS_DETERMINISTIC_VALIDATION",
    "workflow_id": "validate-documentation",
    "profile_id": "bo-docs-validation",
    "repository": "LowcountryDigitalWorks/business-operations",
    "pull_request_number": 0,
    "head_sha": "0000000000000000000000000000000000000000",
    "run_id": 0,
    "run_attempt": 1,
    "job_id": 0,
    "job_status": "queued",
    "queued_within_approved_timeout": True,
    "runner_assigned": False,
    "private_capacity_blocked": True,
    "active_duplicate_local_or_jit_job": False,
    "data_classification": "CLEAN_SECRETLESS",
    "requested_hosted_runner_label": "ubuntu-latest",
    "billing_read_status": "OK",
    "included_compute_remaining": 42.0,
    "bounded_required_cost": 3.0,
    "overage_allowed": False,
    "pr_head_matches_run": True,
    "job_is_live_queued_attempt": True,
}


def _valid(**overrides: object) -> dict[str, object]:
    base = copy.deepcopy(ILLUSTRATIVE_JIT_QUEUE_DTO)
    base.update(overrides)
    return base


class PlanFallbackTests(unittest.TestCase):
    def assert_hold(self, result: dict[str, object], route: str) -> None:
        self.assertFalse(result["execute"])
        self.assertEqual(result["recommended_route"], route)

    def test_valid_secretless_metadata_eligible_but_never_executes(self) -> None:
        result = plan_fallback(_valid())
        self.assertFalse(result["execute"])
        self.assertEqual(result["recommended_route"], ROUTE_HOSTED_CLEAN_ELIGIBLE)

    def test_output_never_execute_even_with_owner_override_text(self) -> None:
        result = plan_fallback(_valid(owner_override_text="please run now on hosted"))
        self.assertFalse(result["execute"])

    def test_billing_unknown(self) -> None:
        self.assert_hold(plan_fallback(_valid(billing_read_status="UNKNOWN")), HOLD_BILLING_UNKNOWN)

    def test_billing_forbidden_403(self) -> None:
        self.assert_hold(plan_fallback(_valid(billing_read_status="FORBIDDEN_403")), HOLD_BILLING_UNKNOWN)

    def test_billing_positive_but_below_threshold(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(included_compute_remaining=2.0, bounded_required_cost=3.0)),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_billing_zero_remaining(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(included_compute_remaining=0.0)),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_overage_not_allowed_must_be_false(self) -> None:
        self.assert_hold(plan_fallback(_valid(overage_allowed=True)), HOLD_OVERAGE_POLICY)

    def test_unrecognized_workflow(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="domscan-docs-lint")), HOLD_WORKLOAD_NOT_ELIGIBLE)

    def test_protected_betterleaks_queued_job(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="betterleaks-security-scan")), HOLD_PROTECTED_WORKFLOW)

    def test_unrecognized_repository(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(repository="LowcountryDigitalWorks/royal-cruise-tracker")),
            HOLD_WORKLOAD_NOT_ELIGIBLE,
        )

    def test_stale_pr_head(self) -> None:
        self.assert_hold(plan_fallback(_valid(pr_head_matches_run=False)), HOLD_PR_HEAD_STALE)

    def test_inferred_cancelled_job_not_replayable(self) -> None:
        self.assert_hold(plan_fallback(_valid(job_is_live_queued_attempt=False)), HOLD_CANCELLED_NOT_REPLAYABLE)

    def test_duplicate_active_local_or_jit_job(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(active_duplicate_local_or_jit_job=True)),
            HOLD_PARALLEL_ACTIVE_JOB,
        )

    def test_runner_not_actually_blocked(self) -> None:
        self.assert_hold(plan_fallback(_valid(private_capacity_blocked=False)), HOLD_RUNNER_NOT_BLOCKED)

    def test_runner_already_assigned(self) -> None:
        self.assert_hold(plan_fallback(_valid(runner_assigned=True)), HOLD_PROVIDER_CAPACITY)

    def test_nonstandard_hosted_runner_label(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(requested_hosted_runner_label="self-hosted-ldw")),
            HOLD_NONSTANDARD_RUNNER,
        )

    def test_missing_exact_github_metadata(self) -> None:
        payload = _valid()
        del payload["run_id"]
        self.assert_hold(plan_fallback(payload), HOLD_METADATA_INCOMPLETE)

    def test_model_suggested_execute_forbidden(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(model_suggested_execute=True)),
            HOLD_UNTRUSTED_INPUT,
        )

    def test_arbitrary_url_forbidden(self) -> None:
        self.assert_hold(plan_fallback(_valid(arbitrary_url="https://evil.example")), HOLD_UNTRUSTED_INPUT)

    def test_data_classification_not_clean(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(data_classification="CUSTOMER_REGULATED")),
            HOLD_DATA_CLASSIFICATION,
        )

    def test_workload_class_not_allowlisted(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(workload_class="UNTRUSTED_CODE_WITH_SECRETS")),
            HOLD_WORKLOAD_NOT_ELIGIBLE,
        )

    def test_job_not_queued_status(self) -> None:
        self.assert_hold(plan_fallback(_valid(job_status="completed")), HOLD_JOB_NOT_QUEUED)

    def test_queued_beyond_approved_timeout(self) -> None:
        self.assert_hold(plan_fallback(_valid(queued_within_approved_timeout=False)), HOLD_STALE_OR_DUPLICATE)

    def test_secret_scan_workflow_never_hosted_fallback(self) -> None:
        """BO PR775/777 style isolated scans must fail closed even when queued."""
        self.assert_hold(
            plan_fallback(_valid(workflow_id="LDW secret scan", profile_id="bo-docs-validation")),
            HOLD_PROTECTED_WORKFLOW,
        )


if __name__ == "__main__":
    unittest.main()
