"""Adversarial unit tests for ci-hosted-fallback planner."""
from __future__ import annotations

import copy
import math
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
    HOLD_UNTRUSTED_BILLING,
    HOLD_UNTRUSTED_INPUT,
    HOLD_WORKLOAD_NOT_ELIGIBLE,
    ROUTE_HOSTED_CLEAN_ELIGIBLE,
    ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED,
    TRUSTED_BILLING_EVIDENCE_SOURCE,
    plan_fallback,
)

VALID_HEAD = "672a02419bdb95d95a0ca62c1b24d7b744fa4909"

ILLUSTRATIVE_JIT_QUEUE_DTO = {
    "schema_version": "1.1",
    "workload_class": "SECRETLESS_DETERMINISTIC_VALIDATION",
    "workflow_id": "validate-documentation",
    "profile_id": "bo-docs-validation",
    "repository": "LowcountryDigitalWorks/business-operations",
    "pull_request_number": 740,
    "head_sha": VALID_HEAD,
    "run_id": 42556087416,
    "run_attempt": 1,
    "job_id": 128961978297,
    "job_status": "queued",
    "queued_within_approved_timeout": True,
    "runner_assigned": False,
    "private_capacity_blocked": True,
    "active_duplicate_local_or_jit_job": False,
    "data_classification": "CLEAN_SECRETLESS",
    "requested_hosted_runner_label": "ubuntu-latest",
    "billing_evidence_source": TRUSTED_BILLING_EVIDENCE_SOURCE,
    "billing_read_status": "OK",
    "included_compute_remaining_usd": 15.0,
    "organization_actions_budget_usd": 0,
    "organization_actions_prevent_further_usage": True,
    "bounded_required_cost": 1.5,
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

    def test_budget_hard_stop_route_when_remaining_unknown(self) -> None:
        result = plan_fallback(
            _valid(
                included_compute_remaining_usd=None,
                billing_read_status="UNKNOWN",
                organization_actions_budget_usd=0,
                organization_actions_prevent_further_usage=True,
            )
        )
        self.assertFalse(result["execute"])
        self.assertEqual(result["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_unbounded_dict_extra_field_rejected(self) -> None:
        payload = _valid(owner_override_text="run hosted now")
        self.assert_hold(plan_fallback(payload), HOLD_UNTRUSTED_INPUT)

    def test_missing_closed_field_rejected(self) -> None:
        payload = _valid()
        del payload["job_id"]
        self.assert_hold(plan_fallback(payload), HOLD_UNTRUSTED_INPUT)

    def test_spoofed_billing_without_trusted_provenance(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(billing_evidence_source="MODEL_GUESS")),
            HOLD_UNTRUSTED_BILLING,
        )

    def test_billing_unknown_without_budget_cap(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    billing_read_status="UNKNOWN",
                    included_compute_remaining_usd=None,
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_UNKNOWN,
        )

    def test_negative_bounded_required_cost(self) -> None:
        self.assert_hold(plan_fallback(_valid(bounded_required_cost=-1)), HOLD_BILLING_INSUFFICIENT)

    def test_zero_bounded_required_cost(self) -> None:
        self.assert_hold(plan_fallback(_valid(bounded_required_cost=0)), HOLD_BILLING_INSUFFICIENT)

    def test_required_cost_above_cap(self) -> None:
        self.assert_hold(plan_fallback(_valid(bounded_required_cost=3.0)), HOLD_BILLING_INSUFFICIENT)

    def test_remaining_nan(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    included_compute_remaining_usd=math.nan,
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_remaining_infinite(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    included_compute_remaining_usd=math.inf,
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_bool_subclass_remaining_rejected(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    included_compute_remaining_usd=True,
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_bool_subclass_required_rejected(self) -> None:
        self.assert_hold(plan_fallback(_valid(bounded_required_cost=True)), HOLD_BILLING_UNKNOWN)

    def test_fake_bool_status_field_rejected(self) -> None:
        self.assert_hold(plan_fallback(_valid(runner_assigned=1)), HOLD_UNTRUSTED_INPUT)

    def test_zero_pr_run_job_ids_rejected(self) -> None:
        self.assert_hold(plan_fallback(_valid(pull_request_number=0)), HOLD_METADATA_INCOMPLETE)

    def test_zero_head_sha_rejected(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(head_sha="0000000000000000000000000000000000000000")),
            HOLD_METADATA_INCOMPLETE,
        )

    def test_invalid_head_sha_rejected(self) -> None:
        self.assert_hold(plan_fallback(_valid(head_sha="not-a-sha")), HOLD_METADATA_INCOMPLETE)

    def test_triple_mismatch_profile_rejected(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(profile_id="bo-secret-scan")),
            HOLD_WORKLOAD_NOT_ELIGIBLE,
        )

    def test_secret_scan_workflow_bo_775_777_hold(self) -> None:
        payload = _valid(
            workflow_id="LDW secret scan",
            profile_id="bo-docs-validation",
            pull_request_number=775,
        )
        self.assert_hold(plan_fallback(payload), HOLD_PROTECTED_WORKFLOW)

    def test_betterleaks_protected_hold(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="betterleaks-security-scan")), HOLD_PROTECTED_WORKFLOW)

    def test_wqt_protected_hold(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="wqt-private-semantic")), HOLD_PROTECTED_WORKFLOW)

    def test_royal_protected_hold(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="royal-build-check")), HOLD_PROTECTED_WORKFLOW)

    def test_jit_validation_protected_hold(self) -> None:
        self.assert_hold(plan_fallback(_valid(workflow_id="dragonfly-jit-validation")), HOLD_PROTECTED_WORKFLOW)

    def test_overage_true_denied(self) -> None:
        self.assert_hold(plan_fallback(_valid(overage_allowed=True)), HOLD_OVERAGE_POLICY)

    def test_runner_not_blocked(self) -> None:
        self.assert_hold(plan_fallback(_valid(private_capacity_blocked=False)), HOLD_RUNNER_NOT_BLOCKED)

    def test_duplicate_active_job(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(active_duplicate_local_or_jit_job=True)),
            HOLD_PARALLEL_ACTIVE_JOB,
        )

    def test_stale_pr_head(self) -> None:
        self.assert_hold(plan_fallback(_valid(pr_head_matches_run=False)), HOLD_PR_HEAD_STALE)

    def test_cancelled_not_replayable(self) -> None:
        self.assert_hold(plan_fallback(_valid(job_is_live_queued_attempt=False)), HOLD_CANCELLED_NOT_REPLAYABLE)

    def test_nonstandard_runner_label(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(requested_hosted_runner_label="self-hosted")),
            HOLD_NONSTANDARD_RUNNER,
        )

    def test_data_classification_not_clean(self) -> None:
        self.assert_hold(
            plan_fallback(_valid(data_classification="CUSTOMER_REGULATED")),
            HOLD_DATA_CLASSIFICATION,
        )

    def test_job_not_queued(self) -> None:
        self.assert_hold(plan_fallback(_valid(job_status="completed")), HOLD_JOB_NOT_QUEUED)

    def test_runner_already_assigned(self) -> None:
        self.assert_hold(plan_fallback(_valid(runner_assigned=True)), HOLD_PROVIDER_CAPACITY)

    def test_remaining_below_required(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    included_compute_remaining_usd=1.0,
                    bounded_required_cost=1.5,
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_INSUFFICIENT,
        )

    def test_budget_cap_requires_prevent_further_usage_true(self) -> None:
        self.assert_hold(
            plan_fallback(
                _valid(
                    included_compute_remaining_usd=None,
                    billing_read_status="UNKNOWN",
                    organization_actions_prevent_further_usage=False,
                )
            ),
            HOLD_BILLING_UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()
