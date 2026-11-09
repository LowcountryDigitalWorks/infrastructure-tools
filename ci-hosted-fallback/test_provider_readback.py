"""Offline adversarial tests for provider_readback (mocked gh only)."""
from __future__ import annotations

import json
import math
import unittest

from plan_fallback import (
    HOLD_PARALLEL_ACTIVE_JOB,
    HOLD_RUNNER_NOT_BLOCKED,
    ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED,
)
from provider_readback import (
    READ_GH_FORBIDDEN,
    READ_GH_MALFORMED,
    READ_GH_UNAVAILABLE,
    READ_JOB_NOT_ELIGIBLE,
    READ_STALE_IDENTITY,
    READ_UNTRUSTED_CALLER,
    READ_UNTRUSTED_INPUT,
    evaluate_provider_plan,
    read_provider_readback,
)

HEAD = "672a02419bdb95d95a0ca62c1b24d7b744fa4909"


def _budgets_json(budget_usd: float = 0.0, prevent: bool = True) -> str:
    return json.dumps(
        {
            "budgets": [
                {
                    "sku": "actions",
                    "budget_amount": {"value": budget_usd},
                    "prevent_further_usage": prevent,
                }
            ]
        }
    )


def _job_json(*, status: str = "queued", conclusion=None, runner_id: int = 0, runner_name: str | None = None) -> str:
    return json.dumps(
        {
            "status": status,
            "conclusion": conclusion,
            "runner_id": runner_id,
            "runner_name": runner_name,
        }
    )


def _run_json(attempt: int = 1) -> str:
    return json.dumps({"head_sha": HEAD, "run_attempt": attempt})


def _pr_json() -> str:
    return json.dumps({"head": {"sha": HEAD}})


def _request(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": "1.0",
        "trusted_caller": "LDW_HOST_GH_ADAPTER",
        "pull_request_number": 740,
        "head_sha": HEAD,
        "run_id": 42556087416,
        "run_attempt": 1,
        "job_id": 128961978297,
        "bounded_required_cost": 1.5,
        "requested_hosted_runner_label": "ubuntu-latest",
        "private_capacity_blocked": True,
        "active_duplicate_local_or_jit_job": False,
        "queued_within_approved_timeout": True,
        "data_classification": "CLEAN_SECRETLESS",
    }
    base.update(overrides)
    return base


def _mock_runner(mapping: dict[str, tuple[int, str]]):
    def runner(argv: list[str]) -> tuple[int, str]:
        if argv[0] != "api":
            return 127, ""
        path = argv[1]
        return mapping.get(path, (404, "{}"))

    return runner


class ProviderReadbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.good = {
            f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100": (0, _budgets_json()),
            f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/128961978297": (
                0,
                _job_json(),
            ),
            f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/42556087416": (0, _run_json()),
            f"/repos/LowcountryDigitalWorks/business-operations/pulls/740": (0, _pr_json()),
        }

    def test_healthy_budget_capped_plan_path(self) -> None:
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(self.good))
        self.assertFalse(out["execute"])
        self.assertEqual(out["readback_code"], "READ_OK")
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_forged_trusted_caller_rejected(self) -> None:
        out = read_provider_readback(_request(trusted_caller="MODEL_GUESS"), gh_runner=_mock_runner(self.good))
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_CALLER)

    def test_extra_field_rejected(self) -> None:
        payload = _request()
        payload["callback_url"] = "https://evil.example"
        out = read_provider_readback(payload, gh_runner=_mock_runner(self.good))
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)

    def test_gh_unavailable(self) -> None:
        out = read_provider_readback(_request(), gh_runner=lambda _a: (127, ""))
        self.assertEqual(out["readback_code"], READ_GH_UNAVAILABLE)

    def test_budget_403_forbidden(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (403, "")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_GH_FORBIDDEN)

    def test_malformed_budget_json(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (0, "not-json")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_GH_MALFORMED)

    def test_oversize_response_body(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (0, "x" * 300_000)
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_GH_MALFORMED)

    def test_missing_actions_budget_sku(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            0,
            json.dumps({"budgets": [{"sku": "packages", "budget_amount": {"value": 0}}]}),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], "READ_OK")
        assert out["planner_result"] is not None
        self.assertNotEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_prevent_not_hard_stopped(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            0,
            _budgets_json(prevent=False),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping))
        assert out["planner_result"] is not None
        self.assertNotEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_stale_pr_head_mismatch(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/pulls/740"] = (
            0,
            json.dumps({"head": {"sha": "a" * 40}}),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_stale_run_attempt_mismatch(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/42556087416"] = (
            0,
            _run_json(attempt=2),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_canceled_job_conclusion(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/128961978297"] = (
            0,
            _job_json(conclusion="cancelled"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_job_not_queued(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/128961978297"] = (
            0,
            _job_json(status="completed"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_runner_assigned_blocks_planner(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/128961978297"] = (
            0,
            _job_json(runner_id=99),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping))
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], "HOLD_PROVIDER_CAPACITY")

    def test_private_capacity_unknown_false(self) -> None:
        out = evaluate_provider_plan(_request(private_capacity_blocked=False), gh_runner=_mock_runner(self.good))
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], HOLD_RUNNER_NOT_BLOCKED)

    def test_duplicate_active_job_hold(self) -> None:
        out = evaluate_provider_plan(
            _request(active_duplicate_local_or_jit_job=True),
            gh_runner=_mock_runner(self.good),
        )
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], HOLD_PARALLEL_ACTIVE_JOB)

    def test_non_secret_classification_rejected(self) -> None:
        out = read_provider_readback(
            _request(data_classification="CUSTOMER_REGULATED"),
            gh_runner=_mock_runner(self.good),
        )
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_nan_bounded_cost_blocked_by_planner(self) -> None:
        out = evaluate_provider_plan(_request(bounded_required_cost=math.nan), gh_runner=_mock_runner(self.good))
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], "HOLD_BILLING_UNKNOWN")

    def test_negative_bounded_cost(self) -> None:
        out = evaluate_provider_plan(_request(bounded_required_cost=-1), gh_runner=_mock_runner(self.good))
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], "HOLD_BILLING_INSUFFICIENT")

    def test_job_not_found(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/128961978297"] = (404, "")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping))
        self.assertEqual(out["readback_code"], "READ_GH_NOT_FOUND")

    def test_output_never_execute(self) -> None:
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(self.good))
        self.assertFalse(out["execute"])
        assert out["planner_result"] is not None
        self.assertFalse(out["planner_result"]["execute"])

    def test_planner_input_sets_trusted_billing_source(self) -> None:
        out = read_provider_readback(_request(), gh_runner=_mock_runner(self.good))
        assert out["planner_input"] is not None
        self.assertEqual(out["planner_input"]["billing_evidence_source"], "GITHUB_ORG_ADMIN_READ")

    def test_queued_timeout_false_rejected_at_readback(self) -> None:
        out = read_provider_readback(_request(queued_within_approved_timeout=False), gh_runner=_mock_runner(self.good))
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)


if __name__ == "__main__":
    unittest.main()
