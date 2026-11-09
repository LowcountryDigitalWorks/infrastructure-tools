"""Offline adversarial tests for provider_readback (mocked gh only)."""
from __future__ import annotations

import json
import math
import unittest
from datetime import datetime, timezone

from plan_fallback import (
    HOLD_PARALLEL_ACTIVE_JOB,
    HOLD_RUNNER_NOT_BLOCKED,
    ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED,
)
from provider_readback import (
    READ_CAPACITY_UNVERIFIED,
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
RUN_ID = 42556087416
JOB_ID = 128961978297
PR = 740


def _trusted_context(
    *,
    private_blocked: bool = True,
    duplicate_job: bool = False,
    kind: str = "LDW_PROTECTED_HOST_SYNTHETIC",
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "attestation_kind": kind,
        "private_capacity_blocked_attested": private_blocked,
        "active_duplicate_local_or_jit_job_attested": duplicate_job,
    }


def _budgets_json(budget_usd: float = 0.0, prevent: bool = True, *, duplicate_actions: bool = False) -> str:
    rows = [
        {
            "id": 1,
            "budget_type": "product",
            "budget_product_sku": "actions",
            "budget_scope": "organization",
            "budget_amount": budget_usd,
            "prevent_further_usage": prevent,
            "budget_entity_name": ALLOWED_ORG_NAME,
            "budget_alerting": True,
        }
    ]
    if duplicate_actions:
        rows.append(
            {
                "id": 2,
                "budget_type": "product",
                "budget_product_sku": "actions",
                "budget_scope": "organization",
                "budget_amount": 1.0,
                "prevent_further_usage": True,
                "budget_entity_name": ALLOWED_ORG_NAME,
                "budget_alerting": True,
            }
        )
    return json.dumps({"budgets": rows})


ALLOWED_ORG_NAME = "LowcountryDigitalWorks"


def _job_json(
    *,
    status: str = "queued",
    conclusion=None,
    runner_id: int = 0,
    runner_name: str | None = None,
) -> str:
    return json.dumps(
        {
            "id": JOB_ID,
            "run_id": RUN_ID,
            "status": status,
            "conclusion": conclusion,
            "runner_id": runner_id,
            "runner_name": runner_name,
        }
    )


def _run_json(
    attempt: int = 1,
    *,
    status: str = "queued",
    conclusion=None,
    created_at: str = "2026-11-08T12:00:00Z",
    head_sha: str = HEAD,
) -> str:
    return json.dumps(
        {
            "id": RUN_ID,
            "event": "pull_request",
            "status": status,
            "conclusion": conclusion,
            "head_sha": head_sha,
            "run_attempt": attempt,
            "created_at": created_at,
            "pull_requests": [{"number": PR}],
        }
    )


def _pr_json(*, state: str = "open", head_sha: str = HEAD) -> str:
    return json.dumps(
        {
            "number": PR,
            "state": state,
            "head": {
                "sha": head_sha,
                "repo": {"full_name": "LowcountryDigitalWorks/business-operations"},
            },
        }
    )


def _request(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": "1.1",
        "trusted_caller": "LDW_HOST_GH_ADAPTER",
        "host_trusted_context": _trusted_context(),
        "pull_request_number": PR,
        "head_sha": HEAD,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "job_id": JOB_ID,
        "bounded_required_cost": 1.5,
        "requested_hosted_runner_label": "ubuntu-latest",
        "private_capacity_blocked": True,
        "active_duplicate_local_or_jit_job": False,
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


def _fixed_clock(now: datetime):
    def _now() -> datetime:
        return now

    return _now


class ProviderReadbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _fixed_clock(datetime(2026, 11, 8, 12, 30, 0, tzinfo=timezone.utc))
        self.good = {
            f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100": (0, _budgets_json()),
            f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}": (
                0,
                _job_json(),
            ),
            f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}": (
                0,
                _run_json(),
            ),
            f"/repos/LowcountryDigitalWorks/business-operations/pulls/{PR}": (0, _pr_json()),
        }

    def test_healthy_budget_capped_plan_path(self) -> None:
        out = evaluate_provider_plan(
            _request(),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertFalse(out["execute"])
        self.assertEqual(out["readback_code"], "READ_OK")
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_forged_trusted_caller_rejected(self) -> None:
        out = read_provider_readback(
            _request(trusted_caller="MODEL_GUESS"),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_CALLER)

    def test_missing_host_trusted_context_rejected(self) -> None:
        out = read_provider_readback(
            _request(host_trusted_context=None),  # type: ignore[arg-type]
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_CALLER)

    def test_extra_field_rejected(self) -> None:
        payload = _request()
        payload["callback_url"] = "https://evil.example"
        calls: list[list[str]] = []

        def spy(argv: list[str]) -> tuple[int, str]:
            calls.append(argv)
            return _mock_runner(self.good)(argv)

        out = read_provider_readback(payload, gh_runner=spy, utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertEqual(calls, [])

    def test_path_injected_job_id_never_calls_gh(self) -> None:
        payload = _request(job_id="../../secrets")
        calls: list[list[str]] = []

        def spy(argv: list[str]) -> tuple[int, str]:
            calls.append(argv)
            return 0, "{}"

        out = read_provider_readback(payload, gh_runner=spy, utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertEqual(calls, [])

    def test_huge_text_field_rejected_without_gh(self) -> None:
        payload = _request(requested_hosted_runner_label="x" * 10_000)
        calls: list[list[str]] = []

        def spy(argv: list[str]) -> tuple[int, str]:
            calls.append(argv)
            return 0, "{}"

        out = read_provider_readback(payload, gh_runner=spy, utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertEqual(calls, [])

    def test_gh_unavailable(self) -> None:
        out = read_provider_readback(_request(), gh_runner=lambda _a: (127, ""), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_UNAVAILABLE)

    def test_budget_403_forbidden(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (403, "")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_FORBIDDEN)

    def test_gh_exit_one_generic_hold(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            1,
            '{"message":"boom"}',
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_UNAVAILABLE)

    def test_malformed_budget_json(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (0, "not-json")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_MALFORMED)

    def test_oversize_response_body(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (0, "x" * 300_000)
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_MALFORMED)

    def test_no_actions_org_budget_row(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            0,
            json.dumps(
                {
                    "budgets": [
                        {
                            "budget_product_sku": "packages",
                            "budget_scope": "organization",
                            "budget_amount": 0,
                            "prevent_further_usage": True,
                        }
                    ]
                }
            ),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], "READ_OK")
        assert out["planner_result"] is not None
        self.assertNotEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_duplicate_actions_org_budget_fail_closed(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            0,
            _budgets_json(duplicate_actions=True),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_GH_MALFORMED)

    def test_prevent_not_hard_stopped(self) -> None:
        mapping = dict(self.good)
        mapping[f"/orgs/LowcountryDigitalWorks/settings/billing/budgets?per_page=100"] = (
            0,
            _budgets_json(prevent=False),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        assert out["planner_result"] is not None
        self.assertNotEqual(out["planner_result"]["recommended_route"], ROUTE_HOSTED_CLEAN_PLAN_BUDGET_CAPPED)

    def test_stale_pr_head_mismatch(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/pulls/{PR}"] = (
            0,
            _pr_json(head_sha="a" * 40),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_stale_run_attempt_mismatch(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            _run_json(attempt=2),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_job_run_id_mismatch(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}"] = (
            0,
            json.dumps({"id": JOB_ID, "run_id": RUN_ID + 1, "status": "queued", "conclusion": None}),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_run_not_pull_request_event(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            json.dumps(
                {
                    "id": RUN_ID,
                    "event": "workflow_dispatch",
                    "status": "queued",
                    "conclusion": None,
                    "head_sha": HEAD,
                    "run_attempt": 1,
                    "created_at": "2026-11-08T12:00:00Z",
                    "pull_requests": [{"number": PR}],
                }
            ),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_run_missing_pr_link(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            json.dumps(
                {
                    "id": RUN_ID,
                    "event": "pull_request",
                    "status": "queued",
                    "conclusion": None,
                    "head_sha": HEAD,
                    "run_attempt": 1,
                    "created_at": "2026-11-08T12:00:00Z",
                    "pull_requests": [],
                }
            ),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_run_completed_rejected(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            _run_json(status="completed", conclusion="success"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_queued_timeout_exceeded(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            _run_json(created_at="2026-11-01T12:00:00Z"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_queued_future_created_at_rejected(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/runs/{RUN_ID}"] = (
            0,
            _run_json(created_at="2026-11-09T12:00:00Z"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_pr_not_open(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/pulls/{PR}"] = (
            0,
            _pr_json(state="closed"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_STALE_IDENTITY)

    def test_canceled_job_conclusion(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}"] = (
            0,
            _job_json(conclusion="cancelled"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_job_not_queued(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}"] = (
            0,
            _job_json(status="completed"),
        )
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_JOB_NOT_ELIGIBLE)

    def test_runner_assigned_blocks_planner(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}"] = (
            0,
            _job_json(runner_id=99),
        )
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], "HOLD_PROVIDER_CAPACITY")

    def test_private_capacity_unverified_without_attestation(self) -> None:
        ctx = _trusted_context(private_blocked=False)
        out = evaluate_provider_plan(
            _request(
                private_capacity_blocked=True,
                host_trusted_context=ctx,
            ),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_CAPACITY_UNVERIFIED)
        self.assertIsNone(out["planner_result"])

    def test_private_capacity_unknown_false(self) -> None:
        out = evaluate_provider_plan(
            _request(
                private_capacity_blocked=False,
                host_trusted_context=_trusted_context(private_blocked=False),
            ),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], HOLD_RUNNER_NOT_BLOCKED)

    def test_duplicate_active_job_hold(self) -> None:
        out = evaluate_provider_plan(
            _request(
                active_duplicate_local_or_jit_job=True,
                host_trusted_context=_trusted_context(duplicate_job=True),
            ),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        assert out["planner_result"] is not None
        self.assertEqual(out["planner_result"]["recommended_route"], HOLD_PARALLEL_ACTIVE_JOB)

    def test_duplicate_claim_without_attestation(self) -> None:
        out = read_provider_readback(
            _request(
                active_duplicate_local_or_jit_job=True,
                host_trusted_context=_trusted_context(duplicate_job=False),
            ),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_CAPACITY_UNVERIFIED)

    def test_non_secret_classification_rejected(self) -> None:
        out = read_provider_readback(
            _request(data_classification="CUSTOMER_REGULATED"),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)

    def test_nan_bounded_cost_rejected_at_adapter(self) -> None:
        out = evaluate_provider_plan(
            _request(bounded_required_cost=math.nan),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertIsNone(out["planner_result"])

    def test_negative_bounded_cost_rejected_at_adapter(self) -> None:
        out = evaluate_provider_plan(
            _request(bounded_required_cost=-1),
            gh_runner=_mock_runner(self.good),
            utc_now=self.clock,
        )
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertIsNone(out["planner_result"])

    def test_job_not_found(self) -> None:
        mapping = dict(self.good)
        mapping[f"/repos/LowcountryDigitalWorks/business-operations/actions/jobs/{JOB_ID}"] = (404, "")
        out = read_provider_readback(_request(), gh_runner=_mock_runner(mapping), utc_now=self.clock)
        self.assertEqual(out["readback_code"], "READ_GH_NOT_FOUND")

    def test_output_never_execute(self) -> None:
        out = evaluate_provider_plan(_request(), gh_runner=_mock_runner(self.good), utc_now=self.clock)
        self.assertFalse(out["execute"])
        assert out["planner_result"] is not None
        self.assertFalse(out["planner_result"]["execute"])

    def test_planner_input_sets_trusted_billing_source(self) -> None:
        out = read_provider_readback(_request(), gh_runner=_mock_runner(self.good), utc_now=self.clock)
        assert out["planner_input"] is not None
        self.assertEqual(out["planner_input"]["billing_evidence_source"], "GITHUB_ORG_ADMIN_READ")

    def test_bool_job_id_rejected_without_gh(self) -> None:
        payload = _request(job_id=True)  # type: ignore[arg-type]
        calls: list[list[str]] = []

        def spy(argv: list[str]) -> tuple[int, str]:
            calls.append(argv)
            return 0, "{}"

        out = read_provider_readback(payload, gh_runner=spy, utc_now=self.clock)
        self.assertEqual(out["readback_code"], READ_UNTRUSTED_INPUT)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
