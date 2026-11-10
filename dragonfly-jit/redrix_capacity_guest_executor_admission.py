#!/usr/bin/env python3
"""Read-only HW&VM product-admission eligibility for the offline 2+6 research executor."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CONTRACT_PATH = Path(__file__).with_name("redrix_capacity_guest_executor_admission.json")


def load_admission_contract() -> dict[str, Any]:
    text = CONTRACT_PATH.read_text(encoding="utf-8")
    return json.loads(text)


def evaluate_product_admission_readiness(
    executor_module: Any,
) -> dict[str, Any]:
    """Source-only readiness for independent HW&VM review; never enables physical runs."""
    contract = load_admission_contract()
    problems: list[str] = []

    if executor_module.PHYSICAL_EXECUTION_ENABLED:
        problems.append("PHYSICAL_EXECUTION_MUST_REMAIN_FALSE_IN_THIS_RELEASE")
    if executor_module.GUEST_MIB != contract["guest_mib"]:
        problems.append("GUEST_MIB_DRIFT")
    if executor_module.RESEARCH_RESERVE_MIB != contract["research_reserve_mib"]:
        problems.append("RESEARCH_RESERVE_DRIFT")
    if executor_module.RESEARCH_FLOOR_MIB != contract["research_floor_mib"]:
        problems.append("RESEARCH_FLOOR_DRIFT")
    if executor_module.PRODUCTION_RESERVE_MIB != contract["production_reserve_mib"]:
        problems.append("PRODUCTION_RESERVE_DRIFT")
    if executor_module.EXPECTED_CONTROLLER_BLOB != contract["pinned_controller_blob_sha1"]:
        problems.append("CONTROLLER_BLOB_PIN_DRIFT")
    if executor_module.EXPECTED_BASE_SHA512 != contract["pinned_base_sha512"]:
        problems.append("BASE_SHA512_PIN_DRIFT")

    research_only = (
        contract["research_only_explicit"]
        and contract["research_floor_mib"] == contract["guest_mib"] + contract["research_reserve_mib"]
        and contract["production_floor_mib"]
        == contract["guest_mib"] + contract["production_reserve_mib"]
        and contract["research_floor_mib"] < contract["production_floor_mib"]
    )
    if not research_only:
        problems.append("RESEARCH_2PLUS6_NOT_EXPLICIT")

    return {
        "marker": "LDW_REDRIX_CAPACITY_GUEST_EXECUTOR_ADMISSION",
        "schema": contract["schema"],
        "eligibility": "READY_FOR_HW_VM_INDEPENDENT_REVIEW" if not problems else "HOLD",
        "problems": problems,
        "research_only_explicit": True,
        "research_floor_mib": executor_module.RESEARCH_FLOOR_MIB,
        "production_floor_mib": executor_module.GUEST_MIB + executor_module.PRODUCTION_RESERVE_MIB,
        "physical_execution_source_enabled": bool(executor_module.PHYSICAL_EXECUTION_ENABLED),
        "runtime_enablement_gate": contract["runtime_enablement"],
        "chromeos_host_corroboration": contract["chromeos_host_corroboration"],
        "owner_interactivity_corroboration_required": contract[
            "owner_interactivity_corroboration_required"
        ],
        "same_uid_race_limitation_disclosed": contract["same_uid_race_limitation_disclosed"],
        "evidence_phases": contract["evidence_phases_required_for_physical_run"],
        "pinned_controller_blob_sha1": executor_module.EXPECTED_CONTROLLER_BLOB,
        "pinned_base_sha512": executor_module.EXPECTED_BASE_SHA512,
        "jit_admission_authorized": False,
        "provider_admission_authorized": False,
        "production_policy_changed": False,
    }
