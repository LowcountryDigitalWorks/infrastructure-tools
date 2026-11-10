#!/usr/bin/env python3
"""Admission contract and HW&VM product-readiness (source-only)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "redrix_capacity_guest_executor.py"
ADMISSION = ROOT / "redrix_capacity_guest_executor_admission.py"
CONTRACT = ROOT / "redrix_capacity_guest_executor_admission.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


exe = _load("redrix_capacity_guest_executor", EXECUTOR)
adm = _load("redrix_capacity_guest_executor_admission", ADMISSION)


class AdmissionContractTests(unittest.TestCase):
    def test_contract_declares_research_2plus6_explicit(self):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertTrue(contract["research_only_explicit"])
        self.assertEqual(contract["guest_mib"] + contract["research_reserve_mib"], 8192)
        self.assertEqual(contract["guest_mib"] + contract["production_reserve_mib"], 10240)
        self.assertFalse(contract["physical_execution_source_flag_default"])
        self.assertEqual(len(contract["evidence_phases_required_for_physical_run"]), 3)

    def test_evaluate_ready_while_physical_disabled(self):
        out = adm.evaluate_product_admission_readiness(exe)
        self.assertEqual(out["eligibility"], "READY_FOR_HW_VM_INDEPENDENT_REVIEW")
        self.assertEqual(out["problems"], [])
        self.assertFalse(out["physical_execution_source_enabled"])
        self.assertTrue(out["research_only_explicit"])
        self.assertEqual(out["research_floor_mib"], 8192)
        self.assertEqual(out["production_floor_mib"], 10240)
        self.assertFalse(out["jit_admission_authorized"])

    def test_runtime_no_start_includes_admission_snapshot(self):
        ctx = exe.RunContext(
            hooks=exe.ExecutorHooks(),
            guest_lock_path=Path("/tmp/unused-guest.lock"),
            state_lock_path=Path("/tmp/unused-state.lock"),
            controller_path=EXECUTOR,
            base_image_path=EXECUTOR,
            state_path=Path("/tmp/unused-status.json"),
            runs_root=Path("/tmp/unused-runs"),
        )
        report = exe.run_once_local(ctx)
        self.assertEqual(report["reason"], "RUNTIME_NO_START")
        readiness = report["product_admission_readiness"]
        self.assertEqual(readiness["eligibility"], "READY_FOR_HW_VM_INDEPENDENT_REVIEW")
        self.assertTrue(report["research_only_explicit"])
        self.assertEqual(report["research_reserve_mib"], 6144)

    def test_main_cli_refuses_without_alternate_argv(self):
        self.assertEqual(exe.main([]), 2)
        self.assertEqual(exe.main(["--unknown"]), 2)


if __name__ == "__main__":
    unittest.main()
