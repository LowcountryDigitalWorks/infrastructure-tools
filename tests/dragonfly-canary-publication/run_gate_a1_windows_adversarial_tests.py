#!/usr/bin/env python3
"""Run Gate A1 Windows adversarial regressions; fail if any test is skipped."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "test_gate_a1_transport_identity.py"
ADVERSARIAL = (
    "test_temp_key_replacement_during_ssh_keygen_blocked",
    "test_temp_key_cleanup_pathname_hardlink_after_bound_destroy",
    "test_temp_key_cleanup_single_link_pathname_replacement_holds",
    "test_temp_key_cleanup_parent_directory_substitution_holds",
    "test_temp_key_cleanup_zeroed_object_moved_outside_temp_dir_holds",
    "test_temp_key_cleanup_failure_hold",
    "test_temp_key_cleanup_setfileinformation_delete_failure_holds",
    "test_temp_key_cleanup_hardlink_same_zeroed_object_removed",
    "test_blind_pathname_unlink_would_destroy_substitute_fixture",
    "test_windows_derive_bound_temp_dir_none_purges_created_directory",
    "test_trusted_icacls_ignores_path_substitution",
    "test_windows_system_ssh_keygen_ephemeral_ed25519_derive_and_cleanup",
)


def _load_module():
    spec = importlib.util.spec_from_file_location("gate_a1_identity_adversarial_host", TARGET)
    if spec is None or spec.loader is None:
        raise RuntimeError("GATE_A1_ADVERSARIAL_TEST_MODULE_LOAD_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if sys.platform != "win32":
        print("GATE_A1_ADVERSARIAL_TESTS=HOLD")
        print("CLASSIFICATION=GATE_A1_WINDOWS_REQUIRED")
        return 1
    module = _load_module()
    suite = unittest.TestSuite(
        [module.GateA1TransportIdentityTests(name) for name in ADVERSARIAL]
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        for test, reason in result.skipped:
            print(f"SKIPPED={test}: {reason}", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
