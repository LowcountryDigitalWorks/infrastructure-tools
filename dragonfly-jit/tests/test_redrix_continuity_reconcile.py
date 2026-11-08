#!/usr/bin/env python3
"""Synthetic negatives for offline REDRIX continuity reconciliation."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "redrix_continuity_reconcile.py"
spec = importlib.util.spec_from_file_location("redrix_continuity_reconcile", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("SOURCE_IMPORT_FAILED")
reconcile_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile_mod)
FIXED_DEVICE_ID = reconcile_mod.FIXED_DEVICE_ID
canonical_packet = reconcile_mod.canonical_packet
reconcile = reconcile_mod.reconcile

FORBIDDEN = ("JIT_READY", "ONLINE_READY", "LOGIN_REQUIRED", "CROSTINI_STOPPED", "CI_READY")


def packet():
    return canonical_packet()


class ReconcileTests(unittest.TestCase):
    def assert_closed(self, result: dict) -> None:
        encoded = json.dumps(result)
        self.assertFalse(result["ci_dispatch_authorized"])
        self.assertFalse(result["runtime_authorized"])
        self.assertFalse(result["chromeos_login_claimed"])
        self.assertEqual(result["process_visibility"], "UNVERIFIED")
        self.assertNotIn(FIXED_DEVICE_ID, encoded)
        for label in FORBIDDEN:
            self.assertNotIn(label, encoded)

    def test_correlated_pair_is_data_only(self) -> None:
        result = reconcile(packet())
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertEqual(result["reasons"], ["BOTH_VIEWS_CORRELATED_NOT_A_CHANNEL"])
        self.assertEqual(result["peer_side_corroboration"], "UNVERIFIED")
        self.assert_closed(result)

    def test_simulated_provider_field_does_not_authorize(self) -> None:
        sample = packet()
        sample["remote"]["provider_verified_simulation"] = True
        result = reconcile(sample)
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertEqual(result["peer_side_corroboration"], "SIMULATED_FIELD_ONLY")
        self.assert_closed(result)

    def test_missing_side_one_sided_and_unknown_field(self) -> None:
        sample = packet()
        del sample["remote"]
        self.assertEqual(reconcile(sample)["reasons"], ["MISSING_SIDE"])
        sample = packet()
        sample["note"] = "extra"
        self.assertEqual(reconcile(sample)["reasons"], ["UNKNOWN_FIELD"])
        self.assertEqual(reconcile("nope")["reasons"], ["SCHEMA_INVALID"])

    def test_version_source_device_and_trust(self) -> None:
        sample = packet()
        sample["local"]["schema_version"] = 2
        self.assertEqual(reconcile(sample)["reasons"], ["VERSION_UNSUPPORTED"])
        sample = packet()
        sample["local"]["source_id"] = "operator-supplied"
        self.assertEqual(reconcile(sample)["reasons"], ["SOURCE_IDENTITY_MISMATCH"])
        sample = packet()
        sample["remote"]["device_id"] = "other-device"
        self.assertEqual(reconcile(sample)["reasons"], ["DEVICE_IDENTITY_MISMATCH"])
        sample = packet()
        sample["remote"]["trust_provenance"] = "user-asserted-live"
        self.assertEqual(reconcile(sample)["reasons"], ["TRUST_PROVENANCE_MISMATCH"])

    def test_nonce_replay_order_skew_and_ttl(self) -> None:
        sample = packet()
        sample["remote"]["nonce"] = "nonce-synthetic-002"
        self.assertEqual(reconcile(sample)["reasons"], ["NONCE_MISMATCH"])
        sample = packet()
        self.assertEqual(
            reconcile(sample, ["nonce-synthetic-001"])["reasons"],
            ["DUPLICATE_OR_REPLAY"],
        )
        sample = packet()
        sample["remote"]["observed_at"] = "2026-11-08T05:00:00Z"
        self.assertEqual(reconcile(sample)["reasons"], ["TIME_ORDER_INVALID"])
        sample = packet()
        sample["remote"]["observed_at"] = "2026-11-08T05:02:00Z"
        sample["now"] = "2026-11-08T05:02:10Z"
        self.assertEqual(reconcile(sample)["reasons"], ["CLOCK_SKEW"])
        sample = packet()
        sample["now"] = "2026-11-08T05:05:00Z"
        self.assertEqual(reconcile(sample)["reasons"], ["TTL_EXPIRED"])

    def test_boot_split_brain_provider_and_confidence(self) -> None:
        sample = packet()
        sample["remote"]["boot_id"] = "boot-synthetic-009"
        self.assertEqual(reconcile(sample)["reasons"], ["BOOT_DISCRIMINATOR_MISMATCH"])
        sample = packet()
        sample["remote"]["controller_lease"] = "AMBIGUOUS"
        self.assertEqual(reconcile(sample)["reasons"], ["SPLIT_BRAIN"])
        sample = packet()
        sample["remote"]["provider_api"] = "FAILED"
        self.assertEqual(reconcile(sample)["reasons"], ["PROVIDER_API_FAILURE"])
        sample = packet()
        sample["remote"]["confidence"] = "HIGH"
        self.assertEqual(reconcile(sample)["reasons"], ["USER_CONFIDENCE_REJECTED"])
        sample = packet()
        sample["local"]["chromeos_session"] = "LOGGED_IN"
        self.assertEqual(reconcile(sample)["reasons"], ["USER_CONFIDENCE_REJECTED"])
        sample = packet()
        sample["local"]["ci_dispatch_authorized"] = True
        self.assertEqual(reconcile(sample)["reasons"], ["USER_CONFIDENCE_REJECTED"])

    def test_owner_claim_vm_tailscale_qemu_and_local_state(self) -> None:
        sample = packet()
        sample["remote"]["owner_session"] = "REMOTE_CLAIM"
        result = reconcile(sample)
        self.assertEqual(result["classification"], "UNVERIFIED")
        self.assertEqual(result["reasons"], ["OWNER_SESSION_WITHOUT_CHROMEOS"])
        self.assertNotIn("LOGIN_REQUIRED", json.dumps(result))
        sample = packet()
        sample["remote"]["vm_posture"] = "UNAVAILABLE"
        self.assertEqual(reconcile(sample)["reasons"], ["LOGIN_OR_VM_UNAVAILABLE"])
        sample = packet()
        sample["remote"]["tailscale_peer"] = "STALE"
        self.assertEqual(reconcile(sample)["reasons"], ["TAILSCALE_STALE"])
        sample = packet()
        sample["local"]["qemu_absent"] = False
        self.assertEqual(reconcile(sample)["reasons"], ["QEMU_RESIDUE"])
        sample = packet()
        del sample["local"]["a4_process_visibility"]
        self.assertEqual(reconcile(sample)["reasons"], ["MISSING_A4"])
        sample = packet()
        sample["local"]["a4_process_visibility"] = "VERIFIED"
        self.assertEqual(reconcile(sample)["reasons"], ["USER_CONFIDENCE_REJECTED"])
        sample = packet()
        sample["local"]["classification"] = "DEGRADED_NETWORK"
        self.assertEqual(reconcile(sample)["reasons"], ["LOCAL_DEGRADED"])
        sample = packet()
        sample["local"]["classification"] = "HOLD"
        self.assertEqual(reconcile(sample)["reasons"], ["LOCAL_HOLD"])

    def test_malformed_nested_values_hold_without_traceback(self) -> None:
        cases = []
        sample = packet()
        sample["remote"]["provider_api"] = []
        cases.append(sample)
        sample = packet()
        sample["local"]["classification"] = {}
        cases.append(sample)
        sample = packet()
        sample["local"]["reasons"] = [{}]
        cases.append(sample)
        sample = packet()
        sample["local"]["reasons"] = ["SAMPLE_FAILED", "SAMPLE_FAILED"]
        cases.append(sample)
        sample = packet()
        sample["local"]["reasons"] = []
        cases.append(sample)
        sample = packet()
        sample["local"]["qemu_absent"] = 1
        cases.append(sample)
        sample = packet()
        sample["remote"]["provider_verified_simulation"] = 0
        cases.append(sample)
        for sample in cases:
            result = reconcile(sample)
            self.assertEqual(result["classification"], "HOLD")
            self.assertEqual(result["reasons"], ["SCHEMA_INVALID"])
            self.assert_closed(result)
            self.assertNotIn("[]", json.dumps(result["reasons"]))
        floated = packet()
        floated["schema_version"] = 1.0
        self.assertEqual(reconcile(floated)["reasons"], ["VERSION_UNSUPPORTED"])
        flagged = packet()
        flagged["local"]["schema_version"] = True
        self.assertEqual(reconcile(flagged)["reasons"], ["VERSION_UNSUPPORTED"])
        self.assertEqual(reconcile(packet(), [{}])["reasons"], ["SCHEMA_INVALID"])
        self.assertEqual(reconcile(packet(), {"nonce-synthetic-001"})["reasons"], ["SCHEMA_INVALID"])
        long_nonce = "n" * 64
        self.assertEqual(reconcile(packet(), [long_nonce])["reasons"], ["SCHEMA_INVALID"])
        self.assertEqual(reconcile(packet(), ["nonce-other", "nonce-other"])["reasons"], ["SCHEMA_INVALID"])
        sample = packet()
        sample["remote"]["tailscale_peer"] = "ABSENT"
        absent = reconcile(sample)
        self.assertEqual(absent["classification"], "DEGRADED")
        self.assertEqual(absent["reasons"], ["TAILSCALE_ABSENT"])
        self.assertNotEqual(absent["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assert_closed(absent)

    def test_history_is_not_mutated(self) -> None:
        seen = ["nonce-other"]
        reconcile(packet(), seen)
        self.assertEqual(seen, ["nonce-other"])
        self.assertIsNot(canonical_packet(), canonical_packet())
        untouched = packet()
        reconcile(copy.deepcopy(untouched))
        self.assertEqual(untouched, packet())


if __name__ == "__main__":
    unittest.main()
