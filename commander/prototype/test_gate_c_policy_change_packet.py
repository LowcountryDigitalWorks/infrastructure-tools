"""Negative-first deterministic Gate C policy packet tests (no Windows needed)."""
from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from gate_c_policy_change_packet import (
    CLASSIFICATION, MANAGEMENT_SOURCES, OBSERVATION_KEYS, POLICIES,
    SOURCE_CLASSIFICATION, SOURCE_SCHEMA, build_change_packet, main,
)


def observed(default: str = "NOT_CONFIGURED") -> dict[str, object]:
    return {
        "schema": SOURCE_SCHEMA,
        "classification": SOURCE_CLASSIFICATION,
        "windows_platform_observed": True,
        "mapped_folder_policy_build_supported": True,
        "policy_states": {name: default for name in POLICIES},
        "all_required_policies_explicitly_deny": default == "EXPLICIT_DENY",
        "runtime_policy_enforcement_verified": False,
        "post_start_mutation_denial_verified": False,
        "guest_isolation_verified": False,
        "hardware_owner_presence_verified": False,
        "admin_session_authorized": False,
    }


class ChangePacketTests(unittest.TestCase):
    def assert_no_authority(self, packet):
        self.assertEqual(packet["classification"], CLASSIFICATION)
        for key in (
            "management_source_verified", "machine_policy_changed",
            "runtime_enforcement_verified", "owner_presence_verified",
            "guest_isolation_verified", "admin_session_authorized",
        ):
            self.assertIs(packet[key], False)
        self.assertEqual(len(packet), 13)
        self.assertNotIn("HKEY", json.dumps(packet))
        self.assertNotIn("host_path", json.dumps(packet))

    def test_all_seven_not_configured_yield_exact_plan(self):
        packet = build_change_packet(observed(), management_source="LOCAL_GPO")
        self.assertEqual(packet["disposition"], "PLAN_ONLY_NOT_AUTHORIZED")
        self.assertEqual([x["policy"] for x in packet["changes"]], list(POLICIES))
        self.assertEqual([x["policy"] for x in packet["rollback_intents"]], list(POLICIES))
        self.assertEqual({x["prior_state"] for x in packet["rollback_intents"]}, {"NOT_CONFIGURED"})
        self.assertEqual({x["intent"] for x in packet["rollback_intents"]}, {"RESTORE_NOT_CONFIGURED_VIA_SAME_MANAGEMENT_SOURCE"})
        self.assertEqual(len(packet["plan_sha256"]), 64)
        self.assert_no_authority(packet)

    def test_allowed_prior_state_restored_as_allowed_not_unset(self):
        obs = observed()
        obs["policy_states"]["AllowNetworking"] = "ALLOWED"
        packet = build_change_packet(obs, management_source="LOCAL_GPO")
        previous = next(x for x in packet["rollback_intents"] if x["policy"] == "AllowNetworking")
        self.assertEqual(previous["intent"], "RESTORE_ALLOWED_VIA_SAME_MANAGEMENT_SOURCE")
        self.assert_no_authority(packet)

    def test_preexisting_denies_excluded_from_changes(self):
        obs = observed()
        obs["policy_states"]["AllowNetworking"] = "EXPLICIT_DENY"
        packet = build_change_packet(obs, management_source="DOMAIN_GPO")
        self.assertEqual(len(packet["changes"]), 6)
        self.assertNotIn("AllowNetworking", [x["policy"] for x in packet["rollback_intents"]])
        self.assert_no_authority(packet)

    def test_all_denied_is_not_runtime_admission(self):
        packet = build_change_packet(observed("EXPLICIT_DENY"), management_source="MDM")
        self.assertEqual(packet["disposition"], "NO_SOURCE_CHANGE_OBSERVED_RUNTIME_UNVERIFIED")
        self.assertEqual(packet["changes"], [])
        self.assertIsNone(packet["plan_sha256"])
        self.assert_no_authority(packet)

    def test_unknown_source_never_produces_plan(self):
        for source in (None, "UNKNOWN", "LOCAL_REGISTRY", "local_gpo", "MDM,DOMAIN_GPO", True, 1):
            with self.subTest(source=source):
                packet = build_change_packet(observed(), management_source=source)
                self.assertEqual(packet["disposition"], "HOLD_POLICY_PROVENANCE_UNKNOWN")
                self.assertEqual(packet["changes"], [])
                self.assert_no_authority(packet)

    def test_named_source_still_not_verified_or_authorized(self):
        for source in MANAGEMENT_SOURCES:
            with self.subTest(source=source):
                packet = build_change_packet(observed(), management_source=source)
                self.assertEqual(packet["management_source_claim"], source)
                self.assertFalse(packet["management_source_verified"])
                self.assert_no_authority(packet)

    def test_missing_invalid_or_unreadable_preimage_holds(self):
        for state in ("INVALID", "UNAVAILABLE", "NOT_INSPECTED"):
            for name in POLICIES:
                with self.subTest(state=state, name=name):
                    obs = observed()
                    obs["policy_states"][name] = state
                    packet = build_change_packet(obs, management_source="LOCAL_GPO")
                    self.assertEqual(packet["disposition"], "HOLD_PREIMAGE_UNAVAILABLE")
                    self.assertEqual(packet["changes"], [])
                    self.assert_no_authority(packet)

    def test_false_windows_or_false_build_holds(self):
        for key in ("windows_platform_observed", "mapped_folder_policy_build_supported"):
            obs = observed()
            obs[key] = False
            self.assertEqual(build_change_packet(obs, management_source="MDM")["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_truthy_non_bool_flags_are_refused(self):
        for key in ("windows_platform_observed", "mapped_folder_policy_build_supported"):
            obs = observed()
            obs[key] = 1
            self.assertEqual(build_change_packet(obs, management_source="MDM")["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_source_authority_booleans_must_remain_false(self):
        for key in (
            "runtime_policy_enforcement_verified", "post_start_mutation_denial_verified",
            "guest_isolation_verified", "hardware_owner_presence_verified",
            "admin_session_authorized",
        ):
            with self.subTest(key=key):
                for value in (True, 0, None):
                    obs = observed()
                    obs[key] = value
                    self.assertEqual(build_change_packet(obs, management_source="MDM")["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_source_proof_claim_inconsistent_all_deny_rejected(self):
        for default in ("NOT_CONFIGURED", "EXPLICIT_DENY"):
            obs = observed(default)
            obs["all_required_policies_explicitly_deny"] = not obs["all_required_policies_explicitly_deny"]
            self.assertEqual(build_change_packet(obs, management_source="LOCAL_GPO")["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_extra_and_missing_observation_keys_rejected(self):
        obs = observed()
        self.assertEqual(set(obs), OBSERVATION_KEYS)
        obs["host"] = "untrusted-host"
        packet = build_change_packet(obs, management_source="LOCAL_GPO")
        self.assertEqual(packet["changes"], [])
        self.assertNotIn("untrusted-host", json.dumps(packet))
        self.assert_no_authority(packet)
        del obs["host"]
        del obs["schema"]
        self.assertEqual(build_change_packet(obs)["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_extra_missing_or_wrong_policy_entries_rejected(self):
        obs = observed()
        obs["policy_states"]["OtherPolicy"] = "EXPLICIT_DENY"
        self.assertEqual(build_change_packet(obs)["disposition"], "HOLD_OBSERVATION_INVALID")
        del obs["policy_states"]["OtherPolicy"]
        del obs["policy_states"][POLICIES[0]]
        self.assertEqual(build_change_packet(obs)["disposition"], "HOLD_OBSERVATION_INVALID")
        obs = observed()
        obs["policy_states"][POLICIES[0]] = 0
        self.assertEqual(build_change_packet(obs)["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_wrong_source_schema_classification_and_types_rejected(self):
        for field, value in (("schema", "bad"), ("classification", "READY"), ("policy_states", [])):
            obs = observed()
            obs[field] = value
            self.assertEqual(build_change_packet(obs)["disposition"], "HOLD_OBSERVATION_INVALID")
        for value in (None, [], {}, "raw user text", True):
            self.assertEqual(build_change_packet(value)["disposition"], "HOLD_OBSERVATION_INVALID")

    def test_digest_stable_under_same_input_and_changes_with_diff(self):
        first = build_change_packet(observed(), management_source="LOCAL_GPO")
        again = build_change_packet(observed(), management_source="LOCAL_GPO")
        altered = observed()
        altered["policy_states"]["AllowNetworking"] = "ALLOWED"
        second = build_change_packet(altered, management_source="LOCAL_GPO")
        self.assertEqual(first["plan_sha256"], again["plan_sha256"])
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])
        self.assert_no_authority(first)
        self.assert_no_authority(second)

    def test_no_live_host_io_functions_or_privileged_change(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path(__file__).with_name("gate_c_policy_change_packet.py").read_text(encoding="utf-8"))
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertTrue(imports)
        module = Path(__file__).with_name("gate_c_policy_change_packet.py").read_text(encoding="utf-8")
        for forbidden in ("import winreg", "subprocess", "CreateProcess", "ctypes", "win32api", "Set-ItemProperty"):
            self.assertNotIn(forbidden, module)

    def test_cli_no_input_yields_hold_without_host_read(self):
        buf = io.StringIO()
        with patch.object(sys, "argv", ["change-packet"]), redirect_stdout(buf):
            main()
        packet = json.loads(buf.getvalue())
        self.assertEqual(packet["disposition"], "HOLD_OBSERVATION_INVALID")
        self.assert_no_authority(packet)

    def test_cli_rejects_any_arguments(self):
        with patch.object(sys, "argv", ["change-packet", "--apply"]):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
