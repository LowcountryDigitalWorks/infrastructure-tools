"""Data-only, non-launching Windows Sandbox configuration policy negatives."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from gate_c_sandbox_profile import (
    CLASSIFICATION, EXPECTED_SETTINGS, PROFILE_NAME,
    inspect_source, main, matches_fixed_profile,
)

PROFILE = Path(__file__).with_name(PROFILE_NAME).read_text(encoding="utf-8")


class ProfileTests(unittest.TestCase):
    def test_reference_profile_matches_and_is_not_authority(self):
        self.assertTrue(matches_fixed_profile(PROFILE))
        result = inspect_source()
        self.assertEqual(result["classification"], CLASSIFICATION)
        self.assertIs(result["fixed_profile_matches"], True)
        for key in (
            "feature_installed_verified", "guest_started_verified",
            "external_network_confinement_verified", "owner_presence_verified",
            "admin_session_authorized",
        ):
            self.assertIs(result[key], False)
        self.assertEqual(len(result), 7)

    def test_each_rejected_option_relaxation(self):
        for key, expected in EXPECTED_SETTINGS:
            with self.subTest(key=key):
                replacement = "Enable" if expected == "Disable" else "Disable"
                changed = PROFILE.replace(f"<{key}>{expected}</{key}>", f"<{key}>{replacement}</{key}>")
                self.assertNotEqual(changed, PROFILE)
                self.assertFalse(matches_fixed_profile(changed))

    def test_each_missing_protection_fails(self):
        for key, value in EXPECTED_SETTINGS:
            with self.subTest(key=key):
                changed = PROFILE.replace(f"  <{key}>{value}</{key}>\n", "")
                self.assertFalse(matches_fixed_profile(changed))

    def test_duplicate_element_fails(self):
        self.assertFalse(matches_fixed_profile(PROFILE.replace(
            "</Configuration>", "  <Networking>Disable</Networking>\n</Configuration>")))

    def test_unknown_option_fails(self):
        self.assertFalse(matches_fixed_profile(PROFILE.replace(
            "</Configuration>", "  <Unsupported>Disable</Unsupported>\n</Configuration>")))

    def test_host_mapping_even_readonly_fails(self):
        snippet = "<MappedFolders><MappedFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>"
        self.assertFalse(matches_fixed_profile(PROFILE.replace("</Configuration>", snippet + "</Configuration>")))

    def test_any_logon_command_fails(self):
        changed = PROFILE.replace("</Configuration>", "<LogonCommand><Command>cmd</Command></LogonCommand></Configuration>")
        self.assertFalse(matches_fixed_profile(changed))

    def test_attributes_and_nested_children_fail(self):
        self.assertFalse(matches_fixed_profile(PROFILE.replace("<Networking>", "<Networking enabled='1'>")))
        self.assertFalse(matches_fixed_profile(PROFILE.replace("<Networking>Disable</Networking>", "<Networking><Extra/>Disable</Networking>")))

    def test_doctype_entity_comment_and_pi_rejected(self):
        for prefix in ('<!DOCTYPE Configuration [<!ENTITY x "a">]>', "<!-- note -->", "<?probe x?>"):
            with self.subTest(prefix=prefix):
                self.assertFalse(matches_fixed_profile(prefix + PROFILE))

    def test_order_case_and_value_variants_rejected(self):
        self.assertFalse(matches_fixed_profile(PROFILE.replace("<Networking>Disable</Networking>", "<networking>Disable</networking>")))
        self.assertFalse(matches_fixed_profile(PROFILE.replace("<Networking>Disable</Networking>", "<Networking>Default</Networking>")))
        self.assertFalse(matches_fixed_profile(PROFILE.replace("<vGPU>Disable</vGPU>", "<vGPU>disable</vGPU>")))

    def test_malformed_and_wrong_root_rejected(self):
        self.assertFalse(matches_fixed_profile(PROFILE[:-3]))
        self.assertFalse(matches_fixed_profile(PROFILE.replace("Configuration", "Sandbox")))

    def test_empty_oversized_and_nonstring_fails(self):
        for bad in ("", "a" * 3000, None, True, b"<Configuration/>"):
            with self.subTest(type=type(bad).__name__):
                self.assertFalse(matches_fixed_profile(bad))

    def test_cli_zero_arg_prints_nonadmission(self):
        out = io.StringIO()
        with patch.object(sys, "argv", ["sandbox-check"]), redirect_stdout(out):
            main()
        result = json.loads(out.getvalue())
        self.assertEqual(result["classification"], CLASSIFICATION)
        self.assertFalse(result["guest_started_verified"])
        self.assertFalse(result["admin_session_authorized"])

    def test_cli_rejects_any_command_argument(self):
        with patch.object(sys, "argv", ["sandbox-check", "--launch"]):
            with self.assertRaises(SystemExit) as cm:
                main()
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
