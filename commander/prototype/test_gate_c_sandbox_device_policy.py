"""Cross-platform, negative-first tests for Gate C Windows Sandbox policy audit."""
from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

from gate_c_sandbox_device_policy import (
    CLASSIFICATION,
    DWORD,
    REQUIRED_POLICIES,
    _classify_entry,
    _read_policy,
    POLICY_PATH,
    inspect_device_policy,
    main,
)


class DevicePolicyTests(unittest.TestCase):
    def assert_only_data(self, result):
        self.assertEqual(result["classification"], CLASSIFICATION)
        for key in (
            "runtime_policy_enforcement_verified",
            "post_start_mutation_denial_verified", "guest_isolation_verified",
            "hardware_owner_presence_verified", "admin_session_authorized",
        ):
            self.assertIs(result[key], False)
        self.assertEqual(set(result["policy_states"]), set(REQUIRED_POLICIES))
        self.assertEqual(len(result), 11)
        serialized = json.dumps(result).lower()
        self.assertNotIn("hostname", serialized)
        self.assertNotIn("username", serialized)
        self.assertNotIn("registry_path", serialized)

    def all_zero(self, _):
        return (0, DWORD)

    def test_non_windows_never_reads_any_registry(self):
        def fail(_):
            self.fail("Non-Windows must not read policies")
        r = inspect_device_policy(platform_tag="linux", os_build=26100, reader=fail)
        self.assertFalse(r["mapped_folder_policy_build_supported"])
        self.assertEqual(set(r["policy_states"].values()), {"NOT_INSPECTED"})
        self.assertFalse(r["all_required_policies_explicitly_deny"])
        self.assert_only_data(r)

    def test_pre_24h2_build_stops_without_read(self):
        def fail(_):
            self.fail("Unsupported Windows build must not inspect")
        r = inspect_device_policy(platform_tag="win32", os_build=26099, reader=fail)
        self.assertFalse(r["mapped_folder_policy_build_supported"])
        self.assert_only_data(r)

    def test_exact_all_denies_are_only_a_signal_not_authority(self):
        calls = []
        def read(name):
            calls.append(name)
            return (0, DWORD)
        r = inspect_device_policy(platform_tag="win32", os_build=26100, reader=read)
        self.assertEqual(tuple(calls), REQUIRED_POLICIES)
        self.assertTrue(r["mapped_folder_policy_build_supported"])
        self.assertTrue(r["all_required_policies_explicitly_deny"])
        self.assertEqual(set(r["policy_states"].values()), {"EXPLICIT_DENY"})
        self.assert_only_data(r)

    def test_each_missing_policy_fails_complete_deny_signal(self):
        for target in REQUIRED_POLICIES:
            with self.subTest(target=target):
                def read(name):
                    if name == target:
                        raise FileNotFoundError("synthetic")
                    return (0, DWORD)
                r = inspect_device_policy(platform_tag="win32", os_build=26100, reader=read)
                self.assertEqual(r["policy_states"][target], "NOT_CONFIGURED")
                self.assertFalse(r["all_required_policies_explicitly_deny"])
                self.assert_only_data(r)

    def test_each_explicit_allow_fails_complete_deny_signal(self):
        for target in REQUIRED_POLICIES:
            with self.subTest(target=target):
                r = inspect_device_policy(platform_tag="win32", os_build=26100,
                    reader=lambda n: (1 if n == target else 0, DWORD))
                self.assertEqual(r["policy_states"][target], "ALLOWED")
                self.assertFalse(r["all_required_policies_explicitly_deny"])
                self.assert_only_data(r)

    def test_each_wrong_data_type_fails(self):
        for invalid in (False, True, "0", None, b"0", 0.0, [], {}):
            with self.subTest(invalid=repr(invalid)):
                self.assertEqual(_classify_entry((invalid, DWORD)), "INVALID")

    def test_each_wrong_registry_type_fails(self):
        for invalid in (None, False, "4", 1, 3, 7):
            with self.subTest(invalid=repr(invalid)):
                self.assertEqual(_classify_entry((0, invalid)), "INVALID")

    def test_malformed_registry_pair_fails(self):
        for bad in (None, False, (0,), (0, 4, 7), "0", [0, 4], {}):
            self.assertEqual(_classify_entry(bad), "INVALID")

    def test_unknown_integer_dword_is_invalid(self):
        for bad in (-1, 2, 4294967295):
            self.assertEqual(_classify_entry((bad, DWORD)), "INVALID")

    def test_permission_error_is_unavailable_not_false_deny(self):
        r = inspect_device_policy(platform_tag="win32", os_build=26100,
            reader=lambda _: (_ for _ in ()).throw(PermissionError("blocked")))
        self.assertEqual(set(r["policy_states"].values()), {"UNAVAILABLE"})
        self.assertFalse(r["all_required_policies_explicitly_deny"])
        self.assert_only_data(r)

    def test_generic_os_error_is_unavailable_not_false_deny(self):
        r = inspect_device_policy(platform_tag="win32", os_build=26100,
            reader=lambda _: (_ for _ in ()).throw(OSError("unavailable")))
        self.assertEqual(set(r["policy_states"].values()), {"UNAVAILABLE"})
        self.assert_only_data(r)

    def test_invalid_build_is_never_supported(self):
        for bad in (None, False, True, "26100", 0, -1, 26000, 26100.0):
            with self.subTest(bad=repr(bad)):
                if bad is None:
                    with patch("gate_c_sandbox_device_policy._windows_build", return_value=None):
                        r = inspect_device_policy(platform_tag="win32", os_build=None, reader=self.all_zero)
                else:
                    r = inspect_device_policy(platform_tag="win32", os_build=bad, reader=self.all_zero)
                self.assertFalse(r["mapped_folder_policy_build_supported"])
                self.assertFalse(r["all_required_policies_explicitly_deny"])
                self.assert_only_data(r)

    def test_build_26101_supported_but_never_admits_guest(self):
        r = inspect_device_policy(platform_tag="win32", os_build=26101, reader=self.all_zero)
        self.assertTrue(r["all_required_policies_explicitly_deny"])
        self.assert_only_data(r)

    def test_no_arguments_cli_emits_only_sanitized_data(self):
        out = io.StringIO()
        with patch.object(sys, "argv", ["audit"]), redirect_stdout(out):
            main()
        r = json.loads(out.getvalue())
        self.assert_only_data(r)

    def test_cli_rejects_argument_including_approve(self):
        with patch.object(sys, "argv", ["audit", "--approve"]):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 2)

    def test_native_winreg_adapter_reads_only_hklm64(self):
        calls = []
        class Key:
            def __enter__(self):
                return "fake-handle"
            def __exit__(self, exc_type, exc, tb):
                return False
        fake = SimpleNamespace(
            HKEY_LOCAL_MACHINE=2147483650,
            KEY_READ=0x20019,
            KEY_WOW64_64KEY=0x0100,
            OpenKey=lambda *a: (calls.append(("open", a)), Key())[1],
            QueryValueEx=lambda *a: (calls.append(("query", a)), (0, DWORD))[1],
        )
        with patch.dict(sys.modules, {"winreg": fake}):
            x = _read_policy("AllowNetworking")
        self.assertEqual(x, (0, DWORD))
        self.assertEqual(calls[0], ("open", (
            fake.HKEY_LOCAL_MACHINE, POLICY_PATH, 0,
            fake.KEY_READ | fake.KEY_WOW64_64KEY,
        )))
        self.assertEqual(calls[1], ("query", ("fake-handle", "AllowNetworking")))

    def test_mixed_policies_never_report_all_denies(self):
        r = inspect_device_policy(platform_tag="win32", os_build=26100,
            reader=lambda n: (0, DWORD) if n == "AllowNetworking" else (1, DWORD))
        self.assertFalse(r["all_required_policies_explicitly_deny"])
        self.assert_only_data(r)


if __name__ == "__main__":
    unittest.main()
