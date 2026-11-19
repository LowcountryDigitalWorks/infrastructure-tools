"""Deterministic, no-host negative tests of Gate C read-only G0 observation."""
from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gate_c_host_g0_readonly import (
    CLASSIFICATION, POWERSHELL_PROBE, RAW_KEYS, SCHEMA,
    _native_system_powershell, collect_g0_snapshot, main,
)


def snapshot(**kwargs):
    value = dict(
        domain_joined_hint="NO",
        windows_sandbox_feature="DISABLED",
        policy_manager_windows_sandbox_key="ABSENT",
        policy_manager_fixed_value_count=0,
        local_machine_gpo_pol_file="ABSENT",
        operator_token_elevated="NO",
    )
    value.update(kwargs)
    return value


def fake_runner(output, *, rc=0):
    return lambda command, **opts: SimpleNamespace(returncode=rc, stdout=output, stderr="ignored synthetic error")


def run(payload=None, *, rc=0, runner=None, platform="win32", executable="/synthetic-windows/System32/WindowsPowerShell/v1.0/powershell.exe"):
    if runner is None:
        if payload is None:
            payload = snapshot()
        runner = fake_runner(json.dumps(payload), rc=rc)
    return collect_g0_snapshot(platform_tag=platform, powershell_locator=lambda: executable, runner=runner)


class G0ReadOnlyTests(unittest.TestCase):
    def assert_not_authorized(self, r):
        self.assertEqual(r["schema"], SCHEMA)
        self.assertEqual(r["classification"], CLASSIFICATION)
        self.assertEqual(len(r), 14)
        for key in (
            "management_source_verified", "effective_policy_proven",
            "guest_isolation_proven", "physical_change_executed",
            "admin_session_authorized",
        ):
            self.assertIs(r[key], False)
        for sensitive in ("host_name", "user_name", "sid", "registry_path", "tenant_id", "raw_value"):
            self.assertNotIn(sensitive, json.dumps(r).lower())

    def test_expected_g0_ldw01_fixture_is_data_only(self):
        r = run()
        self.assertEqual(r["disposition"], "G0_HINTS_ONLY_AUTHORITY_UNVERIFIED")
        self.assertEqual(r["windows_sandbox_feature"], "DISABLED")
        self.assertEqual(r["policy_manager_fixed_value_count"], 0)
        self.assert_not_authorized(r)

    def test_enabled_feature_never_authorizes(self):
        r = run(snapshot(windows_sandbox_feature="ENABLED", operator_token_elevated="YES"))
        self.assertEqual(r["windows_sandbox_feature"], "ENABLED")
        self.assert_not_authorized(r)

    def test_key_present_seven_values_is_not_effective_policy(self):
        r = run(snapshot(policy_manager_windows_sandbox_key="PRESENT", policy_manager_fixed_value_count=7,
                         domain_joined_hint="YES", local_machine_gpo_pol_file="PRESENT"))
        self.assertEqual(r["policy_manager_fixed_value_count"], 7)
        self.assert_not_authorized(r)

    def test_non_windows_does_not_invoke_runner(self):
        def fail(*a, **kw):
            self.fail("Non-Windows platform called Windows command")
        r = collect_g0_snapshot(platform_tag="linux", powershell_locator=lambda: self.fail("Non-Windows location lookup"), runner=fail)
        self.assertEqual(r["disposition"], "HOLD_NOT_WINDOWS")
        self.assert_not_authorized(r)

    def test_missing_system_powershell_fails_without_runner(self):
        def fail(*a, **kw):
            self.fail("Missing root invoked Windows command")
        for bad in ("", "relative", None):
            with self.subTest(bad=bad):
                r = collect_g0_snapshot(platform_tag="win32", powershell_locator=lambda: bad, runner=fail)
                self.assertIn(r["disposition"], {"HOLD_SYSTEM_DIRECTORY_UNAVAILABLE"})
                self.assert_not_authorized(r)

    def test_native_powershell_resolver_uses_kernel32_system_directory(self):
        import gate_c_host_g0_readonly as module
        calls = []
        class Api:
            def __init__(self):
                self.argtypes = None
                self.restype = None
            def __call__(self, buffer, length):
                self.expected_len = length
                buffer.value = "/synthetic-windows/System32"
                return len(buffer.value)
        api = Api()
        class Dll:
            GetSystemDirectoryW = api
        def fake_win_dll(name, *, winmode):
            calls.append((name, winmode))
            return Dll()
        with patch.object(module.ctypes, "WinDLL", fake_win_dll, create=True):
            value = _native_system_powershell()
        self.assertEqual(calls, [("kernel32.dll", 0x800)])
        self.assertEqual(value, "/synthetic-windows/System32/WindowsPowerShell/v1.0/powershell.exe")

    def test_native_powershell_api_failure_holds(self):
        import gate_c_host_g0_readonly as module
        with patch.object(module.ctypes, "WinDLL", side_effect=OSError("no OS api"), create=True):
            self.assertIsNone(_native_system_powershell())

    def test_runner_called_once_with_bounded_fixed_read_only_script(self):
        calls = []
        def inspect(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps(snapshot()), stderr="")
        r = run(runner=inspect)
        self.assertEqual(len(calls), 1)
        cmd, opts = calls[0]
        self.assertEqual(cmd[0], str(Path("/synthetic-windows") / "System32/WindowsPowerShell/v1.0/powershell.exe"))
        self.assertEqual(cmd[1:4], ["-NoLogo", "-NoProfile", "-NonInteractive"])
        self.assertEqual(cmd[-2:], ["-Command", POWERSHELL_PROBE])
        self.assertNotIn("shell", opts)
        self.assertTrue(opts["capture_output"])
        self.assertEqual(opts["timeout"], 12)
        self.assertIs(opts["check"], False)
        self.assert_not_authorized(r)

    def test_environment_does_not_control_executable_path(self):
        # PowerShell executable is resolved from OS GetSystemDirectoryW,
        # not a user-supplied PATH or SystemRoot variable.
        import gate_c_host_g0_readonly as module
        with patch.object(module, "_native_system_powershell", return_value="/synthetic-windows/System32/WindowsPowerShell/v1.0/powershell.exe"):
            with patch.dict("os.environ", {"SystemRoot": "/malicious", "PATH": "/malicious"}):
                calls = []
                def run_it(cmd, **kw):
                    calls.append(cmd)
                    return SimpleNamespace(returncode=0, stdout=json.dumps(snapshot()), stderr="")
                r = collect_g0_snapshot(platform_tag="win32", runner=run_it)
        self.assertEqual(calls[0][0], "/synthetic-windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        self.assert_not_authorized(r)

    def test_powershell_script_has_only_read_functions(self):
        for s in ("Get-CimInstance", "Registry64", "OpenSubKey", "Test-Path", "ConvertTo-Json", "IsInRole"):
            self.assertIn(s, POWERSHELL_PROBE)
        for s in ("Set-Item", "Set-Content", "Set-ExecutionPolicy", "Enable-WindowsOptionalFeature",
                  "Disable-WindowsOptionalFeature", "New-Item", "Remove-Item", "Start-Process", "wsb start",
                  "wsb exec", "Invoke-WebRequest", "Invoke-Expression", "SetValue(", "CreateSubKey("):
            self.assertNotIn(s, POWERSHELL_PROBE)

    def test_nonzero_exit_is_hold_and_no_stderr_leak(self):
        r = run(snapshot(), rc=1)
        self.assertEqual(r["disposition"], "HOLD_PROBE_FAILED")
        self.assertNotIn("ignored synthetic error", json.dumps(r))
        self.assert_not_authorized(r)

    def test_runner_exception_is_hold(self):
        for error in (OSError("private-path"), ValueError("secret"), TypeError("other")):
            with self.subTest(error=type(error).__name__):
                def fail(*a, **kw):
                    raise error
                r = run(runner=fail)
                self.assertEqual(r["disposition"], "HOLD_PROBE_UNAVAILABLE")
                self.assertNotIn(str(error), json.dumps(r))
                self.assert_not_authorized(r)

    def test_timeout_is_hold(self):
        import subprocess
        def fail(*a, **kw):
            raise subprocess.TimeoutExpired("powershell", 12)
        r = run(runner=fail)
        self.assertEqual(r["disposition"], "HOLD_PROBE_UNAVAILABLE")
        self.assert_not_authorized(r)

    def test_malformed_json_is_hold(self):
        for raw in ("", "not-json", "{", "[]", "false", "null", "1337"):
            with self.subTest(raw=raw):
                r = run(runner=fake_runner(raw))
                self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
                self.assert_not_authorized(r)

    def test_duplicate_json_fields_fail_closed(self):
        raw = json.dumps(snapshot())[:-1] + ', "domain_joined_hint":"YES"}'
        r = run(runner=fake_runner(raw))
        self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
        self.assert_not_authorized(r)

    def test_oversized_output_rejected(self):
        r = run(runner=fake_runner("A" * 2050))
        self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
        self.assert_not_authorized(r)

    def test_unknown_fields_rejected_without_reflection(self):
        r = run(snapshot(hostname="private-machine-id", password="secret"))
        self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
        self.assertNotIn("private-machine-id", json.dumps(r))
        self.assert_not_authorized(r)

    def test_missing_fields_rejected(self):
        data = snapshot()
        data.pop("operator_token_elevated")
        r = run(data)
        self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
        self.assert_not_authorized(r)

    def test_invalid_counts_rejected(self):
        for invalid in (-1, 8, False, True, "0", None, 0.0):
            with self.subTest(invalid=repr(invalid)):
                r = run(snapshot(policy_manager_windows_sandbox_key="PRESENT", policy_manager_fixed_value_count=invalid))
                self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
                self.assert_not_authorized(r)

    def test_absent_or_unavailable_policy_key_requires_zero_count(self):
        for key in ("ABSENT", "UNAVAILABLE"):
            r = run(snapshot(policy_manager_windows_sandbox_key=key, policy_manager_fixed_value_count=2))
            self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
            self.assert_not_authorized(r)

    def test_invalid_enum_states_rejected(self):
        for name, value in (
            ("domain_joined_hint", "CORPORATE_DOMAIN"),
            ("windows_sandbox_feature", "ENABLING"),
            ("policy_manager_windows_sandbox_key", "READY"),
            ("local_machine_gpo_pol_file", "C:\\GPO\\Registry.pol"),
            ("operator_token_elevated", "Administrator"),
        ):
            with self.subTest(name=name):
                r = run(snapshot(**{name: value}))
                self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
                self.assert_not_authorized(r)

    def test_non_string_enum_states_rejected(self):
        for bad in (None, True, False, [], 0, {"YES": True}):
            with self.subTest(bad=repr(bad)):
                r = run(snapshot(domain_joined_hint=bad))
                self.assertEqual(r["disposition"], "HOLD_INVALID_PROBE_OUTPUT")
                self.assert_not_authorized(r)

    def test_cli_rejects_any_arguments(self):
        with patch.object(sys, "argv", ["preflight", "--enable-sandbox"]):
            with self.assertRaises(SystemExit) as exc:
                main()
        self.assertEqual(exc.exception.code, 2)

    def test_cli_on_non_windows_has_sanitized_hold(self):
        import gate_c_host_g0_readonly as g0
        out = io.StringIO()
        with patch.object(g0.sys, "platform", "linux"), patch.object(sys, "argv", ["preflight"]), redirect_stdout(out):
            main()
        r = json.loads(out.getvalue())
        self.assertEqual(r["disposition"], "HOLD_NOT_WINDOWS")
        self.assert_not_authorized(r)


if __name__ == "__main__":
    unittest.main()
