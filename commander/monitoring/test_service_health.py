"""Contract tests: no actual host services or privileged operations are queried."""
import json
import ntpath
import os
import subprocess
import unittest
from datetime import datetime, timezone, timedelta
from unittest import mock

from service_health import (
    CONTRACT, MAX_AGE_SECONDS, MAX_SERVICES, Expected, Health,
    LocalServiceObserver, Manager, Observed, ServiceDefinition,
    ServiceMonitorError, ServiceObservation, age_guard, evaluate,
    parse_systemd, parse_windows_scm, trusted_windows_system_directory,
)


NOW = datetime(2026, 11, 3, 22, 0, tzinfo=timezone.utc)
LINUX = ServiceDefinition("ldw-commander", "ldw-commander.service",
                          Manager.LINUX_SYSTEMD, Expected.RUNNING)
WINDOWS = ServiceDefinition("ldw-commander", "LDW.Commander",
                            Manager.WINDOWS_SCM, Expected.RUNNING)


def result(code=0, out=b"", err=b""):
    return subprocess.CompletedProcess(["synthetic"], code, out, err)


class ObserverTests(unittest.TestCase):
    def observer(self, definition=LINUX, output=None, platform="linux"):
        calls = []
        def runner(argv, timeout):
            calls.append((list(argv), timeout))
            if isinstance(output, BaseException):
                raise output
            return output or result(0, b"active\n")
        if platform == "windows":
            # Synthetic Windows contract tests run on both Linux and Windows.
            patcher = mock.patch("service_health.trusted_windows_system_directory",
                                 return_value=r"C:\Windows\System32")
            patcher.start()
            self.addCleanup(patcher.stop)
        obs = LocalServiceObserver((definition,), platform, runner,
                                   clock=lambda: NOW)
        return obs, calls

    def test_linux_active_proves_running_required_service(self):
        monitor, calls = self.observer()
        seen = monitor.observe("ldw-commander")
        self.assertEqual((seen.observed, seen.health, seen.evidence_code),
                         (Observed.RUNNING, Health.HEALTHY, "SYSTEMD_ACTIVE"))
        self.assertEqual(calls, [(["/usr/bin/systemctl", "--system",
                                   "is-active", "--", "ldw-commander.service"], 2)])

    def test_linux_inactive_or_failed_reports_confirmed_stopped(self):
        for out in (b"inactive\n", b"failed\n", b"deactivating\n"):
            with self.subTest(out=out):
                monitor, _ = self.observer(output=result(3, out))
                seen = monitor.observe("ldw-commander")
                self.assertEqual((seen.observed, seen.health),
                                 (Observed.STOPPED, Health.FAILED))

    def test_systemd_unverified_does_not_claim_healthy_or_failed(self):
        for code, out in ((4, b"unknown\n"), (1, b"active\n"),
                          (0, b"ACTIVE\n"), (3, b"not-found\n"),
                          (3, b"inactive but unknown extra")):
            with self.subTest(code=code, out=out):
                monitor, _ = self.observer(output=result(code, out))
                seen = monitor.observe("ldw-commander")
                self.assertEqual((seen.observed, seen.health),
                                 (Observed.UNKNOWN, Health.UNKNOWN))

    def test_windows_service_manager_reports_running(self):
        monitor, calls = self.observer(WINDOWS, result(0,
            b"SERVICE_NAME: LDW.Commander\r\n        STATE              : 4  RUNNING\r\n"),
            platform="windows")
        seen = monitor.observe("ldw-commander")
        self.assertEqual((seen.observed, seen.health, seen.evidence_code),
                         (Observed.RUNNING, Health.HEALTHY, "SCM_RUNNING"))
        self.assertEqual(calls[0][0][-2:], ["query", "LDW.Commander"])
        self.assertEqual(calls[0][1], 2)

    def test_windows_stopped_is_failure_when_expected_running(self):
        monitor, _ = self.observer(WINDOWS,
                                   result(0, b"SERVICE_NAME: LDW.Commander\nSTATE : 1  STOPPED\n"), "windows")
        seen = monitor.observe("ldw-commander")
        self.assertEqual((seen.observed, seen.health),
                         (Observed.STOPPED, Health.FAILED))

    def test_windows_bogus_state_and_failed_query_are_unknown(self):
        for x in (result(0, b"STATE : 4 STOPPED"),
                  result(0, b"STATE : 1 RUNNING"),
                  result(1060, b"", b"service not installed"),
                  result(0, b"RUNNING in program output")):
            with self.subTest(x=x):
                monitor, _ = self.observer(WINDOWS, x, "windows")
                self.assertEqual(monitor.observe("ldw-commander").health,
                                 Health.UNKNOWN)

    def test_scm_status_binds_exact_single_requested_service(self):
        # The name header must be unique, the state unique, and both match
        # the trusted registered service. Never parse an unrelated Green.
        samples = (
            b"STATE : 4  RUNNING\n",
            b"SERVICE_NAME: Other.Service\nSTATE : 4  RUNNING\n",
            b"SERVICE_NAME: LDW.Commander\nSERVICE_NAME: Other.Service\nSTATE : 4 RUNNING\n",
            b"SERVICE_NAME: LDW.Commander\nSTATE : 4 RUNNING\nSTATE : 1 STOPPED\n",
            b"SERVICE_NAME: LDW.Commander\nSTATE : 2 START_PENDING\n",
        )
        for output in samples:
            with self.subTest(output=output):
                observer, _ = self.observer(WINDOWS, result(0, output), "windows")
                item = observer.observe("ldw-commander")
                self.assertEqual((item.observed, item.health),
                                 (Observed.UNKNOWN, Health.UNKNOWN))

    def test_spoofed_systemroot_cannot_select_fake_scm_binary(self):
        # A trusted Windows directory is resolved through the native API,
        # not through attacker-controlled SystemRoot or PATH.
        with mock.patch.dict(os.environ, {
            "SystemRoot": r"C:\AttackerFakeWindows",
            "PATH": r"C:\AttackerFakeWindows\System32",
        }):
            observer, calls = self.observer(
                WINDOWS, result(0,
                    b"SERVICE_NAME: LDW.Commander\nSTATE : 4  RUNNING\n"),
                platform="windows",
            )
            item = observer.observe("ldw-commander")
        self.assertEqual(item.health, Health.HEALTHY)
        self.assertEqual(calls[0][0][0], ntpath.join(
            r"C:\Windows\System32", "sc.exe"))
        self.assertNotIn("AttackerFakeWindows", calls[0][0][0])

    @unittest.skipUnless(os.name == "nt", "native Windows API proof only")
    def test_real_windows_system_directory_ignores_environment_override(self):
        before = trusted_windows_system_directory()
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\FakeWindows"}):
            after = trusted_windows_system_directory()
        self.assertEqual(before.casefold(), after.casefold())
        self.assertTrue(ntpath.isabs(before))
        self.assertIn(ntpath.basename(before).casefold(),
                      ("system32", "syswow64"))

    def test_manager_mismatch_does_not_execute_probe(self):
        monitor, calls = self.observer(LINUX, platform="windows")
        seen = monitor.observe("ldw-commander")
        self.assertEqual((seen.health, seen.evidence_code),
                         (Health.UNKNOWN, "MANAGER_NOT_ON_THIS_HOST"))
        self.assertEqual(calls, [])

    def test_timeout_and_permission_denied_remain_unknown(self):
        for x in (subprocess.TimeoutExpired(["systemctl"], 2),
                  PermissionError("a secret should not appear in status")):
            monitor, _ = self.observer(output=x)
            seen = monitor.observe("ldw-commander")
            self.assertEqual((seen.health, seen.evidence_code),
                             (Health.UNKNOWN, "PROBE_UNAVAILABLE"))
            self.assertNotIn("secret", json.dumps(seen.to_wire()).lower())

    def test_on_demand_stopped_is_intentionally_healthy(self):
        ondemand = ServiceDefinition("ldw-auto-browser", "ldw-auto-browser.service",
                                     Manager.LINUX_SYSTEMD, Expected.ON_DEMAND)
        monitor, _ = self.observer(ondemand, result(3, b"inactive\n"))
        self.assertEqual(monitor.observe("ldw-auto-browser").health, Health.HEALTHY)
        self.assertEqual(evaluate(ondemand, Observed.ABSENT), Health.UNKNOWN)

    def test_disabled_running_is_not_healthy(self):
        d = ServiceDefinition("ldw-chat-relay", "ldw-chat-relay.service",
                              Manager.LINUX_SYSTEMD, Expected.DISABLED)
        monitor, _ = self.observer(d)
        self.assertEqual(monitor.observe("ldw-chat-relay").health, Health.FAILED)
        self.assertEqual(evaluate(d, Observed.STOPPED), Health.HEALTHY)

    def test_optional_failure_degrades(self):
        d = ServiceDefinition("ldw-auto-browser", "ldw-auto-browser.service",
                              Manager.LINUX_SYSTEMD, Expected.RUNNING, required=False)
        monitor, _ = self.observer(d, result(3, b"failed\n"))
        self.assertEqual(monitor.observe("ldw-auto-browser").health, Health.DEGRADED)

    def test_absent_required_expected_running_is_failed_but_unknown_is_not(self):
        self.assertEqual(evaluate(LINUX, Observed.ABSENT), Health.FAILED)
        self.assertEqual(evaluate(LINUX, Observed.UNKNOWN), Health.UNKNOWN)

    def test_status_wire_has_fixed_sanitized_schema(self):
        seen = self.observer()[0].observe("ldw-commander").to_wire()
        self.assertEqual(seen, {
            "contract": CONTRACT, "service_id": "ldw-commander",
            "manager": "LINUX_SYSTEMD", "desired_state": "RUNNING",
            "required": True, "observed_state": "RUNNING",
            "health_state": "HEALTHY", "observed_at_utc": "2026-11-03T22:00:00Z",
            "evidence_code": "SYSTEMD_ACTIVE",
        })
        self.assertNotIn("token", json.dumps(seen).lower())
        self.assertNotIn("pid", json.dumps(seen).lower())

    def test_stale_is_unknown_not_last_known_green(self):
        seen = self.observer()[0].observe("ldw-commander")
        old = age_guard(seen, NOW + timedelta(seconds=MAX_AGE_SECONDS + 1))
        self.assertEqual((old.observed, old.health, old.evidence_code),
                         (Observed.UNKNOWN, Health.UNKNOWN, "STALE_OR_CLOCK_UNTRUSTED"))

    def test_future_clock_skew_unknown(self):
        seen = self.observer()[0].observe("ldw-commander")
        bad = age_guard(seen, NOW - timedelta(seconds=6))
        self.assertEqual((bad.health, bad.evidence_code),
                         (Health.UNKNOWN, "STALE_OR_CLOCK_UNTRUSTED"))

    def test_time_between_boundaries_remains_fresh(self):
        seen = self.observer()[0].observe("ldw-commander")
        self.assertEqual(age_guard(seen, NOW + timedelta(seconds=30)).health,
                         Health.HEALTHY)
        self.assertEqual(age_guard(seen, NOW - timedelta(seconds=5)).health,
                         Health.HEALTHY)

    def test_registry_rejects_unapproved_component(self):
        monitor, calls = self.observer()
        with self.assertRaises(ServiceMonitorError):
            monitor.observe("other-ldw-service")
        self.assertEqual(calls, [])

    def test_untrusted_names_and_arbitrary_commands_refused(self):
        for name in ("--force", "; curl example.test", "../../etc/shadow",
                     "service name with spaces", "/bin/sh", "name\nshell"):
            with self.subTest(name=name):
                with self.assertRaises(ServiceMonitorError):
                    ServiceDefinition("service-id", name,
                                      Manager.LINUX_SYSTEMD, Expected.RUNNING)

    def test_invalid_component_ids_refused(self):
        for name in ("CMD", "", "a", "a.b", "a/b", "a"*65, "../", "a\n"):
            with self.subTest(name=name):
                with self.assertRaises(ServiceMonitorError):
                    ServiceDefinition(name, "unit.service",
                                      Manager.LINUX_SYSTEMD, Expected.RUNNING)

    def test_registry_uniqueness_limit_and_type(self):
        with self.assertRaises(ServiceMonitorError):
            LocalServiceObserver((LINUX, LINUX), "linux")
        too_many = tuple(ServiceDefinition(f"ldw-{i}", f"svc{i}.service",
                                            Manager.LINUX_SYSTEMD, Expected.RUNNING)
                         for i in range(MAX_SERVICES+1))
        with self.assertRaises(ServiceMonitorError):
            LocalServiceObserver(too_many, "linux")
        with self.assertRaises(ServiceMonitorError):
            LocalServiceObserver([LINUX], "linux")

    def test_naive_timestamp_refused(self):
        monitor, _ = self.observer()
        with self.assertRaises(ServiceMonitorError):
            monitor.observe("ldw-commander", datetime(2026, 11, 3))
        obs = monitor.observe("ldw-commander")
        with self.assertRaises(ServiceMonitorError):
            age_guard(obs, datetime(2026, 11, 3))

    def test_tampered_unknown_evidence_not_healthy(self):
        d = ServiceDefinition("ldw-commander", "ldw-commander.service",
                              Manager.LINUX_SYSTEMD, Expected.RUNNING)
        # A service's own string "healthy" is never an OS-manager state.
        monitor, _ = self.observer(d, result(1, b"HEALTHY\n",
                                            b"provider claimed success"))
        self.assertEqual(monitor.observe("ldw-commander").health, Health.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
