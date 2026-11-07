#!/usr/bin/env python3
"""Fail-closed tests for the REDRIX A4 FD preflight. No live proc access."""
from __future__ import annotations

import errno
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE_PATH = ROOT / "tools" / "dragonfly_gate_a4_fd_inspector_core.py"
PREFLIGHT_PATH = ROOT / "tools" / "dragonfly_gate_a4_fd_preflight.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


core = load("_ldw_a4_fd_preflight_core", CORE_PATH)
preflight = load("a4_fd_preflight", PREFLIGHT_PATH)
UID = core.DEFAULT_UID


def clean_root() -> core.SyntheticProcRoot:
    return core.SyntheticProcRoot(
        processes={
            100: core.ProcessFixture(
                pid=100,
                uid=UID,
                starttime=4242,
                comm="worker",
                fd_targets=("/dev/null",),
            )
        }
    )


def measured(**overrides) -> preflight.PrivilegeSnapshot:
    fields = {
        "kernel_measured": True,
        "euid": 0,
        "cap_sys_ptrace": True,
        "cap_dac_read_search": True,
        "user_namespace": "userns-target",
        "pid_namespace": "pidns-target",
        "target_user_namespace": "userns-target",
        "target_pid_namespace": "pidns-target",
        "read_scope_complete": True,
        "correlation": "corr-a4-preflight-1",
        "nonce": "nonce-a4-preflight-1",
        "claims_receiver_authenticated": False,
    }
    fields.update(overrides)
    return preflight.PrivilegeSnapshot(**fields)


class FixedPrivilege:
    def __init__(self, snapshots):
        self._snapshots = list(snapshots)

    def read_privilege(self):
        if len(self._snapshots) > 1:
            return self._snapshots.pop(0)
        return self._snapshots[0]


class DriftFdRoot(core.SyntheticProcRoot):
    def __init__(self):
        super().__init__(
            processes={
                100: core.ProcessFixture(
                    pid=100,
                    uid=UID,
                    starttime=4242,
                    comm="worker",
                    fd_targets=("/dev/null",),
                )
            }
        )
        self.reads = 0

    def list_fd_targets(self, pid: int):
        self.reads += 1
        if self.reads == 1:
            return ["/dev/null"]
        return ["/dev/zero"]


class A4FdPreflightTests(unittest.TestCase):
    def assert_closed(self, result: dict):
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])
        self.assertNotIn("PASS", result["classification"])

    def assert_hold(self, result: dict, reason: str):
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], reason)
        self.assert_closed(result)
        self.assertFalse(result["preflightConsistent"])

    def assert_data_only(self, result: dict, *, consistent: bool):
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertEqual(result["reasonCode"], "EXTERNAL_TRUST_GATES_REQUIRED")
        self.assertEqual(result["preflightConsistent"], consistent)
        self.assert_closed(result)

    def test_source_has_no_launcher_or_pass(self):
        text = PREFLIGHT_PATH.read_text(encoding="utf-8")
        for token in ("__main__", "subprocess", "sudo", "setcap", "systemd", "socket.socket"):
            self.assertNotIn(token, text)
        self.assertNotIn('"a4Pass": True', text)
        self.assertNotIn('"privilegedChannelAuthenticated": True', text)

    def test_no_kernel_evidence_clean_synthetic_stays_data_only(self):
        result = preflight.collect_fd_preflight(clean_root())
        self.assert_data_only(result, consistent=False)

    def test_measured_clean_synthetic_stays_data_only(self):
        result = preflight.collect_fd_preflight(clean_root(), FixedPrivilege([measured()]))
        self.assert_data_only(result, consistent=True)
        self.assertEqual(result["kvmFdProcessCount"], 0)
        self.assertEqual(result["qemuLikeProcessCount"], 0)

    def test_caller_selected_root_and_untrusted_attestation_refused(self):
        self.assert_hold(preflight.collect_fd_preflight("/proc"), "A4_PF_CALLER_SELECTED_ROOT")
        self.assert_hold(
            preflight.collect_fd_preflight(clean_root(), {"euid": 0, "privilegedChannelAuthenticated": True}),
            "A4_PF_UNTRUSTED_ATTESTATION",
        )
        self.assert_hold(
            preflight.collect_fd_preflight(clean_root(), seen_nonces=["nonce-a4-preflight-1"]),
            "A4_PF_UNTRUSTED_ATTESTATION",
        )

    def test_live_proc_adapter_is_refused(self):
        class LinuxProcPort:
            def list_numeric_pids(self):
                return []

            def read_stat_line(self, pid):
                return ""

            def read_status_text(self, pid):
                return ""

            def list_fd_targets(self, pid):
                return []

        self.assert_hold(preflight.collect_fd_preflight(LinuxProcPort()), "A4_PF_CALLER_SELECTED_ROOT")

    def test_false_receiver_auth_and_replay(self):
        self.assert_hold(
            preflight.collect_fd_preflight(
                clean_root(),
                FixedPrivilege([measured(claims_receiver_authenticated=True)]),
            ),
            "A4_PF_FALSE_RECEIVER_AUTH",
        )
        self.assert_hold(
            preflight.collect_fd_preflight(
                clean_root(),
                FixedPrivilege([measured()]),
                seen_nonces=frozenset({"nonce-a4-preflight-1"}),
            ),
            "A4_PF_REPLAY",
        )

    def test_privilege_namespace_and_scope_failures(self):
        cases = (
            (measured(kernel_measured=False, euid=0), "A4_PF_UNPROVEN_PRIVILEGE"),
            (measured(kernel_measured=False, euid=UID, cap_sys_ptrace=False, cap_dac_read_search=False), "A4_PF_PRIVILEGE_NOT_PROVABLE"),
            (measured(cap_sys_ptrace=False, cap_dac_read_search=False, euid=UID), "A4_PF_PRIVILEGE_NOT_PROVABLE"),
            (measured(user_namespace="userns-other"), "A4_PF_USER_NAMESPACE_MISMATCH"),
            (measured(pid_namespace="pidns-other"), "A4_PF_PID_NAMESPACE_MISMATCH"),
            (measured(read_scope_complete=False), "A4_PF_READ_SCOPE_INCOMPLETE"),
        )
        for snapshot, reason in cases:
            with self.subTest(reason=reason):
                self.assert_hold(
                    preflight.collect_fd_preflight(clean_root(), FixedPrivilege([snapshot])),
                    reason,
                )

    def test_privilege_permission_and_snapshot_drift(self):
        class Denied:
            def read_privilege(self):
                raise OSError(errno.EPERM, "synthetic privilege denial")

        self.assert_hold(preflight.collect_fd_preflight(clean_root(), Denied()), "A4_PF_PRIVILEGE_DENIED")
        self.assert_hold(
            preflight.collect_fd_preflight(
                clean_root(),
                FixedPrivilege([measured(), measured(euid=UID)]),
            ),
            "A4_PF_TWO_SNAPSHOT_INCONSISTENT",
        )
        self.assert_hold(
            preflight.collect_fd_preflight(
                clean_root(),
                FixedPrivilege([measured(), measured(nonce="nonce-a4-preflight-2")]),
            ),
            "A4_PF_CORRELATION_MISMATCH",
        )

    def test_core_negative_reasons_pass_through(self):
        cases = (
            (
                core.ProcessFixture(pid=201, uid=UID, starttime=50, comm="bash", fd_os_error=errno.EACCES),
                "A4_FD_DENIED_FD",
            ),
            (
                core.ProcessFixture(pid=202, uid=UID, starttime=50, comm="bash", fd_os_error=errno.EPERM),
                "A4_FD_DENIED_FD",
            ),
            (
                core.ProcessFixture(pid=203, uid=UID, starttime=50, comm="bash", starttime_after_first=99),
                "A4_FD_PID_REUSE",
            ),
            (
                core.ProcessFixture(
                    pid=204,
                    uid=UID,
                    starttime=50,
                    comm="bash",
                    uid_saved=UID,
                    uid_saved_after_first=1001,
                ),
                "A4_FD_PID_REUSE",
            ),
            (
                core.ProcessFixture(pid=207, uid=UID, starttime=50, comm="bash", effective_uid_after_first=1001),
                "A4_FD_INCOMPLETE_ENUMERATION",
            ),
            (
                core.ProcessFixture(pid=205, uid=UID, starttime=50, comm="qemu-system-x86_64"),
                "A4_FD_QEMU_PROCESS_PRESENT",
            ),
            (
                core.ProcessFixture(pid=206, uid=UID, starttime=50, comm="worker", fd_targets=("/dev/kvm",)),
                "A4_FD_KVM_FD_PRESENT",
            ),
        )
        for fixture, reason in cases:
            with self.subTest(reason=reason):
                root = core.SyntheticProcRoot(processes={fixture.pid: fixture})
                result = preflight.collect_fd_preflight(root, FixedPrivilege([measured()]))
                self.assert_hold(result, reason)
                self.assertNotIn("/dev/kvm", str(result))

    def test_fd_target_drift_without_kvm(self):
        result = preflight.collect_fd_preflight(DriftFdRoot(), FixedPrivilege([measured()]))
        self.assert_hold(result, "A4_PF_FD_DRIFT")

    def test_foreign_uid_fd_denial_is_not_read_and_clean_stays_data_only(self):
        class Counting(core.SyntheticProcRoot):
            def __init__(self):
                super().__init__(
                    processes={
                        50: core.ProcessFixture(
                            pid=50,
                            uid=0,
                            starttime=1,
                            comm="other",
                            fd_os_error=errno.EACCES,
                        ),
                        100: core.ProcessFixture(
                            pid=100,
                            uid=UID,
                            starttime=2,
                            comm="worker",
                            fd_targets=("/dev/null",),
                        ),
                    }
                )
                self.asked: list[int] = []

            def list_fd_targets(self, pid: int):
                self.asked.append(pid)
                return super().list_fd_targets(pid)

        root = Counting()
        result = preflight.collect_fd_preflight(root, FixedPrivilege([measured()]))
        self.assert_data_only(result, consistent=True)
        self.assertNotIn(50, root.asked)
        self.assertIn(100, root.asked)

    def test_foreign_qemu_and_unreadable_status_hold(self):
        qemu = core.SyntheticProcRoot(
            processes={
                7: core.ProcessFixture(pid=7, uid=0, starttime=3, comm="qemu-system-x86_64"),
                100: core.ProcessFixture(pid=100, uid=UID, starttime=4, comm="worker", fd_targets=("/dev/null",)),
            }
        )
        self.assert_hold(preflight.collect_fd_preflight(qemu), "A4_FD_QEMU_PROCESS_PRESENT")
        hidden = core.SyntheticProcRoot(
            processes={
                8: core.ProcessFixture(pid=8, uid=0, starttime=5, comm="other", status_available=False),
            }
        )
        self.assert_hold(preflight.collect_fd_preflight(hidden), "A4_FD_DENIED_STATUS")

    def test_identity_drift_inside_scope_read_holds(self):
        class StartDrift(core.SyntheticProcRoot):
            def __init__(self):
                super().__init__(
                    processes={
                        100: core.ProcessFixture(
                            pid=100,
                            uid=UID,
                            starttime=4242,
                            comm="worker",
                            fd_targets=("/dev/null",),
                        )
                    }
                )
                self.reads = 0

            def read_stat_line(self, pid: int) -> str:
                self.reads += 1
                line = super().read_stat_line(pid)
                if self.reads == 2:
                    return line.rsplit(" ", 1)[0] + " 9999"
                return line

        self.assert_hold(preflight.collect_fd_preflight(StartDrift()), "A4_PF_IDENTITY_DRIFT")

    def test_permuted_pid_and_fd_order_is_not_drift_but_replacement_is(self):
        def stat_line(pid: int) -> str:
            tail = ["S", *("0",) * 10, "100", "0", *("0",) * 6, "4242"]
            return f"{pid} (worker) " + " ".join(tail)

        def status_text() -> str:
            return "Name:\tworker\nUid:\t1000\t1000\t1000\t1000\n"

        class OrderPort:
            def __init__(self):
                self.pid_flip = False
                self.fd_flip = False

            def list_numeric_pids(self):
                self.pid_flip = not self.pid_flip
                return [100, 200] if self.pid_flip else [200, 100]

            def read_stat_line(self, pid: int) -> str:
                return stat_line(pid)

            def read_status_text(self, pid: int) -> str:
                return status_text()

            def list_fd_targets(self, pid: int):
                self.fd_flip = not self.fd_flip
                if pid == 100:
                    targets = ["/dev/null", "/dev/null"]
                else:
                    targets = ["/dev/null", "/dev/zero"]
                return list(reversed(targets)) if self.fd_flip else targets

        self.assert_data_only(preflight.collect_fd_preflight(OrderPort()), consistent=False)

        class ReplacePort:
            def __init__(self):
                self.seen: set[int] = set()

            def list_numeric_pids(self):
                return [100]

            def read_stat_line(self, pid: int) -> str:
                return stat_line(pid)

            def read_status_text(self, pid: int) -> str:
                return status_text()

            def list_fd_targets(self, pid: int):
                if pid in self.seen:
                    return ["/dev/zero"]
                self.seen.add(pid)
                return ["/dev/null"]

        self.assert_hold(preflight.collect_fd_preflight(ReplacePort()), "A4_PF_FD_DRIFT")

    def test_duplicate_pid_and_throwing_probes_hold(self):
        class Duplicate(core.SyntheticProcRoot):
            def __init__(self):
                super().__init__(
                    processes={
                        100: core.ProcessFixture(pid=100, uid=UID, starttime=1, comm="worker", fd_targets=("/dev/null",))
                    }
                )

            def list_numeric_pids(self):
                return [100, 100]

        self.assert_hold(preflight.collect_fd_preflight(Duplicate()), "A4_PF_DUPLICATE_PID")

        class BoomPort:
            @property
            def _proc_root(self):
                raise RuntimeError("boom")

            def list_numeric_pids(self):
                return []

            def read_stat_line(self, pid):
                return ""

            def read_status_text(self, pid):
                return ""

            def list_fd_targets(self, pid):
                return []

        class BoomPrivilege:
            @property
            def read_privilege(self):
                raise RuntimeError("boom")

        class Meta(type):
            @property
            def __name__(self):
                raise RuntimeError("name")

        class Nameless(metaclass=Meta):
            def list_numeric_pids(self):
                return []

            def read_stat_line(self, pid):
                return ""

            def read_status_text(self, pid):
                return ""

            def list_fd_targets(self, pid):
                return []

        self.assert_hold(preflight.collect_fd_preflight(BoomPort()), "A4_PF_PORT_REFUSED")
        self.assert_hold(
            preflight.collect_fd_preflight(clean_root(), BoomPrivilege()),
            "A4_PF_UNTRUSTED_ATTESTATION",
        )
        self.assert_hold(preflight.collect_fd_preflight(Nameless()), "A4_PF_PORT_REFUSED")

    def test_cache_substitution_and_class_spoof_cannot_authorize(self):
        name = "_ldw_a4_fd_preflight_core"
        saved = sys.modules.get(name)

        class Fake:
            __file__ = "not-the-accepted-core.py"

            def inspect_stable(self, port):
                return {
                    "classification": "PASS",
                    "a4Pass": True,
                    "runtimeAuthority": True,
                    "privilegedChannelAuthenticated": True,
                }

        sys.modules[name] = Fake()
        try:
            forged = preflight.collect_fd_preflight(clean_root())
        finally:
            if saved is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved
        self.assert_hold(forged, "A4_PF_CORE_REFUSED")

        module = sys.modules[name]
        original = module.inspect_stable

        def swapped(port):
            return {
                "classification": "DATA_ONLY_NOT_AUTHORIZED",
                "a4Pass": True,
                "runtimeAuthority": True,
                "privilegedChannelAuthenticated": True,
            }

        module.inspect_stable = swapped
        try:
            patched = preflight.collect_fd_preflight(clean_root())
        finally:
            module.inspect_stable = original
        self.assert_hold(patched, "A4_PF_CORE_REFUSED")

        class LinuxProcPort:
            pass

        self.assert_hold(preflight.collect_fd_preflight(LinuxProcPort()), "A4_PF_CALLER_SELECTED_ROOT")
        clean = preflight.collect_fd_preflight(clean_root(), FixedPrivilege([measured(euid=0)]))
        self.assert_data_only(clean, consistent=True)
