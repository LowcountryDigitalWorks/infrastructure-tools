#!/usr/bin/env python3
"""Tests for the read-only A4 self privilege sample. No live proc access."""
from __future__ import annotations

import errno
import importlib.util
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "dragonfly_gate_a4_self_privilege.py"
CORE_PATH = ROOT / "tools" / "dragonfly_gate_a4_fd_inspector_core.py"
PREFLIGHT_PATH = ROOT / "tools" / "dragonfly_gate_a4_fd_preflight.py"
BOTH_CAPS = "0000000000080004"  # bit 2 and bit 19
PTRACE_ONLY = "0000000000080000"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


adapter = load("a4_self_privilege", MODULE_PATH)
UID = 1000


def status(euid: int = UID, cap_eff: str = "0000000000000000", cap_bnd: str = "0000000000000000", extra: str = "") -> str:
    return f"Name:\tpython\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\nCapEff:\t{cap_eff}\nCapBnd:\t{cap_bnd}\n{extra}"


def script(*samples: adapter.TestSample) -> adapter.LinuxSelfPrivilegePort:
    return adapter.privilege_port_for_tests(adapter.TestSelfScript(samples))


def sample_of(**kwargs) -> adapter.TestSample:
    fields = {
        "status": status(),
        "user_ns": "user:[10]",
        "pid_ns": "pid:[20]",
    }
    fields.update(kwargs)
    return adapter.TestSample(**fields)


class SelfPrivilegeTests(unittest.TestCase):
    def assert_closed(self, result: dict):
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])
        self.assertFalse(result["readScopeComplete"])
        self.assertNotIn("/proc", str(result))

    def test_source_is_fixed_self_and_has_no_launcher(self):
        text = MODULE_PATH.read_text(encoding="utf-8")
        for token in ("__main__", "subprocess", "sudo", "setcap", "systemd"):
            self.assertNotIn(token, text)
        found = set(re.findall(r"/proc/[A-Za-z0-9_./-]+", text))
        self.assertEqual(
            found,
            {"/proc/self/status", "/proc/self/ns/user", "/proc/self/ns/pid"},
        )
        self.assertIn("do not prove", text)

    def test_production_and_test_entrypoints_reject_paths(self):
        with self.assertRaises(TypeError):
            adapter.open_self_privilege_port("/proc")
        with self.assertRaises(TypeError):
            adapter.privilege_port_for_tests("/proc/self")
        with self.assertRaises(TypeError):
            adapter.privilege_port_for_tests(MODULE_PATH)

    def test_missing_caps_and_nonzero_euid_are_not_authority(self):
        result = adapter.sample_self_privilege(script(sample_of()))
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], "A4_PV_TARGET_NAMESPACE_UNCONFIRMED")
        self.assertTrue(result["kernelMeasured"])
        self.assertEqual(result["euid"], UID)
        self.assertFalse(result["capSysPtrace"])
        self.assertFalse(result["capDacReadSearch"])
        self.assertEqual(result["userNamespace"], "user-10")
        self.assertEqual(result["pidNamespace"], "pid-20")
        self.assert_closed(result)
        snapshot = script(sample_of()).read_privilege()
        self.assertTrue(snapshot.kernel_measured)
        self.assertFalse(snapshot.read_scope_complete)
        self.assertFalse(snapshot.claims_receiver_authenticated)
        self.assertNotEqual(snapshot.user_namespace, snapshot.target_user_namespace)

    def test_effective_caps_do_not_authorize_and_bounding_bits_are_not_effective(self):
        both = adapter.sample_self_privilege(
            script(sample_of(status=status(euid=UID, cap_eff=BOTH_CAPS, cap_bnd=BOTH_CAPS)))
        )
        self.assertTrue(both["capSysPtrace"])
        self.assertTrue(both["capDacReadSearch"])
        self.assertEqual(both["euid"], UID)
        self.assert_closed(both)
        bounding_only = script(sample_of(status=status(cap_eff="0000000000000000", cap_bnd=PTRACE_ONLY))).read_privilege()
        self.assertFalse(bounding_only.cap_sys_ptrace)
        self.assertFalse(bounding_only.cap_dac_read_search)

    def test_malformed_caps_uids_and_namespaces_hold(self):
        cases = (
            (sample_of(status=status(cap_eff="0x10", cap_bnd="ff")), "A4_PV_MALFORMED_CAP"),
            (sample_of(status=status(cap_eff="1" * 17, cap_bnd="ff")), "A4_PV_MALFORMED_CAP"),
            (sample_of(status=status(cap_eff="", cap_bnd="ff")), "A4_PV_MALFORMED_CAP"),
            (sample_of(status=status(cap_eff=PTRACE_ONLY, cap_bnd="0000000000000000")), "A4_PV_CAP_INCONSISTENT"),
            (sample_of(status="Name:\tpython\nUid:\t1\t2\nCapEff:\t0\nCapBnd:\t0\n"), "A4_PV_MALFORMED_UID"),
            (sample_of(status="Uid:\t1\t2\t3\t4\nUid:\t1\t9\t3\t4\nCapEff:\t0\nCapBnd:\t0\n"), "A4_PV_UID_MISMATCH"),
            (sample_of(status=status(euid=2**32)), "A4_PV_MALFORMED_UID"),
            (sample_of(user_ns="mnt:[10]"), "A4_PV_NAMESPACE_AMBIGUOUS"),
            (sample_of(user_ns="user:[01]"), "A4_PV_NAMESPACE_AMBIGUOUS"),
            (sample_of(pid_ns="pid:[20]extra"), "A4_PV_NAMESPACE_AMBIGUOUS"),
            (sample_of(status="CapEff:\t0\nCapEff:\t1\nCapBnd:\t1\nUid:\t1\t1\t1\t1\n"), "A4_PV_MALFORMED_CAP"),
        )
        for item, reason in cases:
            with self.subTest(reason=reason):
                result = adapter.sample_self_privilege(script(item))
                self.assertEqual(result["classification"], "HOLD")
                self.assertEqual(result["reasonCode"], reason)
                self.assertFalse(result["kernelMeasured"])
                self.assert_closed(result)

    def test_unreadable_and_drift_hold(self):
        denied = adapter.sample_self_privilege(script(sample_of(status_errno=errno.EACCES)))
        self.assertEqual(denied["reasonCode"], "A4_PV_UNREADABLE")
        self.assert_closed(denied)
        missing_ns = adapter.sample_self_privilege(script(sample_of(user_errno=errno.EPERM)))
        self.assertEqual(missing_ns["reasonCode"], "A4_PV_UNREADABLE")
        drifted = adapter.sample_self_privilege(
            script(sample_of(user_ns="user:[10]"), sample_of(user_ns="user:[11]"))
        )
        self.assertEqual(drifted["reasonCode"], "A4_PV_MEASUREMENT_DRIFT")
        self.assertFalse(drifted["kernelMeasured"])
        self.assert_closed(drifted)

    def test_preflight_does_not_promote_the_sample(self):
        preflight_name = "_ldw_a4_fd_preflight_core"
        if preflight_name not in sys.modules:
            load(preflight_name, CORE_PATH)
        bound_core = sys.modules[preflight_name]
        module = sys.modules[adapter._accepted_snapshot_type().__module__]
        root = bound_core.SyntheticProcRoot(
            processes={
                100: bound_core.ProcessFixture(pid=100, uid=1000, starttime=5, comm="worker", fd_targets=("/dev/null",))
            }
        )
        port = script(sample_of(status=status(cap_eff=BOTH_CAPS, cap_bnd=BOTH_CAPS)))
        result = module.collect_fd_preflight(root, port)
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], "A4_PF_USER_NAMESPACE_MISMATCH")
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])
        self.assertNotEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
