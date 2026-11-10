#!/usr/bin/env python3
"""Offline deterministic negative tests; no real /proc or privileged execution."""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "tools" / "dragonfly_gate_a4_live_evidence.py"
spec = importlib.util.spec_from_file_location("ldw_a4_live_fd_candidate", TARGET)
assert spec is not None and spec.loader is not None
evidence = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = evidence
spec.loader.exec_module(evidence)

UIDS = (1000, 1000, 1000, 1000)
NAMESPACES = ("user:[1]", "pid:[2]", "mnt:[3]")


class LiveA4CandidateTests(unittest.TestCase):
    def assert_hold(self, actual, code):
        self.assertEqual(actual["classification"], "HOLD")
        self.assertEqual(actual["reasonCode"], code)
        self.assertFalse(actual["a4Pass"])
        self.assertFalse(actual["runtimeAuthority"])
        self.assertFalse(actual["privilegedChannelAuthenticated"])
        self.assertFalse(actual["jitAdmissionAuthorized"])
        self.assertEqual(actual["pairedSnapshots"], 0)

    def test_nonroot_is_refused_without_reading_kernel(self):
        with mock.patch.object(evidence.os, "geteuid", return_value=1000), \
             mock.patch.object(evidence, "_capabilities") as caps:
            result = evidence.collect_live_evidence()
        self.assert_hold(result, "A4_LIVE_PRIVILEGE_REQUIRED")
        caps.assert_not_called()

    def test_kernel_capabilities_must_include_both_eff_and_bound(self):
        available = (1 << 19) | (1 << 2)
        good = f"Uid:\t0\t0\t0\t0\nCapEff:\t{available:016x}\nCapBnd:\t{available:016x}\n"
        for text, expected in (
            (good, True),
            (good.replace("CapBnd:", "CapInh:"), None),
            (good.replace(f"CapEff:\t{available:016x}", "CapEff:\t0000000000000000"), False),
        ):
            with self.subTest(text=text), mock.patch.object(evidence, "_bounded_text", return_value=text):
                if expected is None:
                    with self.assertRaises(evidence.EvidenceHold):
                        evidence._capabilities(evidence.PROC_ROOT)
                else:
                    self.assertIs(evidence._capabilities(evidence.PROC_ROOT), expected)

    def test_capability_absence_holds_before_any_process_scan(self):
        with mock.patch.object(evidence.os, "geteuid", return_value=0), \
             mock.patch.object(evidence, "_capabilities", return_value=False), \
             mock.patch.object(evidence, "_snapshot") as scan:
            result = evidence.collect_live_evidence()
        self.assert_hold(result, "A4_LIVE_CAPABILITY_UNVERIFIED")
        scan.assert_not_called()

    def test_target_namespace_mismatch_holds(self):
        values = ["user:[1]", "pid:[2]", "mnt:[3]", "user:[1]", "pid:[3]", "mnt:[3]"]
        with mock.patch.object(evidence.os, "readlink", side_effect=values):
            with self.assertRaises(evidence.EvidenceHold) as ctx:
                evidence._namespaces(evidence.PROC_ROOT)
        self.assertEqual(ctx.exception.code, "A4_LIVE_NAMESPACE_MISMATCH")

    def test_target_mount_namespace_mismatch_holds(self):
        values = ["user:[1]", "pid:[2]", "mnt:[3]", "user:[1]", "pid:[2]", "mnt:[4]"]
        with mock.patch.object(evidence.os, "readlink", side_effect=values):
            with self.assertRaises(evidence.EvidenceHold) as ctx:
                evidence._namespaces(evidence.PROC_ROOT)
        self.assertEqual(ctx.exception.code, "A4_LIVE_NAMESPACE_MISMATCH")

    def test_namespace_read_denial_fails_closed(self):
        with mock.patch.object(evidence.os, "readlink", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                evidence._namespaces(evidence.PROC_ROOT)

    def test_clean_synthetic_two_snapshots_cannot_authorize_jit(self):
        sample = ((1, 101), ((101, 4242, UIDS, ((3, "/dev/null"),)),))
        def measured(root, ns, pins, resources):
            if 101 not in pins:
                fd = os.open("/dev/null", os.O_RDONLY)
                pins[101] = fd
                resources.callback(os.close, fd)
            return sample
        with mock.patch.object(evidence.os, "geteuid", return_value=0), \
             mock.patch.object(evidence, "_capabilities", return_value=True), \
             mock.patch.object(evidence, "_namespaces", return_value=NAMESPACES), \
             mock.patch.object(evidence, "_snapshot", side_effect=measured) as scan, \
             mock.patch.object(evidence.time, "monotonic", side_effect=[1.0, 1.2]):
            result = evidence.collect_live_evidence()
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertEqual(result["reasonCode"], "EXTERNAL_TRUST_GATES_REQUIRED")
        self.assertTrue(result["kernelReadbackComplete"])
        self.assertEqual(result["sameUidProcessCount"], 1)
        self.assertEqual(result["pairedSnapshots"], 2)
        scan.assert_called()
        self.assertFalse(result["a4Pass"] or result["runtimeAuthority"])
        self.assertFalse(result["jitAdmissionAuthorized"])

    def test_changed_pid_fd_snapshot_is_hold(self):
        with mock.patch.object(evidence.os, "geteuid", return_value=0), \
             mock.patch.object(evidence, "_capabilities", return_value=True), \
             mock.patch.object(evidence, "_namespaces", return_value=NAMESPACES), \
             mock.patch.object(evidence, "_snapshot", side_effect=[
                 ((1, 101), ()), ((1, 102), ())
             ]):
            self.assert_hold(evidence.collect_live_evidence(), "A4_LIVE_SNAPSHOT_DRIFT")

    def test_stale_elapsed_capture_is_hold(self):
        with mock.patch.object(evidence.os, "geteuid", return_value=0), \
             mock.patch.object(evidence, "_capabilities", return_value=True), \
             mock.patch.object(evidence, "_namespaces", return_value=NAMESPACES), \
             mock.patch.object(evidence, "_snapshot", return_value=((1,), ())), \
             mock.patch.object(evidence.time, "monotonic", side_effect=[0.0, 7.0]):
            self.assert_hold(evidence.collect_live_evidence(), "A4_LIVE_CAPTURE_STALE")

    def test_kernel_access_denial_does_not_leak_paths_or_credentials(self):
        with mock.patch.object(evidence.os, "geteuid", return_value=0), \
             mock.patch.object(evidence, "_capabilities", return_value=True), \
             mock.patch.object(evidence, "_namespaces", return_value=NAMESPACES), \
             mock.patch.object(evidence, "_snapshot", side_effect=PermissionError(
                 13, "private secret /proc/101/fd/2"
             )):
            result = evidence.collect_live_evidence()
        self.assert_hold(result, "A4_LIVE_KERNEL_READBACK_INCOMPLETE")
        self.assertNotIn("private", str(result))
        self.assertNotIn("/proc/", str(result))

    def test_any_uid_qemu_refused(self):
        root = evidence.PROC_ROOT
        with mock.patch.object(evidence.os, "listdir", return_value=["1", "101"]), \
             mock.patch.object(evidence, "_identity", return_value=(1, 100, (0, 0, 0, 0), "qemu-system-x86")):
            with ExitStack() as stack:
                with self.assertRaises(evidence.EvidenceHold) as ctx:
                    evidence._snapshot(root, NAMESPACES, {}, stack)
        self.assertEqual(ctx.exception.code, "A4_LIVE_QEMU_PRESENT")

    def test_unreadable_fd_symlink_is_not_misread_as_zero(self):
        root = evidence.PROC_ROOT
        identity = (101, 4242, UIDS, "worker")
        original_listdir = lambda path: ["101"] if path == root else ["3"]
        def kernel_link(path):
            p = str(path)
            if p.endswith("/fd/3"):
                raise PermissionError(13, "readlink denied")
            if p.endswith("/ns/user"):
                return NAMESPACES[0]
            if p.endswith("/ns/pid"):
                return NAMESPACES[1]
            if p.endswith("/ns/mnt"):
                return NAMESPACES[2]
            return "/usr/bin/python3"
        with mock.patch.object(evidence.os, "listdir", side_effect=original_listdir), \
             mock.patch.object(evidence, "_identity", return_value=identity), \
             mock.patch.object(evidence.os, "pidfd_open", side_effect=lambda pid, flags: os.open("/dev/null", os.O_RDONLY)), \
             mock.patch.object(evidence, "_alive_pidfd", return_value=True), \
             mock.patch.object(evidence.os, "readlink", side_effect=kernel_link):
            with ExitStack() as resources:
                with self.assertRaises(PermissionError):
                    evidence._snapshot(root, NAMESPACES, {}, resources)

    def test_process_mount_namespace_mismatch_holds(self):
        root = evidence.PROC_ROOT
        identity = (101, 4242, UIDS, "worker")
        original_listdir = lambda path: ["101"] if path == root else ["3"]
        def kernel_link(path):
            p = str(path)
            if p.endswith("/ns/user"):
                return NAMESPACES[0]
            if p.endswith("/ns/pid"):
                return NAMESPACES[1]
            if p.endswith("/ns/mnt"):
                return "mnt:[999]"
            return "/usr/bin/python3"
        with mock.patch.object(evidence.os, "listdir", side_effect=original_listdir), \
             mock.patch.object(evidence, "_identity", return_value=identity), \
             mock.patch.object(evidence.os, "pidfd_open", side_effect=lambda pid, flags: os.open("/dev/null", os.O_RDONLY)), \
             mock.patch.object(evidence, "_alive_pidfd", return_value=True), \
             mock.patch.object(evidence.os, "readlink", side_effect=kernel_link):
            with ExitStack() as resources:
                with self.assertRaises(evidence.EvidenceHold) as ctx:
                    evidence._snapshot(root, NAMESPACES, {}, resources)
        self.assertEqual(ctx.exception.code, "A4_LIVE_NAMESPACE_MISMATCH")

    def test_source_has_no_privilege_or_transport_entrypoint(self):
        source = TARGET.read_text(encoding="utf-8")
        for forbidden in ("if __name__ ==", "subprocess.run(", "os.system(", "sudo -n",
                          "os.setuid(", "setcap ", "socket.socket(", "pidfd_getfd("):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('"a4Pass": True', source)
        self.assertNotIn('"runtimeAuthority": True', source)


if __name__ == "__main__":
    unittest.main()
