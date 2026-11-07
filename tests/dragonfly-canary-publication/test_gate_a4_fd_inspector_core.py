#!/usr/bin/env python3
"""Deterministic A4 FD inspector core tests mapped to REDRIX_A4 15-case matrix."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CORE_PATH = ROOT / "tools" / "dragonfly_gate_a4_fd_inspector_core.py"


def load():
    spec = importlib.util.spec_from_file_location("a4_fd_inspector_core", CORE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


core = load()
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


class A4FdInspectorCoreTests(unittest.TestCase):
    def assert_hold(self, result: dict, reason: str):
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], reason)
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])

    def assert_data_only(self, result: dict):
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])

    def test_a4_fd_01_no_runtime_authority(self):
        """A4-FD-01: cannot mint trusted privileged evidence."""
        result = core.inspect_stable(clean_root())
        self.assert_data_only(result)
        self.assertEqual(result["reasonCode"], "EXTERNAL_TRUST_GATES_REQUIRED")

    def test_a4_fd_06_denied_fd(self):
        root = core.SyntheticProcRoot(
            processes={
                200: core.ProcessFixture(
                    pid=200, uid=UID, starttime=50, comm="bash", fd_available=False
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_DENIED_FD")

    def test_a4_fd_07_pid_reuse_starttime(self):
        root = core.SyntheticProcRoot(
            processes={
                201: core.ProcessFixture(
                    pid=201,
                    uid=UID,
                    starttime=10,
                    starttime_after_first=11,
                    comm="bash",
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_PID_REUSE")

    def test_a4_fd_07_process_exit(self):
        root = core.SyntheticProcRoot(
            processes={
                202: core.ProcessFixture(
                    pid=202,
                    uid=UID,
                    starttime=15,
                    comm="bash",
                    vanish_after_first=True,
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_PROCESS_VANISHED")

    def test_a4_fd_08_kvm_fd(self):
        root = core.SyntheticProcRoot(
            processes={
                203: core.ProcessFixture(
                    pid=203,
                    uid=UID,
                    starttime=20,
                    comm="bash",
                    fd_targets=("/dev/kvm",),
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_KVM_FD_PRESENT")

    def test_a4_fd_08_qemu_process(self):
        root = core.SyntheticProcRoot(
            processes={
                204: core.ProcessFixture(
                    pid=204,
                    uid=UID,
                    starttime=25,
                    comm="qemu-system-x86_64",
                    exec_tokens=("/usr/bin/qemu-system-x86_64",),
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_QEMU_PROCESS_PRESENT")

    def test_a4_fd_09_unbound_a4_readback(self):
        self.assert_hold(
            core.inspect_stable(clean_root(), bind_a4_readback=False),
            "A4_FD_SNAPSHOT_UNSTABLE",
        )

    def test_a4_fd_06_stat_unavailable(self):
        root = core.SyntheticProcRoot(
            processes={
                205: core.ProcessFixture(
                    pid=205, uid=UID, starttime=30, comm="bash", stat_available=False
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_STAT_UNAVAILABLE")

    def test_a4_fd_06_incomplete_enumeration(self):
        root = core.SyntheticProcRoot(
            processes={
                206: core.ProcessFixture(pid=206, uid=UID, starttime=31, comm="a"),
                207: core.ProcessFixture(pid=207, uid=UID, starttime=32, comm="b"),
            },
            enumeration_incomplete=True,
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_INCOMPLETE_ENUMERATION")

    def test_a4_fd_06_symlink_ambiguous(self):
        root = core.SyntheticProcRoot(
            processes={
                208: core.ProcessFixture(
                    pid=208,
                    uid=UID,
                    starttime=40,
                    comm="bash",
                    ambiguous_symlink=True,
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_SYMLINK_AMBIGUOUS")

    def test_a4_fd_malformed_stat(self):
        class BadPort(core.SyntheticProcRoot):
            def read_stat_line(self, pid: int) -> str:
                return "not-a-stat-line"

        self.assert_hold(
            core.inspect_stable(BadPort(processes=clean_root().processes)),
            "A4_FD_MALFORMED_STAT",
        )

    def test_a4_fd_uid_mismatch_stat_pid(self):
        class PidDrift(core.SyntheticProcRoot):
            def read_stat_line(self, pid: int) -> str:
                line = super().read_stat_line(pid)
                return line.replace(f"{pid} ", "99999 ", 1)

        self.assert_hold(core.inspect_stable(PidDrift(processes=clean_root().processes)), "A4_FD_UID_MISMATCH")

    def test_a4_fd_12_clean_zero_kvm_qemu(self):
        result = core.inspect_stable(clean_root())
        self.assert_data_only(result)
        self.assertEqual(result["kvmFdProcessCount"], 0)
        self.assertEqual(result["qemuLikeProcessCount"], 0)
        self.assertEqual(result["stabilityPasses"], 2)

    def test_a4_fd_comm_parsing_with_spaces(self):
        pid, comm, uid, start = core.parse_proc_stat(
            "42 (my worker proc) S 0 0 0 0 0 0 0 0 0 0 1000 1000 0 0 0 0 0 0 12345"
        )
        self.assertEqual((pid, comm, uid, start), (42, "my worker proc", 1000, 12345))

    def test_a4_fd_output_sanitized_no_private_paths(self):
        root = core.SyntheticProcRoot(
            processes={
                300: core.ProcessFixture(
                    pid=300,
                    uid=UID,
                    starttime=88,
                    comm="bash",
                    exec_tokens=("/home/eddie/secret/path/qemu-system-x86_64",),
                    fd_targets=("/tmp/socket",),
                )
            }
        )
        self.assert_hold(core.inspect_stable(root), "A4_FD_QEMU_PROCESS_PRESENT")
        blob = json.dumps(core.inspect_stable(clean_root()))
        self.assertNotIn("/home/", blob)
        self.assertNotIn("cmdline", blob)

    def test_a4_fd_15_inspector_unavailable_transport(self):
        class BrokenPort:
            def list_numeric_pids(self) -> list[int]:
                raise OSError("synthetic transport busy")

            def read_stat_line(self, pid: int) -> str:
                raise NotImplementedError

            def list_fd_targets(self, pid: int) -> list[str]:
                raise NotImplementedError

        self.assert_hold(core.inspect_stable(BrokenPort()), "A4_FD_INCOMPLETE_ENUMERATION")


if __name__ == "__main__":
    unittest.main()
