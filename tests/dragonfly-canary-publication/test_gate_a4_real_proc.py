#!/usr/bin/env python3
"""Tests for the fixed Linux /proc ProcPort adapter wired to A4 FD inspector core."""
from __future__ import annotations

import errno
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CORE_MODULE = "dragonfly_gate_a4_fd_inspector_core"
core = load_module(CORE_MODULE, ROOT / "tools" / "dragonfly_gate_a4_fd_inspector_core.py")
real_proc = load_module("dragonfly_gate_a4_real_proc", ROOT / "tools" / "dragonfly_gate_a4_real_proc.py")
UID = core.DEFAULT_UID


def stat_line(pid: int, comm: str, *, utime: int = 4242, starttime: int = 12345) -> str:
    tail = ["S", *("0",) * 10, str(utime), "0", *("0",) * 6, str(starttime)]
    return f"{pid} ({comm}) " + " ".join(tail)


def status_text(pid: int, comm: str, *, real: int, eff: int, saved: int, fs: int) -> str:
    return f"Name:\t{comm}\nPid:\t{pid}\nUid:\t{real}\t{eff}\t{saved}\t{fs}\n"


class ProcTree:
    """Test-only fake /proc layout; not a runtime authority surface."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="a4-proc-fixture-"))

    def close(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def add_pid(
        self,
        pid: int,
        *,
        comm: str = "worker",
        uid_eff: int = UID,
        uid_real: int | None = None,
        starttime: int = 12345,
        utime: int = 4242,
        fd_links: dict[str, str] | None = None,
    ) -> Path:
        proc_dir = self.root / str(pid)
        proc_dir.mkdir(parents=True, exist_ok=True)
        real = uid_real if uid_real is not None else uid_eff
        (proc_dir / "stat").write_text(stat_line(pid, comm, utime=utime, starttime=starttime), encoding="utf-8")
        (proc_dir / "status").write_text(
            status_text(pid, comm, real=real, eff=uid_eff, saved=uid_eff, fs=uid_eff),
            encoding="utf-8",
        )
        fd_dir = proc_dir / "fd"
        fd_dir.mkdir(exist_ok=True)
        links = {"0": "/dev/null"} if fd_links is None else fd_links
        for name, target in links.items():
            link = fd_dir / name
            if link.exists():
                link.unlink()
            os.symlink(target, link)
        return proc_dir

    def port(self) -> real_proc.LinuxProcPort:
        return real_proc.proc_port_for_tests(self.root)


def symlink_supported() -> bool:
    if os.name != "posix":
        return False
    tmp = Path(tempfile.mkdtemp())
    try:
        target = tmp / "t"
        link = tmp / "l"
        target.write_text("x", encoding="utf-8")
        os.symlink(target, link)
        return link.is_symlink()
    except OSError:
        return False
    finally:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(symlink_supported(), "proc fd symlinks require POSIX symlink support")
class A4RealProcPortTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = ProcTree()

    def tearDown(self) -> None:
        self.tree.close()

    def assert_hold(self, result: dict, reason: str) -> None:
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], reason)
        self.assertFalse(result["a4Pass"])

    def assert_data_only(self, result: dict) -> None:
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["privilegedChannelAuthenticated"])

    def test_clean_fixture_data_only_via_real_adapter(self) -> None:
        self.tree.add_pid(100, comm="worker", fd_links={"0": "/dev/null", "1": "pipe:[123]"})
        result = core.inspect_stable(self.tree.port(), expected_uid=UID)
        self.assert_data_only(result)

    def test_status_effective_uid_from_status_not_directory_owner_hint(self) -> None:
        self.tree.add_pid(212, comm="bash", uid_eff=UID, uid_real=0)
        text = self.tree.port().read_status_text(212)
        uids = core.parse_proc_status_uids(text)
        self.assertEqual(uids[1], UID)
        self.assertNotEqual(uids[0], uids[1])

    def test_stat_field14_utime_and_field22_starttime(self) -> None:
        self.tree.add_pid(120, comm="worker", utime=9999, starttime=5555)
        line = self.tree.port().read_stat_line(120)
        pid, comm, utime, start = core.parse_proc_stat(line)
        self.assertEqual((pid, comm, utime, start), (120, "worker", 9999, 5555))

    def test_kvm_fd_hold(self) -> None:
        self.tree.add_pid(130, comm="worker", fd_links={"0": "/dev/kvm"})
        self.assert_hold(core.inspect_stable(self.tree.port()), "A4_FD_KVM_FD_PRESENT")

    def test_qemu_any_uid_hold(self) -> None:
        self.tree.add_pid(1, comm="qemu-system-x86_64", uid_eff=0)
        self.tree.add_pid(100, comm="worker")
        self.assert_hold(core.inspect_stable(self.tree.port()), "A4_FD_QEMU_PROCESS_PRESENT")

    def test_denied_fd_dir_eacces_without_privilege(self) -> None:
        self.tree.add_pid(140, comm="worker", fd_links={"0": "/dev/null"})
        port = self.tree.port()
        real_listdir = os.listdir

        def deny_fd_listdir(path: str | os.PathLike[str]) -> list[str]:
            text = os.fspath(path)
            if text.endswith(f"{os.sep}fd") or text.endswith("/fd"):
                raise PermissionError(errno.EACCES, "synthetic fd dir denied")
            return real_listdir(path)

        with mock.patch("os.listdir", side_effect=deny_fd_listdir):
            with self.assertRaises(OSError) as ctx:
                port.list_fd_targets(140)
            self.assertIn(ctx.exception.errno, (errno.EACCES, errno.EPERM))
        with mock.patch("os.listdir", side_effect=deny_fd_listdir):
            result = core.inspect_stable(port)
        self.assert_hold(result, "A4_FD_DENIED_FD")

    def test_integration_denied_fd_readlink_oserror_hold(self) -> None:
        """Regression: adapter OSError must map through core to HOLD without traceback."""
        self.tree.add_pid(161, comm="worker", fd_links={"0": "/dev/null", "1": "pipe:[1]"})
        port = self.tree.port()
        real_readlink = os.readlink

        def deny_readlink(path: str | os.PathLike[str]) -> str:
            text = os.fspath(path)
            if f"{os.sep}fd{os.sep}" in text:
                raise PermissionError(errno.EACCES, "synthetic fd readlink denied")
            return real_readlink(path)

        with mock.patch("os.readlink", side_effect=deny_readlink):
            with self.assertRaises(OSError) as ctx:
                port.list_fd_targets(161)
            self.assertIn(ctx.exception.errno, (errno.EACCES, errno.EPERM))
        with mock.patch("os.readlink", side_effect=deny_readlink):
            result = core.inspect_stable(port)
        self.assert_hold(result, "A4_FD_DENIED_FD")
        self.assertFalse(result.get("runtimeAuthority"))

    def test_denied_stat_read_eacces_without_privilege(self) -> None:
        self.tree.add_pid(141, comm="worker")
        port = self.tree.port()
        with mock.patch.object(Path, "read_text", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaises(OSError) as ctx:
                port.read_stat_line(141)
            self.assertIn(ctx.exception.errno, (errno.EACCES, errno.EPERM))

    def test_vanished_process_enoent(self) -> None:
        self.tree.add_pid(142, comm="worker")
        proc = self.tree.root / "142"
        import shutil

        shutil.rmtree(proc)
        with self.assertRaises(OSError) as ctx:
            self.tree.port().read_stat_line(142)
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_vanished_fd_entry_enoent_after_enumeration(self) -> None:
        self.tree.add_pid(143, comm="worker", fd_links={"0": "/dev/null"})
        port = self.tree.port()
        real_readlink = os.readlink

        def vanish_readlink(path: str | os.PathLike[str]) -> str:
            text = os.fspath(path)
            if text.endswith(f"{os.sep}fd{os.sep}0"):
                raise FileNotFoundError(errno.ENOENT, "fd vanished between list and readlink")
            return real_readlink(path)

        with mock.patch("os.readlink", side_effect=vanish_readlink):
            with self.assertRaises(OSError) as ctx:
                port.list_fd_targets(143)
            self.assertEqual(ctx.exception.errno, errno.ENOENT)
        with mock.patch("os.readlink", side_effect=vanish_readlink):
            result = core.inspect_stable(port)
            self.assert_hold(result, "A4_FD_INCOMPLETE_ENUMERATION")

    def test_empty_fd_dir_is_not_vanished_race(self) -> None:
        self.tree.add_pid(144, comm="worker", fd_links={})
        targets = self.tree.port().list_fd_targets(144)
        self.assertEqual(targets, [])

    def test_malicious_pid_types_rejected(self) -> None:
        port = self.tree.port()
        for bad in (-1, 0, True, False):
            with self.assertRaises(OSError):
                port.read_stat_line(bad)  # type: ignore[arg-type]

    def test_symlink_ambiguous_relative(self) -> None:
        self.tree.add_pid(150, comm="worker", fd_links={"0": "../150/fd/1", "1": "/dev/null"})
        self.assert_hold(core.inspect_stable(self.tree.port()), "A4_FD_INCOMPLETE_ENUMERATION")

    def test_incomplete_fd_enumeration_non_numeric_entry(self) -> None:
        proc = self.tree.add_pid(151, comm="worker", fd_links={"0": "/dev/null"})
        (proc / "fd" / "weird").write_text("x", encoding="utf-8")
        with self.assertRaises(OSError) as ctx:
            self.tree.port().list_fd_targets(151)
        self.assertEqual(ctx.exception.errno, errno.ENOTDIR)
        self.assert_hold(core.inspect_stable(self.tree.port()), "A4_FD_INCOMPLETE_ENUMERATION")

    def test_mixed_numeric_and_invalid_fd_entry_fail_closed(self) -> None:
        proc = self.tree.add_pid(152, comm="worker", fd_links={"0": "/dev/null", "1": "pipe:[1]"})
        (proc / "fd" / "cache").write_text("x", encoding="utf-8")
        port = self.tree.port()
        with self.assertRaises(OSError) as ctx:
            port.list_fd_targets(152)
        self.assertEqual(ctx.exception.errno, errno.ENOTDIR)
        self.assert_hold(core.inspect_stable(port), "A4_FD_INCOMPLETE_ENUMERATION")

    def test_list_numeric_pids_sorted_unique(self) -> None:
        self.tree.add_pid(300, comm="a")
        self.tree.add_pid(100, comm="b")
        self.assertEqual(self.tree.port().list_numeric_pids(), [100, 300])

    def test_malformed_status_utf8_fail_closed(self) -> None:
        proc = self.tree.add_pid(153, comm="worker")
        (proc / "status").write_bytes(b"Name:\tbad\nPid:\t153\n\xff\xff\n")
        with self.assertRaises(OSError) as ctx:
            self.tree.port().read_status_text(153)
        self.assertEqual(ctx.exception.errno, errno.EINVAL)
        result = core.inspect_stable(self.tree.port())
        self.assert_hold(result, "A4_FD_INCOMPLETE_ENUMERATION")

    def test_open_linux_proc_port_rejects_non_linux(self) -> None:
        if os.name == "posix" and sys.platform.startswith("linux"):
            port = real_proc.open_linux_proc_port()
            self.assertTrue(isinstance(port, real_proc.LinuxProcPort))
        else:
            with self.assertRaises(OSError):
                real_proc.open_linux_proc_port()

    def test_proc_port_for_tests_rejects_live_proc(self) -> None:
        with self.assertRaises(ValueError):
            real_proc.proc_port_for_tests("/proc")


if __name__ == "__main__":
    unittest.main()
