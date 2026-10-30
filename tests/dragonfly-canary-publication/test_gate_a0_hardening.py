#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'tools' / 'dragonfly_gate_a0.py'


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a0 = load('gate_a0_hardening', HELPER)


class GateA0HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / 'home'
        self.home.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.ssh = self.home / '.ssh'
        self.ssh.mkdir(mode=0o700)
        self.auth = self.ssh / 'authorized_keys'
        self.key_data = 'AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        self.key_sha = hashlib.sha256(f'ssh-ed25519 {self.key_data}'.encode('ascii')).hexdigest()
        self.good = f'restrict,command="{a0.FORCED_COMMAND}" ssh-ed25519 {self.key_data} synthetic'
        self.auth.write_text(self.good + '\n', encoding='utf-8')
        self.auth.chmod(0o600)
        self.orig_auth = a0.AUTHORIZED_KEYS_PATH
        self.orig_auth2 = a0.AUTHORIZED_KEYS2_PATH
        a0.AUTHORIZED_KEYS_PATH = self.auth
        a0.AUTHORIZED_KEYS2_PATH = self.ssh / 'authorized_keys2'

    def tearDown(self):
        a0.AUTHORIZED_KEYS_PATH = self.orig_auth
        a0.AUTHORIZED_KEYS2_PATH = self.orig_auth2
        self.temp.cleanup()

    def assertHold(self, expected: str, action):
        with self.assertRaisesRegex(a0.A0Error, '^' + expected + '$'):
            action()

    def read_key(self):
        return a0._transport_authorized_key(self.home, self.uid, self.key_sha)

    def test_exact_single_constrained_key_passes_with_comments_and_blanks(self):
        self.auth.write_text(f'\n# comment\n{self.good}\n\n', encoding='utf-8')
        result = self.read_key()
        self.assertTrue(result['authorizedKeysInvariant'])
        self.assertEqual(result['authorizedKeysActiveEntries'], 1)
        self.assertEqual(result['sshDirectoryMode'], '0700')

    def test_extra_bare_ed25519_refused(self):
        self.auth.write_text(self.good + f'\nssh-ed25519 {self.key_data} extra\n', encoding='utf-8')
        self.assertHold('A0_AUTHORIZED_KEYS_NOT_UNIQUE', self.read_key)

    def test_extra_from_option_refused(self):
        self.auth.write_text(self.good + f'\nfrom="*" ssh-ed25519 {self.key_data} extra\n', encoding='utf-8')
        self.assertHold('A0_AUTHORIZED_KEYS_NOT_UNIQUE', self.read_key)

    def test_extra_rsa_refused(self):
        self.auth.write_text(self.good + '\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsynth extra\n', encoding='utf-8')
        self.assertHold('A0_AUTHORIZED_KEYS_NOT_UNIQUE', self.read_key)

    def test_duplicate_good_refused(self):
        self.auth.write_text(self.good + '\n' + self.good + '\n', encoding='utf-8')
        self.assertHold('A0_AUTHORIZED_KEYS_NOT_UNIQUE', self.read_key)

    def test_malformed_active_line_refused(self):
        self.auth.write_text('this is not an authorized key\n', encoding='utf-8')
        self.assertHold('A0_TRANSPORT_KEY_IDENTITY_INVALID', self.read_key)

    def test_ssh_directory_mode_drift_refused(self):
        self.ssh.chmod(0o750)
        self.assertHold('A0_SSH_DIR_INVALID', self.read_key)

    def test_authorized_keys2_presence_refused(self):
        p = self.ssh / 'authorized_keys2'
        p.write_text('# legacy\n', encoding='utf-8')
        p.chmod(0o600)
        self.assertHold('A0_AUTHORIZED_KEYS_ALTERNATE_PRESENT', self.read_key)

    def test_tcp22_requires_nonloopback_listener(self):
        self.assertFalse(a0._has_nonloopback_tcp22('LISTEN 0 128 127.0.0.1:22 0.0.0.0:*'))
        self.assertFalse(a0._has_nonloopback_tcp22('LISTEN 0 128 [::1]:22 [::]:*'))
        self.assertTrue(a0._has_nonloopback_tcp22('LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'))
        self.assertTrue(a0._has_nonloopback_tcp22('LISTEN 0 128 [::]:22 [::]:*'))
        self.assertTrue(a0._has_nonloopback_tcp22('LISTEN 0 128 192.0.2.8:22 0.0.0.0:*'))

    def test_kvm_fd_scan_detects_renamed_vm_process(self):
        proc = Path(self.temp.name) / 'proc'
        fd = proc / '123' / 'fd'
        fd.mkdir(parents=True)
        (fd / '7').symlink_to('/dev/kvm')
        self.assertEqual(a0._kvm_fd_pids(proc), [123])

    def test_kvm_fd_scan_holds_on_fd_directory_permission_denial(self):
        proc = Path(self.temp.name) / 'proc'
        fd = proc / '123' / 'fd'
        fd.mkdir(parents=True)
        original_iterdir = Path.iterdir

        def denied(path: Path):
            if path == fd:
                raise PermissionError('synthetic denial')
            return original_iterdir(path)

        with mock.patch.object(Path, 'iterdir', new=denied):
            self.assertHold('A0_PROCESS_VISIBILITY_UNCERTAIN', lambda: a0._kvm_fd_pids(proc))

    def test_kvm_fd_scan_holds_on_readlink_permission_denial(self):
        proc = Path(self.temp.name) / 'proc'
        fd = proc / '123' / 'fd'
        fd.mkdir(parents=True)
        descriptor = fd / '7'
        descriptor.symlink_to('/dev/kvm')
        original_readlink = os.readlink

        def denied(path):
            if Path(path) == descriptor:
                raise PermissionError('synthetic denial')
            return original_readlink(path)

        with mock.patch.object(os, 'readlink', side_effect=denied):
            self.assertHold('A0_PROCESS_VISIBILITY_UNCERTAIN', lambda: a0._kvm_fd_pids(proc))

    def test_qemu_snapshot_refuses_kvm_fd_without_qemu_name(self):
        proc = Path(self.temp.name) / 'proc'
        fd = proc / '321' / 'fd'
        fd.mkdir(parents=True)
        (fd / '9').symlink_to('/dev/kvm')
        def runner(argv):
            self.assertEqual(argv, ('/usr/bin/ps', '-eo', 'pid=,comm=,args='))
            return 0, '321 myvm /opt/bin/myvm --guest synthetic'
        self.assertHold('A0_QEMU_PROCESS_PRESENT', lambda: a0._qemu_snapshot(runner, proc))


if __name__ == '__main__':
    unittest.main()
