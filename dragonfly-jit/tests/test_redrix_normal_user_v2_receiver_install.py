#!/usr/bin/env python3
"""Offline deterministic tests for normal-user V2 receiver install plan."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
INSTALL = ROOT / "redrix_normal_user_v2_receiver_install.py"
ADMISSION = ROOT / "redrix_normal_user_v2_receiver_install_admission.py"
CONTRACT_PATH = ROOT / "redrix_normal_user_v2_receiver_install.json"
SOURCE_COMMIT = "6d5fab22ec3dac1580ec49dea8f0bfab468b358b"
RECEIVER_SOURCE_PATH = "dragonfly-jit/ssh_forced_receiver.py"
INBOUND_SOURCE_PATH = "dragonfly-jit/inbound_transfer_v2.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


mod = _load("redrix_normal_user_v2_receiver_install", INSTALL)
adm = _load("redrix_normal_user_v2_receiver_install_admission", ADMISSION)
TEST_UID = os.getuid() if hasattr(os, "getuid") else 0


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rev_parse_blob_id(commit: str, repo_path: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"{commit}:{repo_path}"],
        cwd=REPO,
        text=True,
    ).strip()


def _canonical_source_bytes(commit: str, repo_path: str) -> bytes:
    blob_id = _rev_parse_blob_id(commit, repo_path)
    return subprocess.check_output(["git", "cat-file", "-p", blob_id], cwd=REPO)


def _git_cat_blob(sha: str) -> bytes:
    return subprocess.check_output(["git", "cat-file", "-p", sha], cwd=REPO)


class PackageBuilder:
    def __init__(self) -> None:
        self.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def write(
        self,
        work: Path,
        *,
        receiver: bytes | None = None,
        inbound: bytes | None = None,
        use_canonical: bool = True,
    ) -> Path:
        if use_canonical and receiver is None:
            receiver = _canonical_source_bytes(SOURCE_COMMIT, RECEIVER_SOURCE_PATH)
        if use_canonical and inbound is None:
            inbound = _canonical_source_bytes(SOURCE_COMMIT, INBOUND_SOURCE_PATH)
        if receiver is None:
            receiver = (ROOT / "ssh_forced_receiver.py").read_bytes()
        if inbound is None:
            inbound = (ROOT / "inbound_transfer_v2.py").read_bytes()

        rollback = _git_cat_blob(self.contract["required_installed_receiver_git_blob"])
        pkg = work / "package"
        for entry in self.contract["payload_entries"]:
            rel = entry["package_path"]
            data = receiver if entry["role"] == "receiver" else inbound
            target = pkg.joinpath(*Path(rel).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for entry in self.contract["rollback_entries"]:
            target = pkg.joinpath(*Path(entry["package_path"]).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(rollback)
        manifest = {
            "schemaVersion": 1,
            "artifact": self.contract["package_identity"],
            "sourceCommit": self.contract["source_commit"],
            "owner": {"user": "eddie", "uid": 1000},
            "authorizedKeysMutationAuthorized": False,
            "payloadEntries": [],
            "rollbackEntries": [],
        }
        for spec in self.contract["payload_entries"]:
            data = (pkg / spec["package_path"]).read_bytes()
            manifest["payloadEntries"].append(
                {
                    "packagePath": spec["package_path"],
                    "sourcePath": spec["source_path"],
                    "gitBlob": _git_blob(data),
                    "materialization": "raw",
                    "sha256": _sha256(data),
                    "size": len(data),
                    "mode": spec["mode"],
                }
            )
        for spec in self.contract["rollback_entries"]:
            data = (pkg / spec["package_path"]).read_bytes()
            manifest["rollbackEntries"].append(
                {
                    "packagePath": spec["package_path"],
                    "sourcePath": spec["source_path"],
                    "gitBlob": _git_blob(data),
                    "materialization": "raw",
                    "sha256": _sha256(data),
                    "size": len(data),
                    "mode": spec["mode"],
                }
            )
        (pkg / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return pkg


@contextmanager
def _trusted_install_home():
    if sys.platform == "win32":
        raise unittest.SkipTest("POSIX trusted /home anchor")
    try:
        mod._assert_kernel_lock_trust_root(Path.home(), TEST_UID)
    except mod.InstallError:
        raise unittest.SkipTest("trusted /home anchor unavailable")
    home = Path.home() / f".ldw-redrix-test-{uuid.uuid4().hex}"
    home.mkdir(mode=0o700)
    try:
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _seed_home(
    home: Path,
    *,
    receiver_blob: str | None = None,
    receiver_bytes: bytes | None = None,
) -> None:
    install_root = home / ".local/lib/ldw-dragonfly-jit"
    install_root.mkdir(parents=True, mode=0o700)
    if receiver_bytes is None:
        assert receiver_blob is not None
        receiver_bytes = _git_cat_blob(receiver_blob)
    target = install_root / "ssh_forced_receiver.py"
    target.write_bytes(receiver_bytes)
    os.chmod(target, 0o700)


class ContractTests(unittest.TestCase):
    def test_contract_matches_immutable_git_tree_blobs(self):
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        receiver_blob = _rev_parse_blob_id(SOURCE_COMMIT, RECEIVER_SOURCE_PATH)
        inbound_blob = _rev_parse_blob_id(SOURCE_COMMIT, INBOUND_SOURCE_PATH)
        self.assertEqual(contract["payload_entries"][0]["git_blob"], receiver_blob)
        self.assertEqual(contract["payload_entries"][1]["git_blob"], inbound_blob)

    def test_working_tree_may_differ_from_canonical_on_materialized_checkout(self):
        worktree = (ROOT / "ssh_forced_receiver.py").read_bytes()
        canonical = _canonical_source_bytes(SOURCE_COMMIT, RECEIVER_SOURCE_PATH)
        if worktree != canonical:
            self.assertNotEqual(_git_blob(worktree), _git_blob(canonical))
        else:
            self.assertEqual(_git_blob(worktree), _rev_parse_blob_id(SOURCE_COMMIT, RECEIVER_SOURCE_PATH))

    def test_admission_ready_while_physical_disabled(self):
        out = adm.evaluate_product_admission_readiness()
        self.assertEqual(out["eligibility"], "READY_FOR_HW_VM_INDEPENDENT_REVIEW")
        self.assertFalse(out["physical_install_source_enabled"])


class PlanTests(unittest.TestCase):
    def test_plan_reports_coherent_pins_for_canonical_package(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            plan = mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)
            self.assertTrue(plan["receiverInboundPinCoherent"])
            self.assertFalse(plan["eligibleForPhysicalInstall"])

    def test_working_tree_sourced_package_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            worktree = (ROOT / "ssh_forced_receiver.py").read_bytes()
            canonical = _canonical_source_bytes(SOURCE_COMMIT, RECEIVER_SOURCE_PATH)
            if worktree == canonical:
                adversarial = canonical + b"\n# adversarial-append"
            else:
                adversarial = worktree
            pkg = PackageBuilder().write(
                Path(td),
                receiver=adversarial,
                use_canonical=False,
            )
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            with self.assertRaises(mod.InstallError):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_preflight_refuses_preexisting_staging(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            staging = home / ".local/lib/ldw-dragonfly-jit/.v2-receiver-staging"
            staging.mkdir(parents=True, mode=0o700)
            with self.assertRaises(mod.InstallError):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_mismatched_manifest_blob_refused(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
            manifest["payloadEntries"][0]["gitBlob"] = "a" * 40
            (pkg / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            with self.assertRaises(mod.InstallError):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_wrong_installed_receiver_refused(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(
                home,
                receiver_bytes=_canonical_source_bytes(SOURCE_COMMIT, RECEIVER_SOURCE_PATH),
            )
            with self.assertRaises(mod.InstallError):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_inbound_already_present_refused(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            inbound = home / ".local/lib/ldw-dragonfly-jit/inbound_transfer_v2.py"
            inbound.write_bytes(b"# present\n")
            os.chmod(inbound, 0o600)
            with self.assertRaises(mod.InstallError):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)


class InstallFixtureTests(unittest.TestCase):
    def test_physical_install_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            with self.assertRaises(mod.InstallError):
                mod.install_fixture(
                    home=home,
                    uid=TEST_UID,
                    package_root=pkg,
                    operation_id="a" * 32,
                )

    def test_install_fixture_requires_trusted_home_anchor(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX trusted /home anchor")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
            mod.PHYSICAL_INSTALL_ENABLED = True
            try:
                with self.assertRaisesRegex(mod.InstallError, "BLOCKED_LOCK_TRUST_ROOT"):
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id="b" * 32,
                    )
            finally:
                mod.PHYSICAL_INSTALL_ENABLED = False

    def test_full_install_commits_inbound_before_receiver(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id="c" * 32,
                    )
                    installed = _git_blob((home / mod.RECEIVER_REL).read_bytes())
                    self.assertEqual(installed, contract["payload_entries"][0]["git_blob"])
                    inbound_path = home / mod.INBOUND_REL
                    self.assertTrue(inbound_path.is_file())
                    self.assertEqual(
                        _git_blob(inbound_path.read_bytes()),
                        contract["payload_entries"][1]["git_blob"],
                    )
                    self.assertTrue((home / mod.RECEIPT_REL).is_file())
                    self.assertFalse((home / mod.TRANSACTION_REL).exists())
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_interrupt_after_inbound_rolls_back_and_blocks_retry(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            prior_blob = contract["required_installed_receiver_git_blob"]
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=prior_blob)
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="b1" * 16,
                            fault_after=mod.INBOUND_PACKAGE,
                        )
                    rolled = _git_blob((home / mod.RECEIVER_REL).read_bytes())
                    self.assertEqual(rolled, prior_blob)
                    self.assertFalse((home / mod.INBOUND_REL).exists())
                    txn = json.loads((home / mod.TRANSACTION_REL).read_text(encoding="utf-8"))
                    self.assertEqual(txn["phase"], "FAILED")
                    with self.assertRaises(mod.InstallError):
                        mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_interrupt_after_receiver_restores_v1_and_journal(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            prior_blob = contract["required_installed_receiver_git_blob"]
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=prior_blob)
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="e" * 32,
                            fault_after=mod.RECEIVER_PACKAGE,
                        )
                    self.assertEqual(_git_blob((home / mod.RECEIVER_REL).read_bytes()), prior_blob)
                    self.assertFalse((home / mod.INBOUND_REL).exists())
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_concurrent_kernel_lock_refused(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                held = threading.Event()
                release = threading.Event()

                def holder() -> None:
                    lock = mod._KernelLock()
                    lock.acquire(
                        home=home,
                        path=home / mod.KERNEL_LOCK_REL,
                        uid=TEST_UID,
                        operation_id="f" * 32,
                    )
                    held.set()
                    release.wait(timeout=5)
                    lock.release()

                thread = threading.Thread(target=holder)
                thread.start()
                held.wait(timeout=5)
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="0" * 32,
                        )
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False
                    release.set()
                    thread.join(timeout=5)

    def test_crlf_materialized_payload_refused_deterministically(self):
        canonical = _canonical_source_bytes(SOURCE_COMMIT, RECEIVER_SOURCE_PATH)
        crlf = canonical.replace(b"\n", b"\r\n")
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td), receiver=crlf, use_canonical=False)
            manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
            manifest["payloadEntries"][0]["gitBlob"] = _git_blob(canonical)
            manifest["payloadEntries"][0]["sha256"] = _sha256(canonical)
            manifest["payloadEntries"][0]["size"] = len(canonical)
            (pkg / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            with self.assertRaisesRegex(mod.InstallError, "PACKAGE_CRLF_MATERIALIZATION_REFUSED"):
                mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_republished_preflight_under_lock_holds_after_peer_receipt_without_writes(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id="3" * 32,
                    )
                    with self.assertRaisesRegex(mod.InstallError, "RECEIPT_ALREADY_PRESENT"):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="2" * 32,
                        )
                    self.assertFalse((home / mod.TRANSACTION_REL).exists())
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_receipt_fault_preserves_v2_commit_and_refuses_replay(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaisesRegex(mod.InstallError, "INSTALL_POST_RECEIPT_HOLD"):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="4" * 32,
                            fault_after="receipt",
                        )
                    receiver = (home / mod.RECEIVER_REL).read_bytes()
                    inbound = (home / mod.INBOUND_REL).read_bytes()
                    self.assertEqual(_git_blob(receiver), contract["payload_entries"][0]["git_blob"])
                    self.assertEqual(_git_blob(inbound), contract["payload_entries"][1]["git_blob"])
                    self.assertTrue((home / mod.RECEIPT_REL).is_file())
                    receipt = json.loads((home / mod.RECEIPT_REL).read_text(encoding="utf-8"))
                    self.assertEqual(receipt["installedReceiverGitBlob"], contract["payload_entries"][0]["git_blob"])
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="5" * 32,
                        )
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_receipt_parent_fsync_fault_preserves_v2_without_v1_rollback(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            prior_blob = contract["required_installed_receiver_git_blob"]
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=prior_blob)
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaisesRegex(mod.InstallError, "INSTALL_POST_RECEIPT_HOLD"):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="4f" * 16,
                            fault_after="receipt_parent_fsync",
                        )
                    self.assertEqual(_git_blob((home / mod.RECEIVER_REL).read_bytes()), contract["payload_entries"][0]["git_blob"])
                    self.assertEqual(_git_blob((home / mod.INBOUND_REL).read_bytes()), contract["payload_entries"][1]["git_blob"])
                    self.assertNotEqual(_git_blob((home / mod.RECEIVER_REL).read_bytes()), prior_blob)
                    self.assertTrue((home / mod.RECEIPT_REL).is_file())
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_abrupt_incomplete_transaction_requires_recovery_hold(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id="6" * 32,
                            fault_after=mod.INBOUND_PACKAGE,
                        )
                    with self.assertRaisesRegex(mod.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                        mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False

    def test_kernel_lock_rejects_second_acquire_with_empty_record_swap(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        with _trusted_install_home() as home:
            state = home / mod.STATE_REL
            state.mkdir(parents=True, mode=0o700)
            lock_path = home / mod.KERNEL_LOCK_REL
            lock = mod._KernelLock()
            lock.acquire(home=home, path=lock_path, uid=TEST_UID, operation_id="7" * 32)
            try:
                swap = state / "invoke.kernel.lock.swap"
                swap.write_bytes(b"")
                os.chmod(swap, 0o600)
                os.replace(swap, lock_path)
                with self.assertRaisesRegex(mod.InstallError, "CONCURRENT_INVOKE_REFUSED"):
                    mod._KernelLock().acquire(
                        home=home,
                        path=lock_path,
                        uid=TEST_UID,
                        operation_id="8" * 32,
                    )
            finally:
                lock.release()

    def test_kernel_lock_path_identity_stable_through_acquisition(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        with _trusted_install_home() as home:
            lock_path = home / mod.KERNEL_LOCK_REL
            lock = mod._KernelLock()
            lock.acquire(home=home, path=lock_path, uid=TEST_UID, operation_id="9" * 32)
            try:
                anchor = mod._assert_kernel_lock_trust_root(home, TEST_UID)
                anchor_before = anchor.lstat()
                lock.reverify_lock_anchor(home=home, uid=TEST_UID)
                anchor_after = anchor.lstat()
                self.assertEqual(
                    (anchor_before.st_dev, anchor_before.st_ino),
                    (anchor_after.st_dev, anchor_after.st_ino),
                )
                self.assertEqual(lock._identity, (anchor_after.st_dev, anchor_after.st_ino))
            finally:
                lock.release()

    def test_kernel_lock_record_swap_does_not_break_anchor_reverify(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        with _trusted_install_home() as home:
            state = home / mod.STATE_REL
            state.mkdir(parents=True, mode=0o700)
            lock_path = home / mod.KERNEL_LOCK_REL
            lock = mod._KernelLock()
            lock.acquire(home=home, path=lock_path, uid=TEST_UID, operation_id="a" * 32)
            try:
                swap = state / "invoke.kernel.lock.swap"
                swap.write_bytes(b"")
                os.chmod(swap, 0o600)
                os.replace(swap, lock_path)
                lock.reverify_lock_anchor(home=home, uid=TEST_UID)
            finally:
                lock.release()

    def _subprocess_holder_script(self, home: str, wait_path: str, release_path: str) -> str:
        return f"""
import os, sys, time
sys.path.insert(0, {json.dumps(str(ROOT))})
import importlib.util
spec = importlib.util.spec_from_file_location(
    "redrix_normal_user_v2_receiver_install",
    {json.dumps(str(INSTALL))},
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
lock = mod._KernelLock()
lock.acquire(
    home=__import__("pathlib").Path({json.dumps(home)}),
    path=__import__("pathlib").Path({json.dumps(home)}) / mod.KERNEL_LOCK_REL,
    uid=os.getuid(),
    operation_id={json.dumps("f" * 32)},
)
open({json.dumps(wait_path)}, "w", encoding="utf-8").write("ready\\n")
while not __import__("pathlib").Path({json.dumps(release_path)}).exists():
    time.sleep(0.05)
lock.release()
"""

    def test_kernel_lock_subprocess_contention_refuses_install(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                signal_dir = Path(td) / "signals"
                signal_dir.mkdir()
                wait_path = signal_dir / "ready"
                release_path = signal_dir / "release"
                script = self._subprocess_holder_script(str(home), str(wait_path), str(release_path))
                proc = subprocess.Popen([sys.executable, "-c", script])
                try:
                    for _ in range(200):
                        if wait_path.exists():
                            break
                        time.sleep(0.05)
                    else:
                        self.fail("lock holder subprocess did not become ready")
                    mod.PHYSICAL_INSTALL_ENABLED = True
                    try:
                        with self.assertRaisesRegex(mod.InstallError, "CONCURRENT_INVOKE_REFUSED"):
                            mod.install_fixture(
                                home=home,
                                uid=TEST_UID,
                                package_root=pkg,
                                operation_id="0" * 32,
                            )
                    finally:
                        mod.PHYSICAL_INSTALL_ENABLED = False
                finally:
                    release_path.write_text("go\n", encoding="utf-8")
                    proc.wait(timeout=10)

    def test_subprocess_abrupt_exit_after_staged_journal_requires_recovery_hold(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX abrupt exit semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                child = f"""
import os, sys
sys.path.insert(0, {json.dumps(str(ROOT))}
import importlib.util
spec = importlib.util.spec_from_file_location(
    "redrix_normal_user_v2_receiver_install",
    {json.dumps(str(INSTALL))},
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.PHYSICAL_INSTALL_ENABLED = True
mod.install_fixture(
    home=__import__("pathlib").Path({json.dumps(str(home))}),
    uid=os.getuid(),
    package_root=__import__("pathlib").Path({json.dumps(str(pkg))}),
    operation_id={"6a" * 16!r},
    fault_after="abrupt_exit",
)
"""
                proc = subprocess.run([sys.executable, "-c", child], check=False)
                self.assertEqual(proc.returncode, 133)
                self.assertTrue((home / mod.TRANSACTION_REL).is_file())
                txn = json.loads((home / mod.TRANSACTION_REL).read_text(encoding="utf-8"))
                self.assertEqual(txn["phase"], "INBOUND_STAGED")
                with self.assertRaisesRegex(mod.InstallError, "INSTALL_RECOVERY_REQUIRED"):
                    mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)

    def test_replay_refused(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        op = "d" * 32
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            with _trusted_install_home() as home:
                _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
                mod.PHYSICAL_INSTALL_ENABLED = True
                try:
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id=op,
                    )
                    with self.assertRaises(mod.InstallError):
                        mod.install_fixture(
                            home=home,
                            uid=TEST_UID,
                            package_root=pkg,
                            operation_id=op,
                        )
                finally:
                    mod.PHYSICAL_INSTALL_ENABLED = False


if __name__ == "__main__":
    unittest.main()
