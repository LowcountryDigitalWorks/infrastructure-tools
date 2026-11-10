#!/usr/bin/env python3
"""Offline deterministic tests for normal-user V2 receiver install plan."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
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

    def test_full_install_commits_inbound_before_receiver(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
            mod.PHYSICAL_INSTALL_ENABLED = True
            try:
                mod.install_fixture(
                    home=home,
                    uid=TEST_UID,
                    package_root=pkg,
                    operation_id="c" * 32,
                )
                installed = _git_blob((home / ".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py").read_bytes())
                self.assertEqual(installed, contract["payload_entries"][0]["git_blob"])
                inbound_path = home / ".local/lib/ldw-dragonfly-jit/inbound_transfer_v2.py"
                self.assertTrue(inbound_path.is_file())
                self.assertEqual(
                    _git_blob(inbound_path.read_bytes()),
                    contract["payload_entries"][1]["git_blob"],
                )
                txn = json.loads((home / mod.TRANSACTION_REL).read_text(encoding="utf-8"))
                self.assertEqual(txn["phase"], "CLEANUP")
            finally:
                mod.PHYSICAL_INSTALL_ENABLED = False

    def test_interrupt_after_inbound_rolls_back_and_blocks_retry(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            prior_blob = contract["required_installed_receiver_git_blob"]
            _seed_home(home, receiver_blob=prior_blob)
            mod.PHYSICAL_INSTALL_ENABLED = True
            try:
                with self.assertRaises(mod.InstallError):
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id="b" * 32,
                        fault_after=mod.INBOUND_PACKAGE,
                    )
                rolled = _git_blob((home / ".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py").read_bytes())
                self.assertEqual(rolled, prior_blob)
                inbound = home / ".local/lib/ldw-dragonfly-jit/inbound_transfer_v2.py"
                self.assertFalse(inbound.exists())
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
            home = Path(td) / "home"
            home.mkdir()
            prior_blob = contract["required_installed_receiver_git_blob"]
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
                self.assertEqual(
                    _git_blob((home / ".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py").read_bytes()),
                    prior_blob,
                )
                self.assertFalse((home / ".local/lib/ldw-dragonfly-jit/inbound_transfer_v2.py").exists())
            finally:
                mod.PHYSICAL_INSTALL_ENABLED = False

    def test_concurrent_kernel_lock_refused(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX flock semantics")
        contract = mod.load_contract()
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
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

    def test_replay_refused(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        op = "d" * 32
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
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
