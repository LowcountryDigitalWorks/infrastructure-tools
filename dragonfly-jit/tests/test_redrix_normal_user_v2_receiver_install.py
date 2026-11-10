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
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
INSTALL = ROOT / "redrix_normal_user_v2_receiver_install.py"
ADMISSION = ROOT / "redrix_normal_user_v2_receiver_install_admission.py"
CONTRACT_PATH = ROOT / "redrix_normal_user_v2_receiver_install.json"


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


def _with_patched_contract(receiver_bytes: bytes):
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    contract["payload_entries"][0]["git_blob"] = _git_blob(receiver_bytes)
    original = mod.load_contract

    def _patched():
        return contract

    mod.load_contract = _patched
    return original


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_cat_blob(sha: str) -> bytes:
    try:
        return subprocess.check_output(["git", "cat-file", "-p", sha], cwd=REPO)
    except (subprocess.CalledProcessError, FileNotFoundError):
        import base64

        raw = subprocess.check_output(
            [
                "gh",
                "api",
                f"repos/LowcountryDigitalWorks/infrastructure-tools/git/blobs/{sha}",
                "--jq",
                ".content",
            ],
            text=True,
        )
        return base64.b64decode(raw)


class PackageBuilder:
    def __init__(self) -> None:
        self.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def write(self, work: Path, *, receiver: bytes | None = None, inbound: bytes | None = None) -> Path:
        receiver = receiver if receiver is not None else (ROOT / "ssh_forced_receiver.py").read_bytes()
        inbound = inbound if inbound is not None else (ROOT / "inbound_transfer_v2.py").read_bytes()
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
                    "sourcePath": "dragonfly-jit/ssh_forced_receiver.py",
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
    def test_contract_matches_live_main_receiver_blob(self):
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        live = _git_blob((ROOT / "ssh_forced_receiver.py").read_bytes())
        self.assertEqual(contract["payload_entries"][0]["git_blob"], live)

    def test_admission_ready_while_physical_disabled(self):
        out = adm.evaluate_product_admission_readiness()
        self.assertEqual(out["eligibility"], "READY_FOR_HW_VM_INDEPENDENT_REVIEW")
        self.assertFalse(out["physical_install_source_enabled"])


class PlanTests(unittest.TestCase):
    def test_plan_reports_incoherent_pins_on_main_tree(self):
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td))
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=mod.load_contract()["required_installed_receiver_git_blob"])
            plan = mod.build_install_plan(home=home, uid=TEST_UID, package_root=pkg)
            self.assertFalse(plan["receiverInboundPinCoherent"])
            self.assertFalse(plan["eligibleForPhysicalInstall"])

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
            _seed_home(home, receiver_bytes=(ROOT / "ssh_forced_receiver.py").read_bytes())
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

    def test_coherent_install_and_rollback_on_interrupt(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        inbound_blob = contract["payload_entries"][1]["git_blob"]
        receiver = (ROOT / "ssh_forced_receiver.py").read_text(encoding="utf-8")
        receiver = receiver.replace(
            'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "4fb4b1fc5141e0b864a2b29c657932425771c567"',
            f'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "{inbound_blob}"',
        )
        receiver_bytes = receiver.encode("utf-8")
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td), receiver=receiver_bytes)
            home = Path(td) / "home"
            home.mkdir()
            prior_blob = contract["required_installed_receiver_git_blob"]
            _seed_home(home, receiver_blob=prior_blob)
            original_load = _with_patched_contract(receiver_bytes)
            mod.PHYSICAL_INSTALL_ENABLED = True
            try:
                with self.assertRaises(mod.InstallError):
                    mod.install_fixture(
                        home=home,
                        uid=TEST_UID,
                        package_root=pkg,
                        operation_id="b" * 32,
                        fault_after="payload/inbound_transfer_v2.py",
                    )
                rolled = _git_blob((home / ".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py").read_bytes())
                self.assertEqual(rolled, prior_blob)
                mod.install_fixture(
                    home=home,
                    uid=TEST_UID,
                    package_root=pkg,
                    operation_id="c" * 32,
                )
                installed = _git_blob((home / ".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py").read_bytes())
                self.assertEqual(installed, _git_blob(receiver_bytes))
                inbound_path = home / ".local/lib/ldw-dragonfly-jit/inbound_transfer_v2.py"
                self.assertTrue(inbound_path.is_file())
                self.assertEqual(
                    _git_blob(inbound_path.read_bytes()),
                    contract["payload_entries"][1]["git_blob"],
                )
            finally:
                mod.PHYSICAL_INSTALL_ENABLED = False
                mod.load_contract = original_load

    def test_replay_refused(self):
        if sys.platform == "win32":
            raise unittest.SkipTest("POSIX atomic install semantics")
        contract = mod.load_contract()
        inbound_blob = contract["payload_entries"][1]["git_blob"]
        receiver = (ROOT / "ssh_forced_receiver.py").read_text(encoding="utf-8")
        receiver = receiver.replace(
            'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "4fb4b1fc5141e0b864a2b29c657932425771c567"',
            f'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "{inbound_blob}"',
        )
        op = "d" * 32
        receiver_bytes = receiver.encode("utf-8")
        with tempfile.TemporaryDirectory() as td:
            pkg = PackageBuilder().write(Path(td), receiver=receiver_bytes)
            home = Path(td) / "home"
            home.mkdir()
            _seed_home(home, receiver_blob=contract["required_installed_receiver_git_blob"])
            original_load = _with_patched_contract(receiver_bytes)
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
                mod.load_contract = original_load


if __name__ == "__main__":
    unittest.main()
