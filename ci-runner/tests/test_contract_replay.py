"""Metadata guard tests; no network, scanner execution, or real registrations."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("replay", Path(__file__).parents[1] / "guest" / "prove-betterleaks.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


class ContractGuards(unittest.TestCase):
    def fixture(self):
        return {
            "permissions": {"contents": "read"},
            "env": {"BETTERLEAKS_VERSION": "1.7.4", "BETTERLEAKS_SHA256": replay.SCANNER_HASH},
            "jobs": {"secret-scan": {"steps": [
                {"uses": replay.CHECKOUT, "with": {"fetch-depth": 0, "persist-credentials": False}},
                *[{"shell": "bash", "run": "true"} for _ in range(6)],
            ]}},
        }

    def parse(self, value):
        data = yaml.safe_dump(value).encode()
        with patch.object(replay, "SOURCE_HASH", hashlib.sha256(data).hexdigest()):
            return replay.load_contract(data)

    def rejects(self, value):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(value)

    def test_valid_metadata(self):
        _, scripts = self.parse(self.fixture())
        self.assertEqual(len(scripts), 6)

    def test_source_hash_is_required(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            replay.load_contract(b"tampered source")

    def test_no_write_permissions(self):
        value = self.fixture()
        value["permissions"]["contents"] = "write"
        self.rejects(value)

    def test_full_history_required(self):
        value = self.fixture()
        value["jobs"]["secret-scan"]["steps"][0]["with"]["fetch-depth"] = 1
        self.rejects(value)

    def test_credentials_cannot_persist(self):
        value = self.fixture()
        value["jobs"]["secret-scan"]["steps"][0]["with"]["persist-credentials"] = True
        self.rejects(value)

    def test_checkout_pin_required(self):
        value = self.fixture()
        value["jobs"]["secret-scan"]["steps"][0]["uses"] = "actions/checkout@main"
        self.rejects(value)

    def test_scanner_version_and_hash_required(self):
        for key in ("BETTERLEAKS_VERSION", "BETTERLEAKS_SHA256"):
            value = self.fixture()
            value["env"][key] = "changed"
            self.rejects(value)

    def test_all_scripts_required(self):
        value = self.fixture()
        value["jobs"]["secret-scan"]["steps"].pop()
        self.rejects(value)

    def test_bash_shell_required(self):
        value = self.fixture()
        value["jobs"]["secret-scan"]["steps"][1]["shell"] = "sh"
        self.rejects(value)

    def test_push_expression_fallbacks_are_empty(self):
        values = replay.expression_context({"EVENT_NAME": "push", "CALLER_SHA": "a" * 40})
        self.assertEqual(values["${{ github.event.pull_request.base.sha || '' }}"], "")
        self.assertEqual(values["${{ github.event.pull_request.head.sha || '' }}"], "")
        self.assertEqual(values["${{ inputs.verify_canary }}"], "true")

    def test_pull_request_expression_fallbacks_preserve_exact_shas(self):
        values = replay.expression_context({"EVENT_NAME": "pull_request", "CALLER_SHA": "a" * 40, "PR_BASE_SHA": "b" * 40, "PR_HEAD_SHA": "c" * 40})
        self.assertEqual(values["${{ github.event.pull_request.base.sha || '' }}"], "b" * 40)
        self.assertEqual(values["${{ github.event.pull_request.head.sha || '' }}"], "c" * 40)


class DispatcherContractGuards(unittest.TestCase):
    def setUp(self):
        self.ci_runner_dir = Path(__file__).parents[1]

    def test_provenance_manifest_and_file_hashes(self):
        prov_file = self.ci_runner_dir / "provenance.json"
        self.assertTrue(prov_file.is_file(), "provenance.json missing")
        import json
        with open(prov_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest.get("Schema"), 1)
        files = manifest.get("Files", {})
        self.assertIn("Invoke-Ci7Dispatcher.ps1", files)
        self.assertIn("CiRunner.psm1", files)
        self.assertIn("Invoke-IsolatedRunner.ps1", files)

        for rel_path, expected_hash in files.items():
            full_path = self.ci_runner_dir / rel_path
            self.assertTrue(full_path.is_file(), f"Provenance file missing: {rel_path}")
            data = full_path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            self.assertEqual(actual_hash.lower(), expected_hash.lower(), f"Hash mismatch for {rel_path}")

    def test_dispatcher_script_contract(self):
        dispatcher_file = self.ci_runner_dir / "Invoke-Ci7Dispatcher.ps1"
        self.assertTrue(dispatcher_file.is_file())
        content = dispatcher_file.read_text(encoding="utf-8")
        for mode in ("PollOnce", "Loop", "InstallTask", "UninstallTask", "Status", "Reap"):
            self.assertIn(mode, content)
        self.assertIn("Assert-Ci7ControllerProvenance", content)
        self.assertIn("LDW-CiRunner-Dispatcher", content)

    def test_module_exports_dispatcher_functions(self):
        psm1_file = self.ci_runner_dir / "CiRunner.psm1"
        self.assertTrue(psm1_file.is_file())
        content = psm1_file.read_text(encoding="utf-8")
        for func in ("Assert-Ci7ControllerProvenance", "Get-Ci7DispatcherAllowlist", "Get-Ci7QueuedJobs", "Select-Ci7EligibleJob", "Write-Ci7DispatcherEvidence"):
            self.assertIn(f"function {func}", content)


if __name__ == "__main__":
    unittest.main()
