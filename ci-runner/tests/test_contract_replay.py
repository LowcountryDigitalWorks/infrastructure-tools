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


if __name__ == "__main__":
    unittest.main()
