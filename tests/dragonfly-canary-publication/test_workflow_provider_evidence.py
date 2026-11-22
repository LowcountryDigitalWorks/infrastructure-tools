"""Synthetic GitHub REST-shape boundary tests; no actual provider API calls."""
from __future__ import annotations

import base64
import copy
import hashlib
import unittest

from tools.dragonfly_workflow_provider_evidence import collect_workflow_source_evidence

COMMIT = "a" * 40
REF = "refs/heads/main"
PATH = ".github/workflows/dragonfly-jit-canary.yml"
REPO = "LowcountryDigitalWorks/infrastructure-tools"
PRE = f"repos/{REPO}"
WORKFLOW = b"name: synthetic\non: workflow_dispatch\npermissions: {}\n"
BLOB = hashlib.sha1(b"blob " + str(len(WORKFLOW)).encode() + b"\0" + WORKFLOW).hexdigest()


def fixture():
    return dict(schema=1, generation="synthetic-v1",
                profile="dragonfly-github-canary-v1", repository=REPO,
                workflow_path=PATH, commit_sha=COMMIT,
                approved_ref=REF, workflow_blob_sha=BLOB)


def provider_values():
    run = dict(id=555, run_attempt=2, repository=dict(full_name=REPO),
               head_repository=dict(full_name=REPO), head_sha=COMMIT,
               head_branch="main", path=PATH, event="workflow_dispatch",
               status="queued", conclusion=None)
    labels = ["self-hosted", "Linux", "X64", "dragonfly", "jit",
              "ldw-ephemeral", "synthetic-only", "dragonfly-run-555",
              "dragonfly-attempt-2"]
    job = dict(id=777, run_id=555, run_attempt=2, head_sha=COMMIT,
               name="dragonfly-canary", status="queued", conclusion=None,
               runner_id=None, runner_name="", labels=labels)
    return {
        f"{PRE}/git/ref/heads/main": dict(ref=REF, object=dict(type="commit", sha=COMMIT)),
        f"{PRE}/contents/{PATH}?ref={COMMIT}": dict(
            path=PATH, type="file", sha=BLOB, size=len(WORKFLOW),
            encoding="base64", content=base64.b64encode(WORKFLOW).decode()),
        f"{PRE}/actions/runs/555": run,
        f"{PRE}/actions/runs/555/attempts/2/jobs?per_page=100": dict(
            total_count=1, jobs=[job]),
    }


class Reader:
    def __init__(self, values, mutate=None):
        self.values = values
        self.calls = []
        self.mutate = mutate

    def __call__(self, path):
        self.calls.append(path)
        if self.mutate is not None:
            self.mutate(self, path)
        return copy.deepcopy(self.values[path])


def collect(reader=None, candidate=None, **kwargs):
    return collect_workflow_source_evidence(
        reader if reader is not None else Reader(provider_values()),
        candidate if candidate is not None else fixture(),
        555, 2, 777, **kwargs)


class ProviderReadOnlyTests(unittest.TestCase):
    def assert_hold(self, reader, candidate=None):
        value = collect(reader=reader, candidate=candidate)
        self.assertEqual(value["classification"], "HOLD_PROVIDER_EVIDENCE_UNVERIFIED")
        self.assertFalse(value["jit_authorized"])
        self.assertFalse(value["provider_write_authorized"])
        self.assertFalse(value["provider_reads_complete"])

    def test_consistent_evidence_remains_data_only(self):
        reader = Reader(provider_values())
        result = collect(reader)
        self.assertEqual(result["classification"], "SOURCE_TUPLE_CONSISTENT_DATA_ONLY")
        self.assertTrue(result["tuple_consistent"])
        self.assertTrue(result["provider_reads_complete"])
        self.assertFalse(result["jit_authorized"])
        self.assertFalse(result["provider_write_authorized"])
        self.assertEqual(reader.calls, list(provider_values()) * 2)
        self.assertEqual(len(reader.calls), 8)

    def test_no_caller_ref_override(self):
        data = fixture()
        data["approved_ref"] = "refs/heads/development"
        self.assert_hold(Reader(provider_values()), data)

    def test_no_caller_repo_override(self):
        data = fixture()
        data["repository"] = "user/evil"
        reader = Reader(provider_values())
        self.assert_hold(reader, data)
        self.assertEqual(reader.calls, [])

    def test_caller_sha_is_not_issuer(self):
        value = collect(caller_expected_sha=COMMIT)
        self.assertEqual(value["classification"], "SOURCE_TUPLE_CONSISTENT_DATA_ONLY")
        self.assertFalse(value["jit_authorized"])

    def test_ref_moves_on_fresh_read(self):
        def change(reader, path):
            if len(reader.calls) == 5:
                reader.values[path]["object"]["sha"] = "c" * 40
        result = collect(reader=Reader(provider_values(), change))
        # All eight GETs completed, but the independent tuple correlator
        # correctly rejects the moved branch target as untrusted.
        self.assertEqual(result["classification"], "HOLD_WORKFLOW_SOURCE_UNBOUND")
        self.assertTrue(result["provider_reads_complete"])
        self.assertFalse(result["tuple_consistent"])
        self.assertFalse(result["jit_authorized"])
        self.assertFalse(result["provider_write_authorized"])

    def test_blob_changes_after_preflight(self):
        def change(reader, path):
            if len(reader.calls) == 6:
                reader.values[path]["sha"] = "d" * 40
        self.assert_hold(Reader(provider_values(), change))

    def test_claimed_blob_not_equal_to_computed_bytes(self):
        values = provider_values()
        values[f"{PRE}/contents/{PATH}?ref={COMMIT}"]["sha"] = "f" * 40
        self.assert_hold(Reader(values))

    def test_bad_contents_encoding(self):
        values = provider_values()
        values[f"{PRE}/contents/{PATH}?ref={COMMIT}"]["content"] = "%INVALID%"
        self.assert_hold(Reader(values))

    def test_content_size_mismatch(self):
        values = provider_values()
        values[f"{PRE}/contents/{PATH}?ref={COMMIT}"]["size"] = 8
        self.assert_hold(Reader(values))

    def test_content_too_large(self):
        values = provider_values()
        values[f"{PRE}/contents/{PATH}?ref={COMMIT}"]["size"] = 16_385
        self.assert_hold(Reader(values))

    def test_ambiguous_job_records(self):
        values = provider_values()
        item = values[f"{PRE}/actions/runs/555/attempts/2/jobs?per_page=100"]
        item["jobs"].append(copy.deepcopy(item["jobs"][0]))
        item["total_count"] = 2
        self.assert_hold(Reader(values))

    def test_wrong_job_labels(self):
        values = provider_values()
        values[f"{PRE}/actions/runs/555/attempts/2/jobs?per_page=100"]["jobs"][0]["labels"].append("privileged")
        result = collect(reader=Reader(values))
        self.assertEqual(result["classification"], "HOLD_WORKFLOW_SOURCE_UNBOUND")
        self.assertFalse(result["jit_authorized"])

    def test_provider_exception_not_leaked(self):
        class Fails:
            def __call__(self, _):
                raise RuntimeError("SECRET_NEVER_ECHO")
        out = collect(reader=Fails())
        self.assertEqual(out["classification"], "HOLD_PROVIDER_EVIDENCE_UNVERIFIED")
        self.assertNotIn("SECRET", str(out))

    def test_missing_provider_field(self):
        values = provider_values()
        del values[f"{PRE}/actions/runs/555"]["head_branch"]
        self.assert_hold(Reader(values))

    def test_unexpected_run_status(self):
        values = provider_values()
        values[f"{PRE}/actions/runs/555"]["status"] = "completed"
        out = collect(reader=Reader(values))
        self.assertEqual(out["classification"], "HOLD_WORKFLOW_SOURCE_UNBOUND")

    def test_malformed_job_collection(self):
        values = provider_values()
        values[f"{PRE}/actions/runs/555/attempts/2/jobs?per_page=100"]["jobs"] = "not a list"
        self.assert_hold(Reader(values))

    def test_invalid_argument_and_no_reads(self):
        reader = Reader(provider_values())
        result = collect_workflow_source_evidence(reader, fixture(), 555, True, 777)
        self.assertFalse(result["jit_authorized"])
        self.assertEqual(reader.calls, [])

    def test_zero_network_or_provider_write_modules(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parents[2] / "tools" /
               "dragonfly_workflow_provider_evidence.py").read_text(encoding="utf-8")
        for forbidden in ("import requests", "import urllib",
                          "import subprocess", "generate-jitconfig",
                          "Popen(", "https://api.github.com", "gh api"):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    unittest.main()
