"""Adversarial, offline proof for non-authorizing workflow-source correlation."""
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "dragonfly_workflow_source_admission.py"
SPEC = importlib.util.spec_from_file_location("redrix_source_admission", MODULE)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

COMMIT = "a" * 40
BLOB = "b" * 40
PATH = ".github/workflows/dragonfly-jit-canary.yml"
REPO = "LowcountryDigitalWorks/infrastructure-tools"


def evidence():
    candidate = dict(
        schema=1, generation="synthetic-v1", profile="dragonfly-github-canary-v1",
        repository=REPO, workflow_path=PATH,
        commit_sha=COMMIT, approved_ref="refs/heads/main",
        workflow_blob_sha=BLOB,
    )
    ref = dict(ref="refs/heads/main", object_type="commit", object_sha=COMMIT)
    blob = dict(path=PATH, type="file", commit_sha=COMMIT, git_blob_sha=BLOB)
    run = dict(
        id=123456, run_attempt=2, repository=REPO, head_repository=REPO,
        head_sha=COMMIT, head_branch="main", path=PATH, event="workflow_dispatch",
        status="queued", conclusion=None,
    )
    job = dict(
        id=789012, run_id=123456, run_attempt=2, head_sha=COMMIT,
        name="dragonfly-canary", status="queued", conclusion=None,
        runner_id=None, runner_name="",
        labels=[
            "self-hosted", "Linux", "X64", "dragonfly", "jit",
            "ldw-ephemeral", "synthetic-only",
            "dragonfly-run-123456", "dragonfly-attempt-2",
        ],
    )
    return dict(
        candidate=candidate,
        ref_before=ref, blob_before=blob, run_before=run, job_before=job,
        ref_fresh=copy.deepcopy(ref), blob_fresh=copy.deepcopy(blob),
        run_fresh=copy.deepcopy(run), job_fresh=copy.deepcopy(job),
    )


class WorkflowSourceHoldTests(unittest.TestCase):
    def test_consistent_candidate_is_still_non_authorizing(self):
        result = mod.inspect_workflow_source_tuple(**evidence())
        self.assertEqual(result["classification"], "SOURCE_TUPLE_CONSISTENT_DATA_ONLY")
        self.assertTrue(result["tuple_consistent"])
        self.assertFalse(result["jit_authorized"])
        self.assertFalse(result["provider_write_authorized"])

    def assert_hold(self, mutate, reason=None):
        facts = evidence()
        mutate(facts)
        result = mod.inspect_workflow_source_tuple(**facts)
        self.assertEqual(result["classification"], "HOLD_WORKFLOW_SOURCE_UNBOUND")
        self.assertFalse(result["tuple_consistent"])
        self.assertFalse(result["jit_authorized"])
        self.assertFalse(result["provider_write_authorized"])
        if reason:
            self.assertEqual(result["reason"], reason)

    def test_missing_generation(self):
        self.assert_hold(lambda e: e.update(candidate=None), "MISSING_PROTECTED_GENERATION")

    def test_schema_invalid(self):
        self.assert_hold(lambda e: e["candidate"].update(schema=2), "GENERATION_SCHEMA_INVALID")

    def test_profile_mismatch(self):
        self.assert_hold(lambda e: e["candidate"].update(profile="ci10-accepted-synthetic"), "PROFILE_MISMATCH")

    def test_candidate_commit_invalid(self):
        self.assert_hold(lambda e: e["candidate"].update(commit_sha="A" * 40), "PINNED_COMMIT_INVALID")

    def test_generation_invalid(self):
        self.assert_hold(lambda e: e["candidate"].update(generation="../../mutable"), "GENERATION_INVALID")

    def test_branch_ref_invalid(self):
        self.assert_hold(lambda e: e["candidate"].update(approved_ref="refs/tags/floating"), "REF_INVALID")

    def test_ref_moved_before(self):
        self.assert_hold(lambda e: e["ref_before"].update(object_sha="c" * 40), "REF_TARGET_MOVED")

    def test_ref_moved_after(self):
        self.assert_hold(lambda e: e["ref_fresh"].update(object_sha="c" * 40), "REF_TARGET_MOVED")

    def test_ref_annotated_tag_not_branch(self):
        self.assert_hold(lambda e: e["ref_before"].update(object_type="tag"), "REF_TARGET_TYPE_INVALID")

    def test_workflow_blob_changed(self):
        self.assert_hold(lambda e: e["blob_fresh"].update(git_blob_sha="c" * 40), "WORKFLOW_BLOB_MISMATCH")

    def test_workflow_same_path_wrong_commit(self):
        self.assert_hold(lambda e: e["blob_fresh"].update(commit_sha="c" * 40), "WORKFLOW_COMMIT_MISMATCH")

    def test_workflow_not_file(self):
        self.assert_hold(lambda e: e["blob_before"].update(type="symlink"), "WORKFLOW_TYPE_INVALID")

    def test_wrong_run_head(self):
        self.assert_hold(lambda e: e["run_before"].update(head_sha="c" * 40), "RUN_COMMIT_MISMATCH")

    def test_wrong_run_branch(self):
        self.assert_hold(lambda e: e["run_fresh"].update(head_branch="feature"), "RUN_REF_MISMATCH")

    def test_wrong_run_event(self):
        self.assert_hold(lambda e: e["run_before"].update(event="pull_request"), "RUN_WORKFLOW_MISMATCH")

    def test_run_changes_after_preflight(self):
        self.assert_hold(lambda e: e["run_fresh"].update(id=123457), "RUN_CHANGED_BETWEEN_READS")

    def test_run_no_longer_queued(self):
        self.assert_hold(lambda e: e["run_fresh"].update(status="in_progress"), "RUN_NOT_QUEUED")

    def test_job_changes_after_preflight(self):
        self.assert_hold(lambda e: e["job_fresh"].update(id=789013), "JOB_CHANGED_BETWEEN_READS")

    def test_job_unexpected_label(self):
        self.assert_hold(lambda e: e["job_before"]["labels"].append("privileged"), "JOB_LABELS_MISMATCH")

    def test_job_duplicate_label(self):
        self.assert_hold(lambda e: e["job_fresh"]["labels"].__setitem__(0, "jit"), "JOB_LABELS_MISMATCH")

    def test_job_assigned(self):
        self.assert_hold(lambda e: e["job_fresh"].update(runner_id=44), "JOB_ALREADY_ASSIGNED")

    def test_job_wrong_attempt(self):
        self.assert_hold(lambda e: e["job_before"].update(run_attempt=3), "JOB_IDENTITY_MISMATCH")

    def test_missing_provider_field(self):
        self.assert_hold(lambda e: e["run_fresh"].pop("head_branch"), "MISSING_EVIDENCE")

    def test_forged_caller_expected_sha_does_not_authorize(self):
        facts = evidence()
        facts["run_before"]["head_sha"] = "c" * 40
        facts["run_fresh"]["head_sha"] = "c" * 40
        result = mod.inspect_workflow_source_tuple(
            **facts, caller_expected_sha="c" * 40
        )
        self.assertEqual(result["classification"], "HOLD_WORKFLOW_SOURCE_UNBOUND")
        self.assertFalse(result["jit_authorized"])

    def test_matching_caller_expected_sha_does_not_upgrade(self):
        result = mod.inspect_workflow_source_tuple(
            **evidence(), caller_expected_sha=COMMIT
        )
        self.assertEqual(result["classification"], "SOURCE_TUPLE_CONSISTENT_DATA_ONLY")
        self.assertFalse(result["jit_authorized"])

    def test_no_runtime_provider_or_network_import(self):
        text = MODULE.read_text(encoding="utf-8")
        for forbidden in ("requests", "urllib", "subprocess", "Popen(", "generate-jitconfig", "gh api", "ssh ", "qemu"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
