import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("handoff_contract_canary", ROOT / "handoff_contract.py")
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class CanaryHandoffContractTests(unittest.TestCase):
    def capsule(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        run_id = 123456789
        run_attempt = 2
        return {
            "marker": handoff.MARKER,
            "schema": handoff.SCHEMA,
            "dispatch_id": str(uuid.uuid4()),
            "target_host": handoff.TARGET_HOST,
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + dt.timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "profile_id": handoff.CANARY_PROFILE_ID,
            "repository": handoff.REPOSITORY,
            "workflow": handoff.CANARY_WORKFLOW,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job_id": 987654321,
            "head_sha": "a" * 40,
            "job_name": handoff.CANARY_JOB_NAME,
            "labels": list(handoff.expected_labels(handoff.CANARY_PROFILE_ID, run_id, run_attempt)),
            "opaque_bootstrap": "QUJDREVGR0g=",
        }

    def test_canary_profile_accepts_exact_run_and_attempt_labels(self):
        payload = self.capsule()
        summary = handoff.validate_capsule(payload)
        self.assertEqual(summary["labels"][-2], f"dragonfly-run-{payload['run_id']}")
        self.assertEqual(summary["labels"][-1], f"dragonfly-attempt-{payload['run_attempt']}")
        self.assertNotIn("opaque_bootstrap", summary)

    def test_wrong_dynamic_label_fails_closed(self):
        payload = self.capsule()
        payload["labels"][-1] = "dragonfly-attempt-1"
        with self.assertRaisesRegex(handoff.HandoffError, "LABELS_INVALID"):
            handoff.validate_capsule(payload)

    def test_attempt_change_without_label_change_fails_closed(self):
        payload = self.capsule()
        payload["run_attempt"] += 1
        with self.assertRaisesRegex(handoff.HandoffError, "LABELS_INVALID"):
            handoff.validate_capsule(payload)

    def test_canary_identity_is_closed(self):
        cases = (
            ("workflow", ".github/workflows/other.yml", "WORKFLOW_INVALID"),
            ("job_name", "other", "JOB_NAME_INVALID"),
            ("repository", "LowcountryDigitalWorks/other", "REPOSITORY_INVALID"),
        )
        for field, value, error in cases:
            payload = self.capsule()
            payload[field] = value
            with self.assertRaisesRegex(handoff.HandoffError, error):
                handoff.validate_capsule(payload)

    def test_claim_never_persists_bootstrap(self):
        payload = self.capsule()
        summary = handoff.validate_capsule(payload)
        with tempfile.TemporaryDirectory() as temp:
            claim = handoff.claim_dispatch(summary, state_root=Path(temp) / "state")
            text = claim.read_text(encoding="utf-8")
            record = json.loads(text)
            self.assertEqual(record["profile_id"], handoff.CANARY_PROFILE_ID)
            self.assertEqual(record["run_attempt"], payload["run_attempt"])
            self.assertNotIn("opaque_bootstrap", record)
            self.assertNotIn(payload["opaque_bootstrap"], text)

    def test_legacy_synthetic_profile_remains_accepted(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        payload = {
            "marker": handoff.MARKER,
            "schema": handoff.SCHEMA,
            "dispatch_id": str(uuid.uuid4()),
            "target_host": handoff.TARGET_HOST,
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + dt.timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "profile_id": handoff.SYNTHETIC_PROFILE_ID,
            "repository": handoff.REPOSITORY,
            "workflow": handoff.SYNTHETIC_WORKFLOW,
            "run_id": 1,
            "run_attempt": 1,
            "job_id": 1,
            "head_sha": "b" * 40,
            "job_name": handoff.SYNTHETIC_JOB_NAME,
            "labels": list(handoff.SYNTHETIC_LABELS),
            "opaque_bootstrap": "synthetic-only",
        }
        self.assertEqual(handoff.validate_capsule(payload)["profile_id"], handoff.SYNTHETIC_PROFILE_ID)


if __name__ == "__main__":
    unittest.main()
