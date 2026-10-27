from __future__ import annotations

import datetime as dt
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import handoff_contract as hc


NOW = dt.datetime(2026, 10, 27, 4, 0, 0, tzinfo=dt.timezone.utc)


def capsule():
    return {
        "marker": hc.MARKER,
        "schema": hc.SCHEMA,
        "dispatch_id": str(uuid.UUID("12345678-1234-4234-9234-123456789abc")),
        "target_host": hc.TARGET_HOST,
        "issued_at": "2026-10-27T03:59:00Z",
        "expires_at": "2026-10-27T04:03:00Z",
        "profile_id": hc.PROFILE_ID,
        "repository": hc.REPOSITORY,
        "workflow": hc.WORKFLOW,
        "run_id": 1001,
        "run_attempt": 2,
        "job_id": 2002,
        "head_sha": "a" * 40,
        "job_name": hc.JOB_NAME,
        "labels": list(hc.LABELS),
        "opaque_bootstrap": "SECRET-OPAQUE-BOOTSTRAP==",
    }


class HandoffDurabilityTests(unittest.TestCase):
    def test_successful_claim_fsyncs_each_directory_entry_boundary(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            real_fsync_directory = hc._fsync_directory
            with mock.patch.object(
                hc,
                "_fsync_directory",
                wraps=real_fsync_directory,
            ) as fsync_directory:
                path = hc.claim_dispatch(summary, state_root=state, now=NOW)

            self.assertTrue(path.is_file())
            calls = [Path(call.args[0]).absolute() for call in fsync_directory.call_args_list]
            self.assertEqual(
                calls,
                [
                    state.parent.absolute(),
                    state.absolute(),
                    (state / hc.CLAIM_SUBDIR).absolute(),
                ],
            )

    def test_final_directory_fsync_failure_leaves_exclusive_marker_fail_closed(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            claims = state / hc.CLAIM_SUBDIR
            claim = claims / f"{summary['dispatch_id']}.json"
            real_fsync_directory = hc._fsync_directory
            count = 0

            def fail_final(path: Path) -> None:
                nonlocal count
                count += 1
                if count == 3:
                    raise hc.HandoffError("CLAIM_DURABILITY_FAILED")
                real_fsync_directory(path)

            with mock.patch.object(hc, "_fsync_directory", side_effect=fail_final):
                with self.assertRaisesRegex(hc.HandoffError, "CLAIM_DURABILITY_FAILED"):
                    hc.claim_dispatch(summary, state_root=state, now=NOW)

            self.assertTrue(claim.is_file())
            with self.assertRaisesRegex(hc.HandoffError, "HANDOFF_REPLAY"):
                hc.claim_dispatch(summary, state_root=state, now=NOW)

    def test_parent_directory_fsync_failure_occurs_before_claim_creation(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            claims = state / hc.CLAIM_SUBDIR
            with mock.patch.object(
                hc,
                "_fsync_directory",
                side_effect=hc.HandoffError("CLAIM_DURABILITY_FAILED"),
            ):
                with self.assertRaisesRegex(hc.HandoffError, "CLAIM_DURABILITY_FAILED"):
                    hc.claim_dispatch(summary, state_root=state, now=NOW)

            self.assertFalse(claims.exists())


if __name__ == "__main__":
    unittest.main()
