from __future__ import annotations

import datetime as dt
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
import uuid

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import handoff_contract as hc


NOW = dt.datetime(2026, 10, 27, 4, 0, 0, tzinfo=dt.timezone.utc)


def capsule(**overrides):
    value = {
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
    value.update(overrides)
    return value


class HandoffContractTests(unittest.TestCase):
    def test_valid_capsule_returns_sanitized_summary_without_bootstrap(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        encoded = json.dumps(summary, sort_keys=True)
        self.assertTrue(summary["bootstrap_present"])
        self.assertNotIn("SECRET-OPAQUE-BOOTSTRAP", encoded)
        self.assertNotIn("opaque_bootstrap", encoded)
        self.assertEqual(hc.TARGET_HOST, summary["target_host"])

    def test_schema_is_closed_and_identity_is_fixed(self):
        value = capsule(extra="no")
        with self.assertRaisesRegex(hc.HandoffError, "CAPSULE_FIELDS_INVALID"):
            hc.validate_capsule(value, now=NOW)
        for field, replacement, reason in [
            ("marker", "other", "CAPSULE_IDENTITY_INVALID"),
            ("schema", 2, "CAPSULE_IDENTITY_INVALID"),
            ("schema", True, "CAPSULE_IDENTITY_INVALID"),
            ("target_host", "other", "TARGET_HOST_INVALID"),
            ("profile_id", "other", "PROFILE_INVALID"),
            ("repository", "other/repo", "REPOSITORY_INVALID"),
            ("workflow", "other.yml", "WORKFLOW_INVALID"),
            ("job_name", "other", "JOB_NAME_INVALID"),
            ("labels", ["self-hosted"], "LABELS_INVALID"),
        ]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(hc.HandoffError, reason):
                    hc.validate_capsule(capsule(**{field: replacement}), now=NOW)

    def test_job_identity_types_are_strict(self):
        cases = [
            ("dispatch_id", "not-a-uuid", "DISPATCH_ID_INVALID"),
            ("dispatch_id", str(uuid.uuid1()), "DISPATCH_ID_INVALID"),
            ("head_sha", "A" * 40, "HEAD_SHA_INVALID"),
            ("run_id", 0, "RUN_ID_INVALID"),
            ("run_id", True, "RUN_ID_INVALID"),
            ("run_attempt", -1, "RUN_ATTEMPT_INVALID"),
            ("job_id", "2", "JOB_ID_INVALID"),
        ]
        for field, replacement, reason in cases:
            with self.subTest(field=field):
                with self.assertRaisesRegex(hc.HandoffError, reason):
                    hc.validate_capsule(capsule(**{field: replacement}), now=NOW)

    def test_time_window_is_short_and_fail_closed(self):
        with self.assertRaisesRegex(hc.HandoffError, "TTL_INVALID"):
            hc.validate_capsule(capsule(expires_at="2026-10-27T04:10:00Z"), now=NOW)
        with self.assertRaisesRegex(hc.HandoffError, "EXPIRY_INVALID"):
            hc.validate_capsule(capsule(expires_at="2026-10-27T03:58:00Z"), now=NOW)
        with self.assertRaisesRegex(hc.HandoffError, "EXPIRED"):
            hc.validate_capsule(capsule(expires_at="2026-10-27T04:00:00Z"), now=NOW)
        with self.assertRaisesRegex(hc.HandoffError, "NOT_YET_VALID"):
            hc.validate_capsule(
                capsule(issued_at="2026-10-27T04:01:00Z", expires_at="2026-10-27T04:03:00Z"),
                now=NOW,
            )

    def test_bootstrap_is_bounded_printable_and_never_in_claim(self):
        with self.assertRaisesRegex(hc.HandoffError, "OPAQUE_BOOTSTRAP_INVALID"):
            hc.validate_capsule(capsule(opaque_bootstrap="line1\nline2"), now=NOW)
        with self.assertRaisesRegex(hc.HandoffError, "OPAQUE_BOOTSTRAP_INVALID"):
            hc.validate_capsule(capsule(opaque_bootstrap="x" * (hc.MAX_BOOTSTRAP_CHARS + 1)), now=NOW)

        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            path = hc.claim_dispatch(summary, state_root=Path(temp) / "state", now=NOW)
            content = path.read_text()
            self.assertNotIn("SECRET-OPAQUE-BOOTSTRAP", content)
            self.assertNotIn("opaque_bootstrap", content)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_claim_is_atomic_one_time_and_duplicate_refused(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            first = hc.claim_dispatch(summary, state_root=state, now=NOW)
            self.assertTrue(first.is_file())
            with self.assertRaisesRegex(hc.HandoffError, "HANDOFF_REPLAY"):
                hc.claim_dispatch(summary, state_root=state, now=NOW)
            self.assertEqual(0o700, stat.S_IMODE((state / hc.CLAIM_SUBDIR).stat().st_mode))

    def test_claim_revalidates_dispatch_id_before_path_use(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        forged = dict(summary)
        forged["dispatch_id"] = "../escape"
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            with self.assertRaisesRegex(hc.HandoffError, "DISPATCH_ID_INVALID"):
                hc.claim_dispatch(forged, state_root=state, now=NOW)
            self.assertFalse((Path(temp) / "escape.json").exists())

    def test_claim_path_symlink_is_refused(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            link = root / "state"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(hc.HandoffError, "CLAIM_PATH_SYMLINK"):
                hc.claim_dispatch(summary, state_root=link, now=NOW)

    def test_existing_claim_symlink_is_refused_without_following(self):
        summary = hc.validate_capsule(capsule(), now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / "state"
            claims = state / hc.CLAIM_SUBDIR
            claims.mkdir(parents=True)
            victim = Path(temp) / "victim"
            victim.write_text("keep")
            claim = claims / f"{summary['dispatch_id']}.json"
            claim.symlink_to(victim)
            with self.assertRaisesRegex(hc.HandoffError, "CLAIM_PATH_SYMLINK"):
                hc.claim_dispatch(summary, state_root=state, now=NOW)
            self.assertEqual("keep", victim.read_text())

    def test_read_capsule_bounds_and_utf8_json(self):
        raw = json.dumps(capsule()).encode()
        self.assertEqual(capsule(), hc.read_capsule(io.BytesIO(raw)))
        with self.assertRaisesRegex(hc.HandoffError, "CAPSULE_TOO_LARGE"):
            hc.read_capsule(io.BytesIO(b"x" * (hc.MAX_CAPSULE_BYTES + 1)))
        with self.assertRaisesRegex(hc.HandoffError, "CAPSULE_UTF8_INVALID"):
            hc.read_capsule(io.BytesIO(b"\xff"))
        with self.assertRaisesRegex(hc.HandoffError, "CAPSULE_JSON_INVALID"):
            hc.read_capsule(io.BytesIO(b"{"))

    def test_module_has_no_network_or_process_launch_imports(self):
        source = (ROOT / "handoff_contract.py").read_text()
        for forbidden in ("import socket", "import urllib", "import requests", "subprocess", "http.server"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
