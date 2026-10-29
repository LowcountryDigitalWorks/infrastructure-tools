import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ssh_forced_receiver_canary", ROOT / "ssh_forced_receiver.py")
receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)


class FakeHandoff:
    class HandoffError(RuntimeError):
        pass

    def read_capsule(self, stream):
        return json.loads(stream.read().decode("utf-8"))

    def validate_capsule(self, payload):
        return {
            "marker": "CI-RUNNER-DRAGONFLY-JIT-001",
            "schema": 1,
            "dispatch_id": payload["dispatch_id"],
            "target_host": "dragonfly-redrix-01",
            "profile_id": receiver.CANARY_PROFILE_ID,
            "repository": "LowcountryDigitalWorks/infrastructure-tools",
            "workflow": ".github/workflows/dragonfly-jit-canary.yml",
            "run_id": 123,
            "run_attempt": 1,
            "job_id": 456,
            "head_sha": "a" * 40,
            "job_name": "dragonfly-canary",
            "labels": ["synthetic"],
            "issued_at": "2026-10-29T08:00:00Z",
            "expires_at": "2026-10-29T08:04:00Z",
            "bootstrap_present": True,
        }

    def claim_dispatch(self, summary, *, state_root):
        return state_root / "claim.json"


class FakeExecutor:
    class CanaryExecutorError(RuntimeError):
        pass

    def __init__(self):
        self.calls = 0

    def execute_canary(self, payload, summary, *, state_root):
        self.calls += 1
        return {
            "guest_execution": "PASS",
            "guest_cleanup": "PASS",
            "state": "STOPPED",
            "job_id": summary["job_id"],
            "dispatch_id": summary["dispatch_id"],
        }


class CanaryReceiverTests(unittest.TestCase):
    def test_canary_delegates_after_claim_and_never_echoes_bootstrap(self):
        stdin = io.BytesIO(json.dumps({
            "dispatch_id": "11111111-1111-4111-8111-111111111111",
            "opaque_bootstrap": "DO-NOT-ECHO",
        }).encode("utf-8"))
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        executor = FakeExecutor()
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(receiver, "_load_handoff_contract", return_value=FakeHandoff()), \
             mock.patch.object(receiver, "_load_canary_executor", return_value=executor):
            rc = receiver.run_receiver(
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                environ={"SSH_ORIGINAL_COMMAND": receiver.REMOTE_SENTINEL},
                state_root=Path(temp),
            )
        self.assertEqual(rc, 0)
        self.assertEqual(executor.calls, 1)
        self.assertEqual(stderr.getvalue(), b"")
        output = stdout.getvalue().decode("utf-8")
        self.assertNotIn("DO-NOT-ECHO", output)
        self.assertEqual(json.loads(output)["execution"]["state"], "STOPPED")

    def test_receiver_pins_current_handoff_and_canary_executor(self):
        handoff_path = ROOT / receiver.HANDOFF_FILENAME
        handoff_data = receiver._assert_regular_private_source(handoff_path)
        self.assertEqual(receiver._git_blob_sha1(handoff_data), receiver.EXPECTED_HANDOFF_GIT_BLOB)
        executor_path = ROOT / receiver.CANARY_EXECUTOR_FILENAME
        executor_data = receiver._assert_pinned_source(
            executor_path,
            expected_blob=receiver.EXPECTED_CANARY_EXECUTOR_GIT_BLOB,
            max_bytes=receiver.MAX_EXECUTOR_BYTES,
        )
        self.assertEqual(receiver._git_blob_sha1(executor_data), receiver.EXPECTED_CANARY_EXECUTOR_GIT_BLOB)


if __name__ == "__main__":
    unittest.main()
