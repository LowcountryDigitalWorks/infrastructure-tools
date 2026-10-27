import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "ssh_transport_contract", ROOT / "ssh_transport_contract.py"
)
contract = importlib.util.module_from_spec(CONTRACT_SPEC)
CONTRACT_SPEC.loader.exec_module(contract)

RECEIVER_SPEC = importlib.util.spec_from_file_location(
    "ssh_forced_receiver", ROOT / "ssh_forced_receiver.py"
)
receiver = importlib.util.module_from_spec(RECEIVER_SPEC)
RECEIVER_SPEC.loader.exec_module(receiver)


class SshTransportContractTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "schema": 1,
            "target_host": "dragonfly-redrix-01",
            "private_endpoint": "redrix.example-alias",
            "host_key_fingerprint": "SHA256:" + ("A" * 43),
        }

    def test_exact_config_schema(self):
        result = contract.validate_transport_config(self.config)
        self.assertEqual(result["target_host"], "dragonfly-redrix-01")
        for extra in ("command", "port", "user", "key_path", "known_hosts_path"):
            candidate = dict(self.config)
            candidate[extra] = "x"
            with self.assertRaises(contract.TransportContractError):
                contract.validate_transport_config(candidate)

    def test_endpoint_rejects_option_and_shell_injection_shape(self):
        for endpoint in ("-oProxyCommand=x", "host name", "host;cmd", "../host", ".host", "host.", "a..b"):
            candidate = dict(self.config)
            candidate["private_endpoint"] = endpoint
            with self.assertRaises(contract.TransportContractError, msg=endpoint):
                contract.validate_transport_config(candidate)

    def test_fingerprint_is_required_but_not_put_in_argv(self):
        candidate = dict(self.config)
        candidate["host_key_fingerprint"] = "SHA256:bad"
        with self.assertRaises(contract.TransportContractError):
            contract.validate_transport_config(candidate)

        plan = contract.build_openssh_plan(
            self.config,
            local_app_data=r"C:\Users\eddie\AppData\Local",
        )
        joined = "\n".join(plan["arguments"])
        self.assertNotIn(self.config["host_key_fingerprint"], joined)

    def test_plan_is_fixed_no_shell_no_forwarding_and_stdin_only(self):
        plan = contract.build_openssh_plan(
            self.config,
            local_app_data=r"C:\Users\eddie\AppData\Local",
        )
        args = plan["arguments"]
        joined = "\n".join(args)

        self.assertEqual(plan["executable"], r"C:\Windows\System32\OpenSSH\ssh.exe")
        self.assertEqual(args[-2], "eddie@redrix.example-alias")
        self.assertEqual(args[-1], "ldw-dragonfly-jit-handoff-v1")
        self.assertTrue(plan["stdin_capsule_only"])
        self.assertFalse(plan["opens_network"])

        for required in (
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "ForwardAgent=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "RequestTTY=no",
        ):
            self.assertIn(required, args)
        for forbidden in ("-n", "-A", "-L", "-R", "-D"):
            self.assertNotIn(forbidden, args)
        self.assertNotIn("opaque_bootstrap", joined)

    def test_local_app_data_must_be_absolute(self):
        with self.assertRaises(contract.TransportContractError):
            contract.build_openssh_plan(self.config, local_app_data=r"relative\path")


class FakeHandoff:
    class HandoffError(RuntimeError):
        pass

    def __init__(self, *, fail=None):
        self.fail = fail
        self.claimed_root = None

    def read_capsule(self, stream):
        raw = stream.read()
        return json.loads(raw.decode("utf-8"))

    def validate_capsule(self, payload):
        if self.fail:
            raise self.HandoffError(self.fail)
        return {
            "marker": "CI-RUNNER-DRAGONFLY-JIT-001",
            "dispatch_id": payload["dispatch_id"],
            "bootstrap_present": True,
        }

    def claim_dispatch(self, summary, *, state_root):
        self.claimed_root = state_root


class SshForcedReceiverTests(unittest.TestCase):
    def invoke(self, *, original=receiver.REMOTE_SENTINEL, fake=None):
        fake = fake or FakeHandoff()
        stdin = io.BytesIO(json.dumps({
            "dispatch_id": "00000000-0000-4000-8000-000000000001",
            "opaque_bootstrap": "DO-NOT-ECHO",
        }).encode("utf-8"))
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(receiver, "_load_handoff_contract", return_value=fake):
                rc = receiver.run_receiver(
                    stdin=stdin,
                    stdout=stdout,
                    stderr=stderr,
                    environ={"SSH_ORIGINAL_COMMAND": original},
                    state_root=Path(temp),
                )
        return rc, stdout.getvalue().decode(), stderr.getvalue().decode(), fake

    def test_wrong_original_command_fails_before_contract_load(self):
        stdin = io.BytesIO(b"{}")
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        with mock.patch.object(receiver, "_load_handoff_contract") as loader:
            rc = receiver.run_receiver(
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                environ={"SSH_ORIGINAL_COMMAND": "sh"},
                state_root=Path("/tmp/unused"),
            )
        self.assertEqual(rc, 2)
        self.assertEqual(stdout.getvalue(), b"")
        self.assertEqual(stderr.getvalue(), b"ERROR:ORIGINAL_COMMAND_INVALID\n")
        loader.assert_not_called()

    def test_fixed_sentinel_claims_and_never_echoes_bootstrap(self):
        rc, out, err, fake = self.invoke()
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertNotIn("DO-NOT-ECHO", out)
        result = json.loads(out)
        self.assertTrue(result["claimed"])
        self.assertTrue(result["bootstrap_present"])
        self.assertIsNotNone(fake.claimed_root)

    def test_handoff_error_is_sanitized(self):
        rc, out, err, _ = self.invoke(fake=FakeHandoff(fail="HANDOFF_REPLAY"))
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "ERROR:HANDOFF_REPLAY\n")

    def test_receiver_pins_accepted_handoff_blob(self):
        handoff_path = ROOT / "handoff_contract.py"
        data = receiver._assert_regular_private_source(handoff_path)
        self.assertEqual(receiver._git_blob_sha1(data), receiver.EXPECTED_HANDOFF_GIT_BLOB)

    def test_receiver_main_accepts_no_cli_surface(self):
        with mock.patch.object(receiver.sys, "stderr", io.StringIO()):
            self.assertEqual(receiver.main(["unexpected"]), 2)


if __name__ == "__main__":
    unittest.main()
