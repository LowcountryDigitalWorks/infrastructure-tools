#!/usr/bin/env python3
"""Deterministic tests for non-authorizing A4 privileged channel contract (#139)."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "dragonfly_gate_a4_channel_contract.py"


def load():
    spec = importlib.util.spec_from_file_location("a4_channel_contract", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


contract = load()
NONCE = "a" * 64
CORR = "synthetic-correlation-139"
OP = contract.OPERATION


def closed_request(**overrides) -> bytes:
    body = {"schemaVersion": 1, "operation": OP, "arguments": []}
    body.update(overrides)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def closed_response(**overrides) -> bytes:
    body = {
        "schemaVersion": 1,
        "operation": OP,
        "correlation": CORR,
        "nonce": NONCE,
        "uidPolicy": 1000,
        "snapshots": [
            {
                "sequence": 1,
                "observedAtMonotonicMs": 1000,
                "processCount": 0,
                "qemuProcessCount": 0,
                "kvmFdProcessCount": 0,
            },
            {
                "sequence": 2,
                "observedAtMonotonicMs": 2000,
                "processCount": 0,
                "qemuProcessCount": 0,
                "kvmFdProcessCount": 0,
            },
        ],
    }
    body.update(overrides)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def evaluate(request: bytes = closed_request(), response: bytes | None = None, **kwargs):
    if response is None:
        response = closed_response()
    return contract.evaluate_privileged_channel_exchange(
        request,
        response,
        expected_nonce=kwargs.get("expected_nonce", NONCE),
        expected_correlation=kwargs.get("expected_correlation", CORR),
    )


class A4ChannelContractTests(unittest.TestCase):
    def assert_hold(self, result: dict, reason: str) -> None:
        self.assertEqual(result["classification"], "HOLD")
        self.assertEqual(result["reasonCode"], reason)
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])

    def assert_data_only(self, result: dict) -> None:
        self.assertEqual(result["classification"], "DATA_ONLY_NOT_AUTHORIZED")
        self.assertFalse(result["a4Pass"])
        self.assertFalse(result["runtimeAuthority"])
        self.assertFalse(result["privilegedChannelAuthenticated"])

    def assert_never_pass(self, result: dict) -> None:
        self.assertNotEqual(result["classification"], "PASS")
        self.assertFalse(result.get("a4Pass"))
        self.assertFalse(result.get("runtimeAuthority"))
        self.assertFalse(result.get("privilegedChannelAuthenticated"))

    def test_a4_fd_12_synthetic_positive_data_only(self) -> None:
        result = evaluate()
        self.assert_data_only(result)
        self.assert_never_pass(result)

    def test_forbidden_auth_claims_hold(self) -> None:
        for field, value in (
            ("privilegedChannelAuthenticated", True),
            ("root", True),
            ("signature", "forged"),
            ("a4Pass", True),
            ("runtimeAuthority", True),
        ):
            with self.subTest(field=field):
                payload = json.loads(closed_response())
                payload[field] = value
                self.assert_hold(
                    evaluate(response=json.dumps(payload).encode()),
                    "A4_CH_FORBIDDEN_AUTH_CLAIM",
                )

    def test_caller_selected_path_and_command_rejected(self) -> None:
        for key, value in (
            ("path", "/usr/bin/bash"),
            ("executable", "/bin/sh"),
            ("command", "sudo cat /proc/1/fd/0"),
            ("token", "secret-token"),
        ):
            payload = json.loads(closed_response())
            payload[key] = value
            self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_FORBIDDEN_AUTH_CLAIM")

    def test_duplicate_json_keys_fail_closed(self) -> None:
        raw = b'{"schemaVersion":1,"schemaVersion":1,"operation":"' + OP.encode() + b'","arguments":[]}'
        self.assert_hold(
            contract.evaluate_privileged_channel_exchange(
                raw,
                closed_response(),
                expected_nonce=NONCE,
                expected_correlation=CORR,
            ),
            "A4_CH_DUPLICATE_KEY",
        )

    def test_nonce_and_correlation_mismatch_hold(self) -> None:
        self.assert_hold(
            evaluate(expected_nonce="b" * 64),
            "A4_CH_NONCE_MISMATCH",
        )
        payload = json.loads(closed_response())
        payload["correlation"] = "other-correlation"
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_CORRELATION_MISMATCH")

    def test_stale_nonmonotonic_snapshots_hold(self) -> None:
        payload = json.loads(closed_response())
        payload["snapshots"][1]["observedAtMonotonicMs"] = 500
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_SNAPSHOT_NONMONOTONIC")
        payload = json.loads(closed_response())
        payload["snapshots"][1]["sequence"] = 1
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_SNAPSHOT_DUPLICATE_SEQUENCE")

    def test_qemu_and_kvm_positive_hold(self) -> None:
        payload = json.loads(closed_response())
        payload["snapshots"][0]["qemuProcessCount"] = 1
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_QEMU_PRESENT")
        payload = json.loads(closed_response())
        payload["snapshots"][1]["kvmFdProcessCount"] = 1
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_KVM_FD_PRESENT")

    def test_uid_policy_drift_hold(self) -> None:
        payload = json.loads(closed_response())
        payload["uidPolicy"] = 0
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_UID_POLICY_DRIFT")

    def test_unexpected_operation_schema_and_arguments(self) -> None:
        self.assert_hold(evaluate(closed_request(operation="RUN_AS_ROOT")), "A4_CH_UNEXPECTED_OPERATION")
        self.assert_hold(evaluate(closed_request(schemaVersion=2)), "A4_CH_UNEXPECTED_SCHEMA")
        self.assert_hold(evaluate(closed_request(arguments=["--exec"])), "A4_CH_UNEXPECTED_ARGUMENTS")
        self.assert_hold(evaluate(closed_request(extra="x")), "A4_CH_UNEXPECTED_FIELD")

    def test_boolean_masquerading_as_int(self) -> None:
        payload = json.loads(closed_response())
        payload["uidPolicy"] = True
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_TYPE_MISMATCH")

    def test_malformed_utf8_and_oversize_input(self) -> None:
        self.assert_hold(
            evaluate(response=b"\xff\xfe"),
            "A4_CH_MALFORMED_UTF8",
        )
        huge = b" " * (contract.MAX_INPUT_BYTES + 1)
        self.assert_hold(evaluate(response=huge), "A4_CH_INPUT_TOO_LARGE")

    def test_json_depth_and_non_json_hold(self) -> None:
        deep: dict = {"schemaVersion": 1, "operation": OP, "arguments": []}
        cursor = deep
        for _ in range(contract.MAX_JSON_DEPTH + 2):
            cursor["nest"] = {}
            cursor = cursor["nest"]
        self.assert_hold(evaluate(closed_request(), json.dumps(deep).encode()), "A4_CH_JSON_TOO_DEEP")
        self.assert_hold(evaluate(response=b"{not-json"), "A4_CH_MALFORMED_JSON")

    def test_sensitive_correlation_and_email_leak_rejected(self) -> None:
        payload = json.loads(closed_response())
        payload["correlation"] = "owner@example.test"
        self.assert_hold(evaluate(response=json.dumps(payload).encode()), "A4_CH_FORBIDDEN_CONTENT")

    def test_parser_never_mints_nonce_evidence(self) -> None:
        result = evaluate()
        self.assertNotIn("nonce", result)
        self.assert_data_only(result)

    def test_build_closed_request_helper(self) -> None:
        self.assertEqual(contract.build_closed_request_json(), closed_request())


if __name__ == "__main__":
    unittest.main()
