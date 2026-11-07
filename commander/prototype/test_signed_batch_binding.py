"""Negatives for synthetic signed-batch binding. The private key never leaves this file."""
import base64
import hashlib
import json
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from canonical_command_batch import PRIVILEGE_MODE
import test_canonical_command_batch as fixture
from signed_batch_binding import (
    DECISION_VERSION, RISK_CLASS, BatchDecisionRefused, SyntheticNonceLedger,
    verify_signed_batch,
)

OPERATOR = "owner-synthetic"
SIGNER_GENERATION = 2
NOW = fixture.NOW


def _b64(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def _decision(batch_raw: bytes, batch: dict, **overrides) -> dict:
    document = {
        "version": DECISION_VERSION,
        "decision_id": batch["decision_id"],
        "batch_id": batch["batch_id"],
        "session_id": batch["session_id"],
        "host_id": batch["host_id"],
        "operator": OPERATOR,
        "signer_key_id": batch["signer_key_id"],
        "signer_generation": SIGNER_GENERATION,
        "privilege_mode": PRIVILEGE_MODE,
        "batch_sha256": hashlib.sha256(batch_raw).hexdigest(),
        "intent_sha256": hashlib.sha256(batch["intent_text"].encode("utf-8")).hexdigest(),
        "issued_unix": batch["issued_unix"],
        "expires_unix": batch["expires_unix"],
        "generation": batch["generation"],
        "max_commands": batch["max_commands"],
        "risk_class": RISK_CLASS,
        "nonce": str(uuid.UUID("66666666-6666-4666-8666-666666666666")),
    }
    document.update(overrides)
    return document


def _sign(private: Ed25519PrivateKey, document: dict) -> str:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return _b64(raw) + "." + _b64(private.sign(raw))


def _verify(token, public, batch_raw, ledger=None, **kwargs):
    return verify_signed_batch(
        token, public, batch_raw,
        host_id=kwargs.get("host_id", fixture.HOST),
        operator=kwargs.get("operator", OPERATOR),
        signer_key_id=kwargs.get("signer_key_id", fixture.SIGNER),
        signer_generation=kwargs.get("signer_generation", SIGNER_GENERATION),
        generation=kwargs.get("generation", 3),
        now_unix=kwargs.get("now_unix", NOW),
        ledger=ledger if ledger is not None else SyntheticNonceLedger(),
    )


class SignedBatchBindingTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.batch_raw = fixture._raw()
        self.batch = fixture._parse(self.batch_raw)
        self.token = _sign(self.private, _decision(self.batch_raw, self.batch))

    def test_exact_batch_verifies_and_does_not_authorize_execution(self):
        bound = _verify(self.token, self.public, self.batch_raw)
        self.assertEqual(bound["batch_sha256"], hashlib.sha256(self.batch_raw).hexdigest())
        self.assertEqual(bound["command_ids"], [fixture.COMMAND_ID])
        self.assertNotIn("argv", bound)
        self.assertNotIn("payload", bound)

    def test_owner_decision_v1_and_approved_flag_are_not_batch_approval(self):
        from owner_decision import DECISION_VERSION as OWNER_V1
        self.assertNotEqual(OWNER_V1, DECISION_VERSION)
        v1 = {"version": OWNER_V1, "approved": True, "host": fixture.HOST}
        raw = json.dumps(v1, sort_keys=True, separators=(",", ":")).encode()
        forged = _b64(raw) + "." + _b64(self.private.sign(raw))
        with self.assertRaises(BatchDecisionRefused) as refused:
            _verify(forged, self.public, self.batch_raw)
        self.assertIn(refused.exception.reason, {"NOT_BATCH_DECISION", "NONCANONICAL_ENCODING", "SCHEMA_MISMATCH"})

    def test_wrong_key_host_operator_signer_generation_and_ttl_fail_closed(self):
        other = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(BatchDecisionRefused) as wrong_key:
            _verify(self.token, other, self.batch_raw)
        self.assertEqual(wrong_key.exception.reason, "WRONG_KEY")
        with self.assertRaises(BatchDecisionRefused) as absent:
            _verify("not-a-token", self.public, self.batch_raw)
        self.assertEqual(absent.exception.reason, "SIGNATURE_INVALID")
        for kwargs, reason in (
            ({"host_id": fixture.OTHER_HOST}, "WRONG_HOST"),
            ({"operator": "other-operator"}, "WRONG_OPERATOR"),
            ({"signer_key_id": "signer-key:other"}, "WRONG_SIGNER"),
            ({"signer_generation": 9}, "WRONG_SIGNER"),
            ({"generation": 1}, "STALE_GENERATION"),
            ({"now_unix": NOW + 120}, "BATCH_NOT_BOUND"),
        ):
            with self.assertRaises(BatchDecisionRefused) as refused:
                _verify(self.token, self.public, self.batch_raw, **kwargs)
            self.assertEqual(refused.exception.reason, reason, kwargs)

    def test_modified_batch_bytes_and_new_command_are_not_bound(self):
        changed = fixture._document()
        changed["commands"][0]["argv"] = ["ldw-canary", "twice"]
        changed_raw = fixture._raw(changed)
        with self.assertRaises(BatchDecisionRefused) as argv:
            _verify(self.token, self.public, changed_raw)
        self.assertEqual(argv.exception.reason, "BATCH_NOT_BOUND")
        extra = fixture._document()
        extra["max_commands"] = 2
        second = fixture._command()
        second["command_id"] = "55555555-5555-4555-8555-555555555555"
        extra["commands"] = [fixture._command(), second]
        extra_raw = fixture._raw(extra)
        with self.assertRaises(BatchDecisionRefused) as outside:
            _verify(self.token, self.public, extra_raw)
        self.assertEqual(outside.exception.reason, "BATCH_NOT_BOUND")

    def test_intent_field_and_replay_are_distinct_from_payload(self):
        rewritten = _decision(self.batch_raw, self.batch, intent_sha256="a" * 64)
        bad_intent = _sign(self.private, rewritten)
        with self.assertRaises(BatchDecisionRefused) as intent:
            _verify(bad_intent, self.public, self.batch_raw)
        self.assertEqual(intent.exception.reason, "BATCH_NOT_BOUND")
        ledger = SyntheticNonceLedger()
        first = _verify(self.token, self.public, self.batch_raw, ledger)
        self.assertEqual(first["batch_id"], fixture.BATCH_ID)
        with self.assertRaises(BatchDecisionRefused) as replay:
            _verify(self.token, self.public, self.batch_raw, ledger)
        self.assertEqual(replay.exception.reason, "BATCH_REPLAY")

    def test_noncanonical_decision_json_is_refused(self):
        raw = json.dumps(
            _decision(self.batch_raw, self.batch), sort_keys=True, indent=2,
        ).encode()
        token = _b64(raw) + "." + _b64(self.private.sign(raw))
        with self.assertRaises(BatchDecisionRefused) as refused:
            _verify(token, self.public, self.batch_raw)
        self.assertEqual(refused.exception.reason, "NONCANONICAL_ENCODING")

    def test_signed_invalid_types_refuse_before_the_ledger(self):
        cases = (
            {"nonce": []},
            {"nonce": {}},
            {"nonce": 1},
            {"generation": True},
            {"signer_generation": True},
            {"batch_sha256": "GG" + "a" * 62},
            {"decision_id": "not-a-uuid"},
            {"approved": True},
        )
        for overrides in cases:
            token = _sign(self.private, _decision(self.batch_raw, self.batch, **overrides))
            with self.assertRaises(BatchDecisionRefused) as refused:
                _verify(token, self.public, self.batch_raw)
            self.assertIn(refused.exception.reason, {"SCHEMA_MISMATCH", "NONCANONICAL_ENCODING"}, overrides)
            self.assertNotIsInstance(refused.exception.__cause__, TypeError)
        with self.assertRaises(BatchDecisionRefused) as trusted_bool:
            _verify(self.token, self.public, self.batch_raw, signer_generation=True)
        self.assertEqual(trusted_bool.exception.reason, "SCHEMA_MISMATCH")

    def test_module_has_no_private_signer_or_process_api(self):
        import inspect
        import signed_batch_binding as module
        source = inspect.getsource(module)
        self.assertNotIn("Ed25519PrivateKey", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Popen", source)


if __name__ == "__main__":
    unittest.main()
