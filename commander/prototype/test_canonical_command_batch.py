"""Deterministic negatives for the synthetic command/batch envelope.

No subprocess, shell, signature key, or filesystem path is used.
"""
import hashlib
import json
import unittest

from canonical_command_batch import (
    ENVELOPE_VERSION, PRIVILEGE_MODE, BatchRefused, canonical_batch_sha256,
    parse_canonical_batch, payload_matches,
)

HOST = "host:synthetic-a"
OTHER_HOST = "host:synthetic-b"
SIGNER = "signer-key:public-ref-1"
NOW = 1_700_000_000
PAYLOAD = b"synthetic-fixed-bytes-v1"
STDIN = b""
COMMAND_ID = "11111111-1111-4111-8111-111111111111"
BATCH_ID = "22222222-2222-4222-8222-222222222222"
DECISION_ID = "33333333-3333-4333-8333-333333333333"
SESSION_ID = "44444444-4444-4444-8444-444444444444"


def _command():
    return {
        "command_id": COMMAND_ID,
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "argv": ["ldw-canary", "once"],
        "stdin_sha256": hashlib.sha256(STDIN).hexdigest(),
        "env_allowlist": [{"name": "LDW_CANARY", "value_sha256": hashlib.sha256(b"on").hexdigest()}],
        "cwd_identity": "posix:/opt/ldw/canary",
    }


def _document(**overrides):
    document = {
        "version": ENVELOPE_VERSION,
        "host_id": HOST,
        "signer_key_id": SIGNER,
        "decision_id": DECISION_ID,
        "session_id": SESSION_ID,
        "privilege_mode": PRIVILEGE_MODE,
        "batch_id": BATCH_ID,
        "generation": 3,
        "issued_unix": NOW - 10,
        "expires_unix": NOW + 60,
        "max_commands": 1,
        "intent_text": "Show the fixed canary identity.",
        "commands": [_command()],
    }
    document.update(overrides)
    return document


def _raw(document=None) -> bytes:
    return json.dumps(
        _document() if document is None else document,
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _parse(raw=None, **kwargs):
    return parse_canonical_batch(
        _raw() if raw is None else raw,
        host_id=kwargs.get("host_id", HOST),
        privilege_mode=kwargs.get("privilege_mode", PRIVILEGE_MODE),
        generation=kwargs.get("generation", 3),
        now_unix=kwargs.get("now_unix", NOW),
    )


class CanonicalCommandBatchTests(unittest.TestCase):
    def test_pinned_utf8_sha256_vector_separates_intent_from_payload(self):
        raw = _raw()
        parsed = _parse(raw)
        self.assertEqual(
            canonical_batch_sha256(raw),
            "4ff11b98cf3322bd6849adcff8cda170dfe7fb62cb067de020678d4c90580245",
        )
        self.assertEqual(parsed["intent_text"], "Show the fixed canary identity.")
        self.assertNotEqual(parsed["intent_text"].encode(), PAYLOAD)
        self.assertEqual(parsed["commands"][0]["payload_sha256"], hashlib.sha256(PAYLOAD).hexdigest())
        payload_matches(parsed, COMMAND_ID, PAYLOAD)
        other_intent = _document(intent_text="Different displayed wording.")
        other_raw = json.dumps(other_intent, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        other = _parse(other_raw)
        self.assertNotEqual(canonical_batch_sha256(raw), canonical_batch_sha256(other_raw))
        self.assertEqual(other["commands"][0]["payload_sha256"], parsed["commands"][0]["payload_sha256"])

    def test_wrong_host_mode_schema_and_stale_generation_denied(self):
        with self.assertRaises(BatchRefused) as wrong_host:
            _parse(host_id=OTHER_HOST)
        self.assertEqual(wrong_host.exception.reason, "WRONG_HOST")
        with self.assertRaises(BatchRefused) as wrong_mode:
            _parse(privilege_mode="FULL_ADMIN_UNRESTRICTED")
        self.assertEqual(wrong_mode.exception.reason, "WRONG_MODE")
        with self.assertRaises(BatchRefused) as stale:
            _parse(generation=2)
        self.assertEqual(stale.exception.reason, "STALE_GENERATION")
        bad_version = _raw(_document(version="ldw.commander.command-batch.v0"))
        with self.assertRaises(BatchRefused) as schema:
            _parse(bad_version)
        self.assertEqual(schema.exception.reason, "SCHEMA_MISMATCH")

    def test_modified_argv_script_stdin_and_env_change_identity(self):
        base = canonical_batch_sha256(_raw())
        changed_argv = _document()
        changed_argv["commands"][0]["argv"] = ["ldw-canary", "twice"]
        changed_stdin = _document()
        changed_stdin["commands"][0]["stdin_sha256"] = hashlib.sha256(b"other").hexdigest()
        changed_env = _document()
        changed_env["commands"][0]["env_allowlist"][0]["value_sha256"] = hashlib.sha256(b"off").hexdigest()
        self.assertNotEqual(base, canonical_batch_sha256(_raw(changed_argv)))
        self.assertNotEqual(base, canonical_batch_sha256(_raw(changed_stdin)))
        self.assertNotEqual(base, canonical_batch_sha256(_raw(changed_env)))
        parsed = _parse()
        with self.assertRaises(BatchRefused) as mismatch:
            payload_matches(parsed, COMMAND_ID, PAYLOAD + b"-race")
        self.assertEqual(mismatch.exception.reason, "HASH_MISMATCH")

    def test_duplicate_invalid_utf8_and_noncanonical_forms_refused(self):
        raw = _raw()
        duplicate = raw.replace(b'"host_id"', b'"host_id":"host:synthetic-a","host_id"', 1)
        with self.assertRaises(BatchRefused) as dup:
            _parse(duplicate)
        self.assertEqual(dup.exception.reason, "DUPLICATE_FIELD")
        with self.assertRaises(BatchRefused) as bad_utf8:
            _parse(b"\xff")
        self.assertEqual(bad_utf8.exception.reason, "INVALID_UTF8")
        pretty = json.dumps(_document(), sort_keys=True, indent=2).encode()
        with self.assertRaises(BatchRefused) as space:
            _parse(pretty)
        self.assertEqual(space.exception.reason, "NONCANONICAL_ENCODING")
        reordered = json.dumps(_document(), sort_keys=False, separators=(",", ":")).encode()
        if reordered != raw:
            with self.assertRaises(BatchRefused) as order:
                _parse(reordered)
            self.assertEqual(order.exception.reason, "NONCANONICAL_ENCODING")
        escaped = raw.replace(b"Show", b"\\u0053how")
        with self.assertRaises(BatchRefused) as encoding:
            _parse(escaped)
        self.assertEqual(encoding.exception.reason, "NONCANONICAL_ENCODING")

    def test_shell_download_path_alias_and_replay_collision_refused(self):
        for argv in (["bash", "-c"], ["curl", "https://example.invalid/x"], ["ldw-canary", "a;b"]):
            document = _document()
            document["commands"][0]["argv"] = argv
            with self.assertRaises(BatchRefused) as refused:
                _parse(_raw(document))
            self.assertIn(refused.exception.reason, {"DYNAMIC_EXECUTION_REFUSED", "SCHEMA_MISMATCH"})
        aliased = _document()
        aliased["commands"][0]["cwd_identity"] = "posix:/opt/ldw/../canary"
        with self.assertRaises(BatchRefused) as path:
            _parse(_raw(aliased))
        self.assertEqual(path.exception.reason, "PATH_ALIAS")
        windows_slash = _document()
        windows_slash["commands"][0]["cwd_identity"] = "windows:C:\\LDW\\Canary"
        with self.assertRaises(BatchRefused):
            _parse(_raw(windows_slash))
        collided = _document()
        collided["max_commands"] = 2
        collided["commands"] = [_command(), _command()]
        with self.assertRaises(BatchRefused) as replay:
            _parse(_raw(collided))
        self.assertEqual(replay.exception.reason, "REPLAY_MARKER_COLLISION")
        distinct = _document()
        other = _command()
        other["command_id"] = "55555555-5555-4555-8555-555555555555"
        distinct["max_commands"] = 2
        distinct["commands"] = [_command(), other]
        parsed = _parse(_raw(distinct))
        self.assertEqual(
            [item["command_id"] for item in parsed["commands"]],
            [COMMAND_ID, other["command_id"]],
        )

    def test_module_does_not_name_a_process_or_shell_api(self):
        import inspect
        import canonical_command_batch as module
        source = inspect.getsource(module)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("Popen", source)


if __name__ == "__main__":
    unittest.main()
