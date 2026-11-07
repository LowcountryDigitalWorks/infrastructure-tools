"""Synthetic transport refusal. The fixture string is not a credential."""
import base64
import inspect
import json
import unittest

import model_tool_transport_proof as transport
from model_output_boundary import BLOCKED_STATUS
from model_tool_transport_proof import model_tool_result

SECRET = "SYNTHETIC_TEST_SECRET_NOT_REAL"
BLOCKED = {"status": BLOCKED_STATUS}


def _text(result: dict) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


class ModelToolTransportProofTests(unittest.TestCase):
    def assert_blocked(self, payload):
        result = model_tool_result(payload)
        text = _text(result)
        self.assertEqual(result, BLOCKED)
        self.assertEqual(set(result), {"status"})
        self.assertNotIn(SECRET, text)
        self.assertNotIn(SECRET[:8], text)
        self.assertNotIn(base64.b64encode(SECRET.encode()).decode(), text)
        self.assertNotIn(SECRET.encode().hex(), text)

    def test_streams_errors_flags_and_chunks_stay_blocked(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        chunks = [SECRET[:9], SECRET[9:]]
        side = []

        def delayed():
            side.append(SECRET)
            yield SECRET

        def callback():
            raise RuntimeError(SECRET)

        generator = delayed()
        samples = (
            SECRET,
            "SYNTHETIC_TEST_SECRET_NÖT_REAL",
            encoded,
            SECRET.encode().hex(),
            chunks,
            SECRET.encode(),
            bytearray(SECRET.encode()),
            generator,
            callback,
            {"ok": True, "approved": True, "stdout": SECRET},
            {"status": "SYNTHETIC_CANARY_FINISHED", "safe": True},
            {"error": {"http": 500, "body": SECRET}},
            RuntimeError(SECRET),
            object(),
        )
        for sample in samples:
            self.assert_blocked(sample)
        self.assertEqual(side, [])
        self.assert_blocked(list(generator))

    def test_result_never_carries_reserved_status_text(self):
        for name in ("SYNTHETIC_CANARY_NOT_STARTED", "SYNTHETIC_CANARY_FINISHED"):
            text = _text(model_tool_result(name))
            self.assertEqual(text, '{"status":"MODEL_OUTPUT_BLOCKED"}')
            self.assertNotIn(name, text)

    def test_module_does_not_execute_or_iterate_untrusted_values(self):
        source = inspect.getsource(transport)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Popen", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("next(", source)
        self.assertNotIn("open(", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("logging", source)
        self.assertIn("project_model_output", source)


if __name__ == "__main__":
    unittest.main()
