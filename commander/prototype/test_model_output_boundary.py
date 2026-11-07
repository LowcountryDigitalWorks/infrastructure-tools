"""Default-deny checks. The fixture string is synthetic and is not a credential."""
import base64
import inspect
import json
import unittest

import model_output_boundary as boundary
from model_output_boundary import BLOCKED_STATUS, project_model_output

SECRET = "SYNTHETIC_TEST_SECRET_NOT_REAL"
BLOCKED = {"status": BLOCKED_STATUS}


def _encoded(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class ModelOutputBoundaryTests(unittest.TestCase):
    def assert_blocked(self, value):
        result = project_model_output(value)
        text = _encoded(result)
        self.assertEqual(result, BLOCKED)
        self.assertEqual(set(result), {"status"})
        self.assertNotIn(SECRET, text)
        self.assertNotIn(SECRET[:8], text)
        self.assertNotIn(base64.b64encode(SECRET.encode()).decode(), text)
        self.assertNotIn(SECRET.encode().hex(), text)

    def test_reserved_canary_strings_are_blocked(self):
        class StatusName(str):
            pass

        for name in ("SYNTHETIC_CANARY_NOT_STARTED", "SYNTHETIC_CANARY_FINISHED"):
            self.assert_blocked(name)
            self.assert_blocked(StatusName(name))

    def test_plain_encoded_chunked_and_nested_secrets_are_blocked(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        chunks = [SECRET[:9], SECRET[9:18], SECRET[18:]]
        samples = (
            SECRET,
            encoded,
            SECRET.encode().hex(),
            chunks,
            {"stdout": SECRET, "status": "SYNTHETIC_CANARY_FINISHED"},
            {"safe": True, "risk": "low"},
            [SECRET, encoded],
            {"nested": {"stderr": chunks}},
            bytearray(SECRET.encode()),
            memoryview(SECRET.encode()),
            SECRET.encode(),
        )
        for sample in samples:
            self.assert_blocked(sample)

    def test_exception_injection_unknown_and_huge_inputs_are_blocked(self):
        self.assert_blocked(RuntimeError(SECRET))
        self.assert_blocked(type("Odd", (), {})())
        self.assert_blocked(None)
        self.assert_blocked(SECRET * 10000)
        self.assert_blocked(" " + "SYNTHETIC_CANARY_FINISHED")
        self.assert_blocked({"status": "SYNTHETIC_CANARY_FINISHED"})

    def test_module_does_not_collect_process_output_or_log_payloads(self):
        source = inspect.getsource(boundary)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Popen", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("open(", source)
        self.assertNotIn("print(", source)
        self.assertNotIn("logging", source)
        self.assertNotIn("b64decode", source)
        self.assertNotIn(SECRET, source)


if __name__ == "__main__":
    unittest.main()
