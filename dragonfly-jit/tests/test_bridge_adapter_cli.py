import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "bridge_adapter.py"
SPEC = importlib.util.spec_from_file_location("bridge_adapter_cli", MODULE_PATH)
ba = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ba)


class BridgeAdapterCliTests(unittest.TestCase):
    def test_unexpected_failure_is_sanitized_without_exception_text(self):
        output = io.StringIO()
        request = {"operation": "dragonfly.runner.status", "arguments": {}}
        with mock.patch.object(ba, "read_request", return_value=request):
            with mock.patch.object(
                ba,
                "invoke",
                side_effect=RuntimeError("secret /home/eddie/private"),
            ):
                with contextlib.redirect_stdout(output):
                    rc = ba.main()
        self.assertEqual(rc, 2)
        self.assertEqual(
            output.getvalue().strip(),
            '{"marker":"DRAGONFLY-BRIDGE-001","reason":"ADAPTER_FAILED","result":"FAILED"}',
        )
        self.assertNotIn("/home/eddie/private", output.getvalue())


if __name__ == "__main__":
    unittest.main()
