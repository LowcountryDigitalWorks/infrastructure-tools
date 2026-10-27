import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "dragonfly_jit.py"
SPEC = importlib.util.spec_from_file_location("dragonfly_jit", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(mod)


class DrainResidueRegressionTests(unittest.TestCase):
    def test_prelaunch_draining_with_owned_residue_holds_for_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            controller = mod.Controller(data_root=root / "data", state_root=root / "state")
            controller.ensure_roots()
            controller.write_state("DRAINING", reason="DRAIN_REQUESTED")
            residue = controller.runs_root / "11111111-1111-4111-8111-111111111111"
            residue.mkdir()

            with mock.patch.object(controller, "_guest_lock_available", return_value=True):
                state = controller.drain()

            self.assertEqual("HOLD", state["state"])
            self.assertEqual("DRAIN_RESIDUE", state["reason"])
            self.assertTrue(residue.exists())


if __name__ == "__main__":
    unittest.main()
