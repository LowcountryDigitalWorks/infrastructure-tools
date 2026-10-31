#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
from pathlib import Path
import re
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools" / "dragonfly_gate_a3_bootstrap.py"
PREFLIGHT = ROOT / "tools" / "dragonfly_canary_redrix_preflight.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = load("test_gate_a3_bootstrap_module", SOURCE)


class GateA3BootstrapTests(unittest.TestCase):
    def test_accepted_preflight_pin_matches_worktree(self):
        data = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", "HEAD:tools/dragonfly_canary_redrix_preflight.py"],
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(len(data), bootstrap.ACCEPTED_A3_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), bootstrap.ACCEPTED_A3_SHA256)

    def test_render_binds_transport_digest_and_provenance(self):
        digest = "a" * 64
        command = bootstrap.render_command(transport_key_sha256=digest)
        parts = shlex.split(command)
        self.assertEqual(parts[0], bootstrap.PYTHON)
        self.assertIn("-B", parts)
        code = parts[parts.index("-c") + 1]
        self.assertIn(digest, code)
        self.assertIn("TRANSPORT_SHA256=", code)
        self.assertIn(bootstrap.ACCEPTED_A3_URL, code)

    def test_render_rejects_invalid_transport_digest(self):
        with self.assertRaisesRegex(bootstrap.BootstrapInputError, "A3_EXPECTED_TRANSPORT_KEY_SHA256_INVALID"):
            bootstrap.render_command(transport_key_sha256="not-a-digest")


if __name__ == "__main__":
    unittest.main()
