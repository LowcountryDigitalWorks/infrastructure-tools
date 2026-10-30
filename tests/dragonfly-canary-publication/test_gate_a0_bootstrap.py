#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import shlex
import sys
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools" / "dragonfly_gate_a0_bootstrap.py"
ACCEPTED_HELPER = ROOT / "tools" / "dragonfly_gate_a0.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = load("test_gate_a0_bootstrap_module", SOURCE)


class FakeResponse:
    def __init__(self, data: bytes, *, url: str, status: int = 200):
        self.data = data
        self.url = url
        self.status = status
        self.closed = False

    def geturl(self):
        return self.url

    def read(self, count: int):
        return self.data[:count]

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


class GateA0BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.url = "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/" + ("a" * 40) + "/tools/dragonfly_gate_a0.py"

    def execute(
        self,
        *,
        payload: bytes,
        expected_sha: str | None = None,
        expected_bytes: int | None = None,
        max_bytes: int = 64,
        response_url: str | None = None,
        status: int = 200,
        error: Exception | None = None,
    ):
        expected = expected_sha or hashlib.sha256(payload).hexdigest()
        exact = len(payload) if expected_bytes is None else expected_bytes
        code = bootstrap.build_bootstrap_code(
            url=self.url,
            sha256=expected,
            exact_bytes=exact,
            max_bytes=max_bytes,
        )
        response = FakeResponse(payload, url=response_url or self.url, status=status)
        opener = FakeOpener(response, error)
        output = io.StringIO()
        old_argv = sys.argv[:]
        try:
            sys.argv = ["python3", "--synthetic-arg", "value"]
            with mock.patch.object(urllib.request, "build_opener", return_value=opener), contextlib.redirect_stdout(output):
                try:
                    exec(compile(code, "<bootstrap-test>", "exec"), {"__name__": "__main__"})
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = int(exc.code or 0)
        finally:
            sys.argv = old_argv
        return exit_code, output.getvalue(), response, opener

    def test_accepted_source_identity_is_exact_and_matches_checked_out_bytes(self):
        self.assertEqual(bootstrap.ACCEPTED_A0_COMMIT, "5815e4e4e5ea4719c9d694b1ccefa1808c927ac7")
        self.assertEqual(bootstrap.ACCEPTED_A0_BLOB, "fc9784a52d5f0d20b02c5d95ad4adc2e86ae04e9")
        self.assertEqual(bootstrap.ACCEPTED_A0_SHA256, "eed2ab4ef830a119b6c73915c20a07c354be43844806b692277004bc6d0461b7")
        self.assertEqual(bootstrap.ACCEPTED_A0_BYTES, 25719)
        self.assertEqual(
            bootstrap.ACCEPTED_A0_URL,
            "https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/5815e4e4e5ea4719c9d694b1ccefa1808c927ac7/tools/dragonfly_gate_a0.py",
        )
        self.assertEqual(bootstrap.MAX_SOURCE_BYTES, 65536)

        data = ACCEPTED_HELPER.read_bytes()
        self.assertEqual(len(data), bootstrap.ACCEPTED_A0_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), bootstrap.ACCEPTED_A0_SHA256)
        git_blob = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
        self.assertEqual(git_blob, bootstrap.ACCEPTED_A0_BLOB)

    def test_renderer_is_shell_safe_and_contains_only_public_identity_inputs(self):
        fingerprint = "SHA256:" + ("A" * 43)
        key_sha = "b" * 64
        rendered = bootstrap.render_command(alias="redrix", host_fingerprint=fingerprint, transport_key_sha256=key_sha)
        argv = shlex.split(rendered)
        self.assertEqual(argv[0], "/usr/bin/python3")
        self.assertEqual(argv[1], "-c")
        self.assertIn(bootstrap.ACCEPTED_A0_URL, argv[2])
        self.assertIn(bootstrap.ACCEPTED_A0_SHA256, argv[2])
        self.assertIn("EXPECTED_BYTES=25719", argv[2])
        self.assertEqual(
            argv[3:],
            [
                "--expected-local-alias", "redrix",
                "--expected-host-fingerprint", fingerprint,
                "--expected-transport-key-sha256", key_sha,
            ],
        )

    def test_renderer_refuses_invalid_public_inputs(self):
        fingerprint = "SHA256:" + ("A" * 43)
        key_sha = "b" * 64
        with self.assertRaisesRegex(bootstrap.BootstrapInputError, "A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID"):
            bootstrap.render_command(alias="other", host_fingerprint=fingerprint, transport_key_sha256=key_sha)
        with self.assertRaisesRegex(bootstrap.BootstrapInputError, "A0_EXPECTED_HOST_FINGERPRINT_INVALID"):
            bootstrap.render_command(alias="redrix", host_fingerprint="bad", transport_key_sha256=key_sha)
        with self.assertRaisesRegex(bootstrap.BootstrapInputError, "A0_EXPECTED_TRANSPORT_KEY_SHA256_INVALID"):
            bootstrap.render_command(alias="redrix", host_fingerprint=fingerprint, transport_key_sha256="bad")

    def test_verified_payload_executes_only_after_length_and_digest_match(self):
        payload = b'import sys\nprint("SYNTHETIC_HELPER_EXECUTED")\nprint("ARGV="+"|".join(sys.argv))\n'
        exit_code, output, response, opener = self.execute(payload=payload, max_bytes=256)
        self.assertEqual(exit_code, 0)
        self.assertIn("SYNTHETIC_HELPER_EXECUTED", output)
        self.assertIn("ARGV=dragonfly_gate_a0.py|--synthetic-arg|value", output)
        self.assertTrue(response.closed)
        self.assertEqual(len(opener.calls), 1)
        request, timeout = opener.calls[0]
        self.assertEqual(request.full_url, self.url)
        self.assertEqual(timeout, 10)

    def test_digest_or_length_mismatch_holds_before_payload_execution(self):
        payload = b'print("MUST_NOT_EXECUTE")\n'
        exit_code, output, response, _opener = self.execute(payload=payload, expected_sha="0" * 64)
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_SHA256_MISMATCH", output)
        self.assertNotIn("MUST_NOT_EXECUTE", output)
        self.assertTrue(response.closed)

        exit_code, output, _response, _opener = self.execute(payload=payload, expected_bytes=len(payload) - 1)
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_LENGTH_MISMATCH", output)
        self.assertNotIn("MUST_NOT_EXECUTE", output)

    def test_oversize_redirect_http_and_fetch_fail_closed(self):
        payload = b'x' * 65
        exit_code, output, _response, _opener = self.execute(payload=payload, expected_bytes=64, max_bytes=64)
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_TOO_LARGE", output)

        payload = b'print("ok")\n'
        exit_code, output, _response, _opener = self.execute(payload=payload, response_url="https://example.invalid/redirected")
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_FINAL_URL_INVALID", output)

        exit_code, output, _response, _opener = self.execute(payload=payload, status=404)
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_HTTP_STATUS_INVALID", output)

        exit_code, output, _response, _opener = self.execute(payload=payload, error=OSError("synthetic"))
        self.assertEqual(exit_code, 1)
        self.assertIn("CLASSIFICATION=A0_SOURCE_FETCH_FAILED", output)
        self.assertNotIn("synthetic", output)

    def test_bootstrap_source_verifies_length_and_digest_before_compile_and_has_no_disk_write_surface(self):
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A0_URL,
            sha256=bootstrap.ACCEPTED_A0_SHA256,
            exact_bytes=bootstrap.ACCEPTED_A0_BYTES,
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
        )
        length_check = code.index("len(data)!=EXPECTED_BYTES")
        digest_check = code.index("hashlib.sha256(data).hexdigest()")
        compile_call = code.index("compile(data")
        self.assertLess(length_check, digest_check)
        self.assertLess(digest_check, compile_call)
        for forbidden in (
            "tempfile",
            "subprocess",
            "pathlib",
            "os.system",
            "os.remove",
            "write(",
            "open(\"/",
            "NamedTemporaryFile",
            "mkstemp",
        ):
            self.assertNotIn(forbidden, code)
        self.assertIn("urllib.request.ProxyHandler({})", code)
        self.assertIn("urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)", code)
        self.assertIn("response.read(MAX_BYTES+1)", code)
        self.assertIn("response.geturl()!=URL", code)


if __name__ == "__main__":
    unittest.main()
