#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = load("gate_a3_bootstrap_network_test", ROOT / "tools" / "dragonfly_gate_a3_bootstrap.py")


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        data: bytes = b"",
        url: str,
        requested_url: str,
    ) -> None:
        self.status = status
        self._data = data
        self._url = url
        self._requested = requested_url

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._data
        return self._data[:size]

    def close(self) -> None:
        return None


class GateA3BootstrapNetworkTests(unittest.TestCase):
    def _run_bootstrap(self, *, preflight: bytes, installer: bytes, digest: str = "e" * 64) -> tuple[int, str]:
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256=hashlib.sha256(preflight).hexdigest(),
            exact_bytes=len(preflight),
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=hashlib.sha256(installer).hexdigest(),
            installer_exact_bytes=len(installer),
            transport_key_sha256=digest,
        )

        responses = {
            bootstrap.ACCEPTED_A3_URL: FakeResponse(
                data=preflight,
                url=bootstrap.ACCEPTED_A3_URL,
                requested_url=bootstrap.ACCEPTED_A3_URL,
            ),
            bootstrap.ACCEPTED_INSTALLER_URL: FakeResponse(
                data=installer,
                url=bootstrap.ACCEPTED_INSTALLER_URL,
                requested_url=bootstrap.ACCEPTED_INSTALLER_URL,
            ),
        }

        class FakeOpener:
            def open(self, request, timeout=None):
                url = request.full_url
                if url not in responses:
                    raise OSError("unexpected url")
                return responses[url]

        namespace: dict = {}
        stdout = io.StringIO()
        with mock.patch("urllib.request.build_opener", return_value=FakeOpener()):
            with mock.patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    exec(compile(code, "<bootstrap>", "exec"), namespace)
        return ctx.exception.code, stdout.getvalue()

    def test_redirect_final_url_mismatch_holds(self):
        preflight = b"x" * 32
        installer = b"y" * 32
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256=hashlib.sha256(preflight).hexdigest(),
            exact_bytes=len(preflight),
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=hashlib.sha256(installer).hexdigest(),
            installer_exact_bytes=len(installer),
            transport_key_sha256="f" * 64,
        )

        class RedirectOpener:
            def open(self, request, timeout=None):
                return FakeResponse(
                    data=preflight,
                    url="https://evil.example/final",
                    requested_url=request.full_url,
                )

        stdout = io.StringIO()
        with mock.patch("urllib.request.build_opener", return_value=RedirectOpener()):
            with mock.patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    exec(compile(code, "<bootstrap>", "exec"), {})
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("A3_SOURCE_FINAL_URL_INVALID", stdout.getvalue())
        self.assertNotIn("f" * 64, stdout.getvalue())

    def test_length_mismatch_holds(self):
        preflight = b"x" * 32
        installer = b"y" * 32
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256=hashlib.sha256(preflight).hexdigest(),
            exact_bytes=len(preflight) + 1,
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=hashlib.sha256(installer).hexdigest(),
            installer_exact_bytes=len(installer),
            transport_key_sha256="a" * 64,
        )

        class FakeOpener:
            def open(self, request, timeout=None):
                if request.full_url == bootstrap.ACCEPTED_A3_URL:
                    return FakeResponse(data=preflight, url=request.full_url, requested_url=request.full_url)
                return FakeResponse(data=installer, url=request.full_url, requested_url=request.full_url)

        stdout = io.StringIO()
        with mock.patch("urllib.request.build_opener", return_value=FakeOpener()):
            with mock.patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    exec(compile(code, "<bootstrap>", "exec"), {})
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("A3_SOURCE_LENGTH_MISMATCH", stdout.getvalue())
        self.assertNotIn("a" * 64, stdout.getvalue())

    def test_sha256_mismatch_holds(self):
        preflight = b"x" * 32
        installer = b"y" * 32
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256="0" * 64,
            exact_bytes=len(preflight),
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=hashlib.sha256(installer).hexdigest(),
            installer_exact_bytes=len(installer),
            transport_key_sha256="b" * 64,
        )

        class FakeOpener:
            def open(self, request, timeout=None):
                if request.full_url == bootstrap.ACCEPTED_A3_URL:
                    return FakeResponse(data=preflight, url=request.full_url, requested_url=request.full_url)
                return FakeResponse(data=installer, url=request.full_url, requested_url=request.full_url)

        stdout = io.StringIO()
        with mock.patch("urllib.request.build_opener", return_value=FakeOpener()):
            with mock.patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    exec(compile(code, "<bootstrap>", "exec"), {})
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("A3_SOURCE_SHA256_MISMATCH", stdout.getvalue())

    def test_oversize_body_holds(self):
        preflight = b"x" * (bootstrap.MAX_SOURCE_BYTES + 1)
        installer = b"y" * 32
        code = bootstrap.build_bootstrap_code(
            url=bootstrap.ACCEPTED_A3_URL,
            sha256=hashlib.sha256(preflight).hexdigest(),
            exact_bytes=bootstrap.MAX_SOURCE_BYTES,
            max_bytes=bootstrap.MAX_SOURCE_BYTES,
            installer_url=bootstrap.ACCEPTED_INSTALLER_URL,
            installer_sha256=hashlib.sha256(installer).hexdigest(),
            installer_exact_bytes=len(installer),
            transport_key_sha256="c" * 64,
        )

        class FakeOpener:
            def open(self, request, timeout=None):
                if request.full_url == bootstrap.ACCEPTED_A3_URL:
                    return FakeResponse(data=preflight, url=request.full_url, requested_url=request.full_url)
                return FakeResponse(data=installer, url=request.full_url, requested_url=request.full_url)

        stdout = io.StringIO()
        with mock.patch("urllib.request.build_opener", return_value=FakeOpener()):
            with mock.patch("sys.stdout", stdout):
                with self.assertRaises(SystemExit) as ctx:
                    exec(compile(code, "<bootstrap>", "exec"), {})
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("A3_SOURCE_TOO_LARGE", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
