"""Deterministic negative-first tests; no Windows/elevation access needed."""
from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from windows_gate_c_capability import (
    CLASSIFICATION,
    PF_SECOND_LEVEL_ADDRESS_TRANSLATION,
    PF_VIRT_FIRMWARE_ENABLED,
    collect_capability_hints,
    main,
)


class Fn:
    def __init__(self, fn):
        self.fn = fn
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.fn(*args)


class StubDLL:
    def __init__(self, **funcs):
        self.__dict__.update(funcs)


class CapabilityTests(unittest.TestCase):
    def _assert_not_authority(self, outcome):
        self.assertEqual(outcome["classification"], CLASSIFICATION)
        for key in (
            "owner_presence_verified", "protected_issuer_verified",
            "external_guest_isolation_verified", "admin_session_authorized",
        ):
            self.assertIs(outcome[key], False)
        self.assertEqual(set(outcome), {
            "schema", "classification", "windows_api_inspected",
            "webauthn_api_version", "firmware_virtualization_hint", "slat_hint",
            "owner_presence_verified", "protected_issuer_verified",
            "external_guest_isolation_verified", "admin_session_authorized",
        })
        self.assertNotIn("host", json.dumps(outcome).lower())
        self.assertNotIn("user", json.dumps(outcome).lower())
        self.assertNotIn("key", json.dumps(outcome).lower())

    def test_non_windows_never_loads_dll(self):
        def no_load(_):
            self.fail("Non-Windows must never load Windows DLL")
        x = collect_capability_hints(platform_tag="linux", dll_loader=no_load)
        self.assertIs(x["windows_api_inspected"], False)
        self.assertIsNone(x["webauthn_api_version"])
        self._assert_not_authority(x)

    def test_known_system_apis_are_only_hints(self):
        calls = []
        def load(name):
            calls.append(name)
            if name == "webauthn.dll":
                return StubDLL(WebAuthNGetApiVersionNumber=Fn(lambda: 7))
            if name == "kernel32.dll":
                return StubDLL(IsProcessorFeaturePresent=Fn(lambda i: 1 if i in (20, 21) else 0))
            self.fail("Unexpected library")
        x = collect_capability_hints(platform_tag="win32", dll_loader=load)
        self.assertEqual(calls, ["webauthn.dll", "kernel32.dll"])
        self.assertIs(x["windows_api_inspected"], True)
        self.assertEqual(x["webauthn_api_version"], 7)
        self.assertIs(x["firmware_virtualization_hint"], True)
        self.assertIs(x["slat_hint"], True)
        self._assert_not_authority(x)

    def test_known_processor_indices(self):
        indexes = []
        def load(name):
            if name == "webauthn.dll":
                raise OSError("absent")
            return StubDLL(IsProcessorFeaturePresent=Fn(lambda i: indexes.append(i) or 0))
        x = collect_capability_hints(platform_tag="win32", dll_loader=load)
        self.assertEqual(indexes, [PF_VIRT_FIRMWARE_ENABLED, PF_SECOND_LEVEL_ADDRESS_TRANSLATION])
        self.assertIsNone(x["webauthn_api_version"])
        self.assertIs(x["firmware_virtualization_hint"], False)
        self._assert_not_authority(x)

    def test_failed_dll_load_remains_non_authorizing(self):
        def fail(_):
            raise OSError("unavailable")
        x = collect_capability_hints(platform_tag="win32", dll_loader=fail)
        self.assertIs(x["windows_api_inspected"], True)
        self.assertIsNone(x["webauthn_api_version"])
        self.assertIsNone(x["slat_hint"])
        self._assert_not_authority(x)

    def test_missing_exports_and_partial_results(self):
        def load(name):
            return StubDLL()
        x = collect_capability_hints(platform_tag="win32", dll_loader=load)
        self.assertIsNone(x["webauthn_api_version"])
        self.assertIsNone(x["firmware_virtualization_hint"])
        self._assert_not_authority(x)

    def test_invalid_version_and_processor_values_rejected(self):
        for version in (0, True, -1, 65536, "7", None):
            with self.subTest(version=version):
                def load(name):
                    if name == "webauthn.dll":
                        return StubDLL(WebAuthNGetApiVersionNumber=Fn(lambda: version))
                    return StubDLL(IsProcessorFeaturePresent=Fn(lambda _: 2))
                x = collect_capability_hints(platform_tag="win32", dll_loader=load)
                self.assertIsNone(x["webauthn_api_version"])
                self.assertIsNone(x["firmware_virtualization_hint"])
                self._assert_not_authority(x)

    def test_processor_errors_each_fail_closed(self):
        def load(name):
            if name == "webauthn.dll":
                return StubDLL(WebAuthNGetApiVersionNumber=Fn(lambda: 1))
            return StubDLL(IsProcessorFeaturePresent=Fn(lambda i: (_ for _ in ()).throw(OSError("blocked")) if i == 21 else 1))
        x = collect_capability_hints(platform_tag="win32", dll_loader=load)
        self.assertIsNone(x["firmware_virtualization_hint"])
        self.assertIs(x["slat_hint"], True)
        self._assert_not_authority(x)

    def test_cli_no_parameters_and_only_bounded_schema(self):
        stream = io.StringIO()
        with patch.object(sys, "argv", ["preflight"]), redirect_stdout(stream):
            main()
        x = json.loads(stream.getvalue())
        self._assert_not_authority(x)
        with patch.object(sys, "argv", ["preflight", "--approve"]):
            with self.assertRaises(SystemExit) as ctx:
                main()
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
