#!/usr/bin/env python3
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "ci-dispatch/Invoke-DragonflyCanaryProduction.ps1"


class Ldw01ProductionEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = ENTRY.read_text(encoding="utf-8")

    def test_public_parameter_surface_is_closed(self):
        prefix = self.text.split("Set-StrictMode", 1)[0]
        names = re.findall(r"\$([A-Za-z][A-Za-z0-9]*)", prefix)
        self.assertEqual(names, ["RunId", "RunAttempt", "JobId", "HeadSha"])
        for forbidden in ("ApiInvoker", "ProcessInvoker", "StatusProvider", "DispatcherRoot", "LocalAppData", "WindowsRoot", "Root"):
            self.assertNotIn("$" + forbidden, prefix)

    def test_dispatcher_root_and_repository_are_fixed(self):
        self.assertIn("$script:Repository = 'LowcountryDigitalWorks/infrastructure-tools'", self.text)
        self.assertIn("Join-Path $env:ProgramData 'LDW\\CiRunnerDispatch'", self.text)
        self.assertNotIn("Read-Host", self.text)

    def test_provider_write_surface_is_only_jit_post_and_exact_runner_delete(self):
        self.assertIn("ValidateSet('POST','DELETE')", self.text)
        self.assertIn("/actions/runners/generate-jitconfig", self.text)
        self.assertIn("/actions/runners/[1-9][0-9]*$", self.text)
        self.assertNotIn("workflow_dispatch", self.text)
        self.assertNotIn("/actions/workflows/", self.text)
        self.assertNotIn("/contents/", self.text)

    def test_jit_request_body_is_stdin_only(self):
        self.assertIn("$psi.RedirectStandardInput = $true", self.text)
        self.assertIn("$psi.ArgumentList.Add('--input')", self.text)
        self.assertIn("$psi.ArgumentList.Add('-')", self.text)
        self.assertIn("$process.StandardInput.Write($payload)", self.text)
        self.assertNotIn("--raw-field", self.text)
        self.assertNotIn("--field", self.text)

    def test_provider_errors_are_sanitized(self):
        self.assertIn("$null = $stderrTask.GetAwaiter().GetResult()", self.text)
        self.assertNotIn("StandardError.ReadToEnd()", self.text)
        self.assertIn("DRAGONFLY_CANARY_API_WRITE_FAILED", self.text)
        self.assertIn("DRAGONFLY_CANARY_PRODUCTION_FAILED", self.text)

    def test_accepted_runtime_and_lock_are_reused(self):
        self.assertIn("Import-Module (Join-Path $PSScriptRoot 'Dispatch.psm1')", self.text)
        self.assertIn("Import-Module (Join-Path $PSScriptRoot 'DragonflyCanary.psm1')", self.text)
        self.assertIn("Import-Module (Join-Path $PSScriptRoot 'DragonflyCanaryRuntime.psm1')", self.text)
        self.assertIn("Invoke-LdwDragonflyCanaryOnce", self.text)
        self.assertIn("-DispatcherRoot $script:DispatcherRoot", self.text)
        self.assertNotIn("dispatcher.lock'", self.text)


if __name__ == "__main__":
    unittest.main()
