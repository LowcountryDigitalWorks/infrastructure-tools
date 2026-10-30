import hashlib
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "systemd" / "ldw-operations-bridge-dragonfly.service"
CREDENTIAL_HELPER = ROOT / "scripts" / "redrix-systemd-bridge-credential.py"
SERVICE_HELPER = ROOT / "scripts" / "redrix-systemd-bridge-service.py"
EXPECTED_UNIT_SHA256 = "9a72afaaaa34bb510e8a693d3377b08ffc55ffcf0880d17d8b3b71ae949fba9a"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SystemdBridgeLifecycleTests(unittest.TestCase):
    def test_unit_is_exact_system_manager_nonroot_credential_contract(self):
        text = UNIT.read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(UNIT.read_bytes()).hexdigest(), EXPECTED_UNIT_SHA256)
        required = (
            "User=eddie",
            "Group=eddie",
            "WorkingDirectory=/home/eddie",
            "ExecStart=/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload/LDW.OperationsBridge.Runner --dragonfly-run",
            "Environment=LDW_DRAGONFLY_CREDENTIAL_SOURCE=systemd",
            "LoadCredentialEncrypted=bridge-bearer:/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred",
            "StartLimitIntervalSec=300",
            "StartLimitBurst=3",
            "Restart=on-failure",
            "RestartSec=15s",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        )
        for value in required:
            self.assertIn(value, text)
        for forbidden in (
            "Environment=BRIDGE_CLIENT_TOKEN=",
            "EnvironmentFile=",
            "LoadCredential=bridge-bearer:",
            "/bin/sh",
            "bash -c",
            "sudo ",
            "--run\n",
        ):
            self.assertNotIn(forbidden, text)

    def test_credential_helper_never_deletes_secret_service_or_prints_secret(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        self.assertIn('"--with-key=host"', text)
        self.assertIn('"--name=" + CREDENTIAL_NAME', text)
        self.assertIn('SECRET_TOOL, "lookup", "service", "ldw-operations-bridge", "bridge-id", BRIDGE_ID', text)
        self.assertIn("SECRET_SERVICE_PRESERVED=yes", text)
        self.assertNotIn('SECRET_TOOL, "clear"', text)
        self.assertNotIn('SECRET_TOOL, "store"', text)
        self.assertNotIn("shell=True", text)
        self.assertNotRegex(text, r"print\([^\n]*(token|bearer|digest_stdout)")
        self.assertNotIn("capture_output=True", text)

    def test_credential_publication_is_privileged_atomic_and_no_clobber(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        self.assertIn('_artifact_present_privileged()', text)
        self.assertIn('[TEST, "-e", str(CREDENTIAL_PATH)]', text)
        self.assertIn('[TEST, "-L", str(CREDENTIAL_PATH)]', text)
        self.assertIn('[LN, str(temp_path), str(CREDENTIAL_PATH)]', text)
        self.assertIn('"CREDENTIAL_ARTIFACT_EXISTS"', text)
        self.assertIn('secrets.token_hex(12)', text)
        self.assertIn('CREDENTIAL_DIRECTORY_METADATA_INVALID', text)
        self.assertIn('CREDENTIAL_ENCRYPT_TIMEOUT', text)
        self.assertIn('CREDENTIAL_DIGEST_TIMEOUT', text)
        self.assertNotIn('tempfile._get_candidate_names', text)

    def test_post_publish_verification_failure_removes_published_artifact(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        publication = text.index('[LN, str(temp_path), str(CREDENTIAL_PATH)]')
        verification = text.index('_verify_ciphertext_metadata()', publication)
        handler = text.index('except Exception as verify_error:', verification)
        rollback = text.index('_remove_published_credential()', handler)
        self.assertGreater(verification, publication)
        self.assertGreater(handler, verification)
        self.assertGreater(rollback, handler)
        self.assertIn('def _remove_published_credential()', text)
        self.assertIn('[RM, "-f", str(CREDENTIAL_PATH)]', text)
        self.assertIn('"CREDENTIAL_ARTIFACT_ROLLBACK_FAILED"', text)
        self.assertNotIn('if encrypted_credential_digest() != source_digest:\n        _run_sudo([RM', text)

    def test_post_publish_temp_cleanup_failure_unwinds_published_artifact(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        publication = text.index('[LN, str(temp_path), str(CREDENTIAL_PATH)]')
        published = text.index('published = True', publication)
        temp_cleanup = text.index('"CREDENTIAL_TEMP_CLEANUP_FAILED"', published)
        handler = text.index('except Exception as temp_cleanup_error:', temp_cleanup)
        condition = text.index('if published:', handler)
        rollback = text.index('_remove_published_credential()', condition)
        re_raise = text.index('raise temp_cleanup_error', rollback)
        self.assertGreater(published, publication)
        self.assertGreater(handler, temp_cleanup)
        self.assertGreater(condition, handler)
        self.assertGreater(rollback, condition)
        self.assertGreater(re_raise, rollback)

    def test_service_state_is_exact_and_ambiguous_states_fail_closed(self):
        combined = CREDENTIAL_HELPER.read_text(encoding="utf-8") + SERVICE_HELPER.read_text(encoding="utf-8")
        for value in (
            '"--property=LoadState"',
            '"--property=ActiveState"',
            '"--property=UnitFileState"',
            '"SERVICE_STATE_UNAVAILABLE"',
            '"SERVICE_STATE_AMBIGUOUS"',
            '"SERVICE_MUST_BE_INACTIVE_AND_DISABLED"',
        ):
            self.assertIn(value, combined)
        self.assertNotIn('"is-active"', combined)
        self.assertNotIn('"is-enabled"', combined)

    def test_service_helper_has_no_enable_or_start_mutation(self):
        text = SERVICE_HELPER.read_text(encoding="utf-8")
        self.assertIn('SYSTEMCTL, "daemon-reload"', text)
        self.assertNotRegex(text, r'SYSTEMCTL,\s*"(?:enable|start|restart|try-restart|reenable)"')
        self.assertNotIn("--now", text)
        self.assertIn('SERVICE_ENABLED=no', text)
        self.assertIn('SERVICE_STARTED=no', text)

    def test_service_preflight_binds_installed_binary_to_package_manifest(self):
        text = SERVICE_HELPER.read_text(encoding="utf-8")
        for required in (
            'PACKAGE_MANIFEST = PACKAGE_ROOT / "manifest.json"',
            '"artifact": "ldw-operations-bridge-dragonfly-linux-x64"',
            '"entrypoint": "payload/LDW.OperationsBridge.Runner"',
            '"containsCredential": False',
            '"containsConfiguration": False',
            'GIT_SHA_RE.fullmatch',
            'BINARY.stat().st_size != record["size"]',
            '_sha256(BINARY) != record["sha256"]',
            'BRIDGE_BINARY_PROVENANCE_INVALID',
        ):
            self.assertIn(required, text)

    def test_helpers_pin_expected_paths_and_unit_digest(self):
        credential = load_module(CREDENTIAL_HELPER, "redrix_systemd_bridge_credential")
        service = load_module(SERVICE_HELPER, "redrix_systemd_bridge_service")
        self.assertEqual(str(credential.CREDENTIAL_PATH), "/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred")
        self.assertEqual(credential.UNIT_NAME, "ldw-operations-bridge-dragonfly.service")
        self.assertEqual(credential.BRIDGE_ID, "dragonfly-redrix-01")
        self.assertEqual(service.EXPECTED_UNIT_SHA256, EXPECTED_UNIT_SHA256)
        self.assertEqual(str(service.UNIT_DESTINATION), "/etc/systemd/system/ldw-operations-bridge-dragonfly.service")
        self.assertEqual(str(service.BINARY), "/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload/LDW.OperationsBridge.Runner")
        self.assertEqual(str(service.PACKAGE_MANIFEST), "/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/manifest.json")
        self.assertEqual(str(service.CONFIG), "/home/eddie/.config/ldw/operations-bridge/dragonfly/config.json")

    def test_source_has_no_runtime_authority_or_provider_surface(self):
        combined = CREDENTIAL_HELPER.read_text(encoding="utf-8") + SERVICE_HELPER.read_text(encoding="utf-8") + UNIT.read_text(encoding="utf-8")
        for forbidden in (
            "gh api",
            "GITHUB_TOKEN",
            "generate-jitconfig",
            "tailscale set",
            "authorized_keys",
            "cloudflared",
            "wrangler",
            "systemctl enable",
            "systemctl start",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
