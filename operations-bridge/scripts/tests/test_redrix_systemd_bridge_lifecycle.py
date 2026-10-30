import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "systemd" / "ldw-operations-bridge-dragonfly.service"
CREDENTIAL_HELPER = ROOT / "scripts" / "redrix-systemd-bridge-credential.py"
SERVICE_HELPER = ROOT / "scripts" / "redrix-systemd-bridge-service.py"
EXPECTED_UNIT_SHA256 = "2ac20b0169355616da1afdc57a77b0d610d202b2b117a1d21eb9b032c8ddf613"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_record(path: Path, relative: str) -> dict:
    return {
        "path": relative,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


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
            "ReadWritePaths=/home/eddie/.local/state/ldw/operations-bridge/dragonfly /home/eddie/.local/state/ldw-dragonfly-jit /run/user/1000",
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
        self.assertIn('CREDENTIAL_ARTIFACT_IDENTITY_CHANGED', text)
        self.assertIn('CREDENTIAL_OPERATION_BUSY', text)
        self.assertNotIn('tempfile._get_candidate_names', text)

    def test_cleanup_refuses_replaced_final_identity_behaviorally(self):
        credential = load_module(CREDENTIAL_HELPER, "credential_identity_refusal")
        with (
            mock.patch.object(credential, "_artifact_present_privileged", return_value=True),
            mock.patch.object(credential, "_artifact_identity_privileged", return_value="22:200"),
            mock.patch.object(credential, "_run_sudo") as run_sudo,
        ):
            with self.assertRaisesRegex(credential.MigrationError, "CREDENTIAL_ARTIFACT_IDENTITY_CHANGED"):
                credential._remove_published_credential("11:100")
            run_sudo.assert_not_called()

    def test_cleanup_removes_only_matching_published_identity_behaviorally(self):
        credential = load_module(CREDENTIAL_HELPER, "credential_identity_match")
        with (
            mock.patch.object(credential, "_artifact_present_privileged", side_effect=[True, False]),
            mock.patch.object(credential, "_artifact_identity_privileged", return_value="11:100"),
            mock.patch.object(credential, "_run_sudo") as run_sudo,
        ):
            credential._remove_published_credential("11:100")
            run_sudo.assert_called_once_with(
                [credential.RM, "-f", str(credential.CREDENTIAL_PATH)],
                "CREDENTIAL_ARTIFACT_ROLLBACK_FAILED",
            )

    def test_credential_operation_lock_refuses_concurrent_invocation(self):
        credential = load_module(CREDENTIAL_HELPER, "credential_lock")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            lock = root / "credential.lock"
            with mock.patch.object(credential, "LOCK_PATH", lock):
                with credential._operation_lock():
                    with self.assertRaisesRegex(credential.MigrationError, "CREDENTIAL_OPERATION_BUSY"):
                        with credential._operation_lock():
                            pass

    def test_post_publish_verification_failure_uses_identity_bound_cleanup(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        publication = text.index('[LN, str(temp_path), str(CREDENTIAL_PATH)]')
        verification = text.index('_verify_ciphertext_metadata()', publication)
        handler = text.index('except Exception as verify_error:', verification)
        rollback = text.index('_remove_published_credential(published_identity)', handler)
        self.assertGreater(verification, publication)
        self.assertGreater(handler, verification)
        self.assertGreater(rollback, handler)
        self.assertIn('_assert_published_identity(published_identity)', text[publication:handler])

    def test_post_publish_temp_cleanup_failure_unwinds_matching_identity(self):
        text = CREDENTIAL_HELPER.read_text(encoding="utf-8")
        publication = text.index('[LN, str(temp_path), str(CREDENTIAL_PATH)]')
        identity = text.index('published_identity = temp_identity', publication)
        temp_cleanup = text.index('"CREDENTIAL_TEMP_CLEANUP_FAILED"', identity)
        handler = text.index('except Exception as temp_cleanup_error:', temp_cleanup)
        condition = text.index('if published_identity is not None:', handler)
        rollback = text.index('_remove_published_credential(published_identity)', condition)
        re_raise = text.index('raise temp_cleanup_error', rollback)
        self.assertGreater(identity, publication)
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

    def test_service_verifies_complete_manifest_payload_and_rejects_tampered_dll(self):
        service = load_module(SERVICE_HELPER, "service_payload_integrity")
        with tempfile.TemporaryDirectory() as td:
            package_root = Path(td) / "package"
            payload = package_root / "payload"
            payload.mkdir(parents=True)
            runner = payload / "LDW.OperationsBridge.Runner"
            managed = payload / "LDW.OperationsBridge.Runner.dll"
            runner.write_bytes(b"synthetic-runner")
            runner.chmod(0o755)
            managed.write_bytes(b"synthetic-managed")
            manifest_path = package_root / "manifest.json"
            manifest = {
                "schemaVersion": 1,
                "artifact": "ldw-operations-bridge-dragonfly-linux-x64",
                "sourceCommit": "a" * 40,
                "runtimeIdentifier": "linux-x64",
                "targetFramework": "net10.0",
                "selfContained": True,
                "requiresSystemDotnet": False,
                "installRoot": "~/.local/lib/ldw/operations-bridge/dragonfly",
                "entrypoint": "payload/LDW.OperationsBridge.Runner",
                "configurationPath": "~/.config/ldw/operations-bridge/dragonfly/config.json",
                "statePath": "~/.local/state/ldw/operations-bridge/dragonfly/health.json",
                "containsConfiguration": False,
                "containsCredential": False,
                "files": [
                    file_record(runner, runner.name),
                    file_record(managed, managed.name),
                ],
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with (
                mock.patch.object(service, "PACKAGE_ROOT", package_root),
                mock.patch.object(service, "PAYLOAD_ROOT", payload),
                mock.patch.object(service, "PACKAGE_MANIFEST", manifest_path),
                mock.patch.object(service, "BINARY", runner),
            ):
                service._verify_installed_package()
                managed.write_bytes(b"tampered-managed")
                with self.assertRaisesRegex(service.ServiceError, "BRIDGE_PACKAGE_PAYLOAD_PROVENANCE_INVALID"):
                    service._verify_installed_package()
                managed.write_bytes(b"synthetic-managed")
                manifest["files"][1] = file_record(managed, managed.name)
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                extra = payload / "unexpected.dll"
                extra.write_bytes(b"unexpected")
                with self.assertRaisesRegex(service.ServiceError, "BRIDGE_PACKAGE_PAYLOAD_SET_INVALID"):
                    service._verify_installed_package()

    def test_service_preflight_binds_complete_payload_to_package_manifest(self):
        text = SERVICE_HELPER.read_text(encoding="utf-8")
        for required in (
            'PACKAGE_MANIFEST = PACKAGE_ROOT / "manifest.json"',
            'PAYLOAD_ROOT = PACKAGE_ROOT / "payload"',
            '"artifact": "ldw-operations-bridge-dragonfly-linux-x64"',
            '"entrypoint": "payload/LDW.OperationsBridge.Runner"',
            '"containsCredential": False',
            '"containsConfiguration": False',
            'GIT_SHA_RE.fullmatch',
            '_verify_payload_records(manifest.get("files"))',
            'BRIDGE_PACKAGE_PAYLOAD_PROVENANCE_INVALID',
            'BRIDGE_PACKAGE_PAYLOAD_SET_INVALID',
        ):
            self.assertIn(required, text)

    def test_helpers_pin_expected_paths_and_unit_digest(self):
        credential = load_module(CREDENTIAL_HELPER, "redrix_systemd_bridge_credential")
        service = load_module(SERVICE_HELPER, "redrix_systemd_bridge_service")
        self.assertEqual(str(credential.CREDENTIAL_PATH), "/etc/ldw/operations-bridge/dragonfly/bridge-bearer.cred")
        self.assertEqual(str(credential.LOCK_PATH), "/run/user/1000/ldw-operations-bridge-dragonfly-credential.lock")
        self.assertEqual(credential.UNIT_NAME, "ldw-operations-bridge-dragonfly.service")
        self.assertEqual(credential.BRIDGE_ID, "dragonfly-redrix-01")
        self.assertEqual(service.EXPECTED_UNIT_SHA256, EXPECTED_UNIT_SHA256)
        self.assertEqual(str(service.UNIT_DESTINATION), "/etc/systemd/system/ldw-operations-bridge-dragonfly.service")
        self.assertEqual(str(service.BINARY), "/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload/LDW.OperationsBridge.Runner")
        self.assertEqual(str(service.PAYLOAD_ROOT), "/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload")
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
