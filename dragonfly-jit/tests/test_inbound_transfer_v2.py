import base64
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("inbound_transfer_v2", ROOT / "inbound_transfer_v2.py")
transfer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transfer)


def _manifest_file_records():
    rows = []
    for path in transfer.PINNED_FILE_PATHS:
        data = f"synthetic:{path}".encode("utf-8")
        rows.append({
            "path": path,
            "sourceCommit": transfer.CANARY_COMMIT if path != "ci-dispatch/Dispatch.psm1" else transfer.DISPATCH_COMMIT,
            "sourceTree": transfer.CANARY_TREE if path != "ci-dispatch/Dispatch.psm1" else transfer.DISPATCH_TREE,
            "gitBlob": "a" * 40,
            "representation": "crlf" if path == "ci-dispatch/Dispatch.psm1" else "raw",
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return rows


def _build_manifest():
    return {
        "schema": 2,
        "artifact": transfer.ARTIFACT_ID,
        "releaseIdentity": transfer.RELEASE_IDENTITY,
        "canaryCommit": transfer.CANARY_COMMIT,
        "canaryTree": transfer.CANARY_TREE,
        "entryCommit": transfer.ENTRY_COMMIT,
        "entryTree": transfer.ENTRY_TREE,
        "dispatchAuthority": {
            "commit": transfer.DISPATCH_COMMIT,
            "tree": transfer.DISPATCH_TREE,
            "blob": transfer.DISPATCH_BLOB,
            "rawSha256": transfer.DISPATCH_RAW_SHA256,
            "windowsSha256": transfer.DISPATCH_WINDOWS_SHA256,
            "materialization": "crlf",
        },
        "containsCredential": False,
        "containsBootstrap": False,
        "containsPrivateEndpoint": False,
        "files": _manifest_file_records(),
    }


def _build_envelope(**overrides):
    manifest = overrides.pop("manifest", _build_manifest())
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    files = {}
    for entry in manifest["files"]:
        data = f"synthetic:{entry['path']}".encode("utf-8")
        files[entry["path"]] = {
            "sha256": entry["sha256"],
            "content": base64.b64encode(data).decode("ascii"),
        }
    payload = {
        "schema": transfer.TRANSFER_SCHEMA,
        "marker": transfer.TRANSFER_MARKER,
        "release_identity": transfer.RELEASE_IDENTITY,
        "manifest_sha256": manifest_sha256,
        "manifest": manifest,
        "files": files,
    }
    payload.update(overrides)
    return payload


class InboundTransferV2Tests(unittest.TestCase):
    def test_positive_install_emits_sender_receiver_manifest_pair(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            evidence = transfer.install_transfer_bundle(
                envelope,
                install_root=install_root,
                state_root=state_root,
            )
            self.assertEqual(evidence["outcome"], "TRANSFER_INSTALLED")
            self.assertEqual(evidence["manifest_sha256_sender"], evidence["manifest_sha256_receiver"])
            with self.assertRaises(transfer.TransferError):
                transfer.install_transfer_bundle(envelope, install_root=install_root, state_root=state_root)

    def test_forged_manifest_or_digest_fails_closed(self):
        payload = _build_envelope()
        payload["manifest_sha256"] = "b" * 64
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(payload)
        payload = _build_envelope()
        bad = payload["files"][transfer.PINNED_FILE_PATHS[0]]
        bad["sha256"] = "b" * 64
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(payload)

    def test_wrong_release_repo_or_missing_file_rejected(self):
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(_build_envelope(release_identity="f" * 40))
        manifest = _build_manifest()
        manifest["files"] = manifest["files"][:2]
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(_build_envelope(manifest=manifest))

    def test_run_inbound_transfer_stdout_evidence(self):
        payload = _build_envelope()
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            rc = transfer.run_inbound_transfer(
                stdin=io.BytesIO(json.dumps(payload).encode("utf-8")),
                stdout=stdout,
                stderr=stderr,
                install_root=install_root,
                state_root=state_root,
            )
        self.assertEqual(rc, 0)
        body = json.loads(stdout.getvalue().decode("utf-8"))
        self.assertEqual(body["outcome"], "TRANSFER_INSTALLED")
        self.assertEqual(body["manifest_sha256_sender"], body["manifest_sha256_receiver"])


class TransportTransferPlanTests(unittest.TestCase):
    def test_transfer_plan_uses_closed_remote_command(self):
        transport_spec = importlib.util.spec_from_file_location("ssh_transport_contract", ROOT / "ssh_transport_contract.py")
        transport = importlib.util.module_from_spec(transport_spec)
        transport_spec.loader.exec_module(transport)
        plan = transport.build_openssh_transfer_plan(
            {
                "schema": 1,
                "target_host": transport.TARGET_HOST,
                "private_endpoint": "redrix-jit.example.invalid",
                "host_key_fingerprint": "SHA256:J3amNSfjSNRyUOpBNPLMFuyMG7yVJXkGspSmyXDTEEI",
            },
            local_app_data=r"C:\Users\synthetic\AppData\Local",
        )
        self.assertEqual(plan["remote_command"], transport.TRANSFER_REMOTE_SENTINEL)
        self.assertTrue(plan["stdin_transfer_envelope_only"])
        self.assertIn("ForwardAgent=no", plan["arguments"])
