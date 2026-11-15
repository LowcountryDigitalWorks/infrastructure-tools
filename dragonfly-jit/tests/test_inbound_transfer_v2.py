import base64
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock
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
            "sourceCommit": transfer.DISPATCH_COMMIT if path == "ci-dispatch/Dispatch.psm1" else (transfer.ENTRY_COMMIT if path == "ci-dispatch/Invoke-DragonflyCanaryProduction.ps1" else transfer.CANARY_COMMIT),
            "sourceTree": transfer.DISPATCH_TREE if path == "ci-dispatch/Dispatch.psm1" else (transfer.ENTRY_TREE if path == "ci-dispatch/Invoke-DragonflyCanaryProduction.ps1" else transfer.CANARY_TREE),
            "gitBlob": transfer.PINNED_FILE_BLOBS[path],
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
    manifest_bytes = overrides.pop("manifest_bytes", None)
    if manifest_bytes is None:
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
        "manifest_content": base64.b64encode(manifest_bytes).decode("ascii"),
        "files": files,
    }
    payload.update(overrides)
    return payload


class InboundTransferV2Tests(unittest.TestCase):
    def setUp(self):
        # Synthetic suite bytes are NOT the real trusted V2 package. Override
        # immutable pins only within these deterministic offline tests.
        records = {p: f"synthetic:{p}".encode("utf-8") for p in transfer.PINNED_FILE_PATHS}
        pins = {p: transfer._git_blob_sha1(data) for p, data in records.items()}
        changes = (
            mock.patch.object(transfer, "PINNED_FILE_BLOBS", pins),
            mock.patch.object(transfer, "DISPATCH_WINDOWS_SHA256", hashlib.sha256(records["ci-dispatch/Dispatch.psm1"]).hexdigest()),
        )
        for change in changes:
            change.start()
            self.addCleanup(change.stop)

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

    def test_forced_receiver_pins_exact_current_hardened_transfer_source(self):
        actual = transfer._git_blob_sha1((ROOT / "inbound_transfer_v2.py").read_bytes())
        receiver = (ROOT / "ssh_forced_receiver.py").read_text(encoding="utf-8")
        self.assertIn(f'EXPECTED_INBOUND_TRANSFER_GIT_BLOB = "{actual}"', receiver)

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

    def test_forged_self_consistent_manifest_and_file_are_not_authority(self):
        payload = _build_envelope()
        path = "ci-dispatch/DragonflyCanary.psm1"
        forged = b"not-the-accepted-v2-package"
        new_sha = hashlib.sha256(forged).hexdigest()
        payload["files"][path] = {
            "sha256": new_sha,
            "content": base64.b64encode(forged).decode("ascii"),
        }
        for record in payload["manifest"]["files"]:
            if record["path"] == path:
                record["sha256"] = new_sha
                break
        canonical = json.dumps(payload["manifest"], sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        payload["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
        payload["manifest_content"] = base64.b64encode(canonical).decode("ascii")
        with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_FILE_PROVENANCE_MISMATCH"):
            transfer.validate_transfer_envelope(payload)

    def test_windows_crlf_manifest_bytes_preserved_and_hash_matched(self):
        manifest = _build_manifest()
        raw = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\r\n"
        payload = _build_envelope(manifest=manifest, manifest_bytes=raw)
        envelope = transfer.validate_transfer_envelope(payload)
        self.assertEqual(envelope["files"]["manifest.json"], raw)
        with tempfile.TemporaryDirectory() as temp:
            proof = transfer.install_transfer_bundle(
                envelope,
                install_root=Path(temp) / "adjunct-v2",
                state_root=Path(temp) / "state",
            )
            self.assertEqual(proof["manifest_sha256_sender"], proof["manifest_sha256_receiver"])
            release = Path(temp) / "adjunct-v2" / "releases" / transfer.RELEASE_IDENTITY
            self.assertEqual((release / "manifest.json").read_bytes(), raw)

    def test_manifest_object_and_actual_publisher_bytes_must_agree(self):
        payload = _build_envelope()
        payload["manifest"]["artifact"] = "other-artifact"
        with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_MANIFEST_OBJECT_DRIFT"):
            transfer.validate_transfer_envelope(payload)

    def test_unknown_manifest_field_and_bounded_reader_refuse(self):
        payload = _build_envelope()
        payload["manifest"]["unexpectedCommand"] = "untrusted"
        with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_MANIFEST_OBJECT_DRIFT"):
            transfer.validate_transfer_envelope(payload)
        # Even if the attacker recomputes the manifest blob+hash, the frozen
        # manifest allowlist rejects an unknown command/metadata field.
        raw = json.dumps(payload["manifest"], separators=(",", ":")).encode("utf-8") + b"\n"
        payload["manifest_content"] = base64.b64encode(raw).decode("ascii")
        payload["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_MANIFEST_INVALID"):
            transfer.validate_transfer_envelope(payload)
        with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_PAYLOAD_TOO_LARGE"):
            transfer._read_bounded(io.BytesIO(b"1" * 17), 16)

    @unittest.skipUnless(os.name == "posix", "requires POSIX directory modes")
    def test_preexisting_world_readable_state_root_refused(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            state_root = Path(temp) / "state"
            state_root.mkdir(mode=0o755)
            # mkdir(mode=...) is still masked by the caller's umask. The
            # accepted REDRIX native source CI runs with a private 0o077
            # umask, so explicitly make this hostile fixture world-readable.
            # Never relax the source runner's private checkout/umask policy.
            state_root.chmod(0o755)
            self.assertEqual(state_root.stat().st_mode & 0o777, 0o755)
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_STAGING_INVALID"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=Path(temp) / "adjunct-v2",
                    state_root=state_root,
                )

    def test_wrong_release_repo_or_missing_file_rejected(self):
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(_build_envelope(release_identity="f" * 40))
        manifest = _build_manifest()
        manifest["files"] = manifest["files"][:2]
        with self.assertRaises(transfer.TransferError):
            transfer.validate_transfer_envelope(_build_envelope(manifest=manifest))

    def test_precommit_write_failure_allows_successful_retry(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        original_write = transfer._write_private_file
        attempts = {"count": 0}

        def flaky_write(path, data):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise OSError("synthetic precommit write failure")
            return original_write(path, data)

        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            with mock.patch.object(transfer, "_write_private_file", side_effect=flaky_write):
                with self.assertRaises(OSError):
                    transfer.install_transfer_bundle(
                        envelope,
                        install_root=install_root,
                        state_root=state_root,
                    )
            pending = state_root / transfer.PENDING_CLAIM_FILENAME
            self.assertFalse(pending.exists())
            evidence = transfer.install_transfer_bundle(
                envelope,
                install_root=install_root,
                state_root=state_root,
            )
            self.assertEqual(evidence["outcome"], "TRANSFER_INSTALLED")
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_REPLAY_REFUSED"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=install_root,
                    state_root=state_root,
                )

    def test_post_replace_commit_failure_reconciles_orphan_then_refuses_replay(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        calls = {"count": 0}
        real_commit = transfer._commit_install_transaction

        def flaky_commit(state_root, manifest_sha256):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("synthetic claim commit failure")
            return real_commit(state_root, manifest_sha256)

        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            with mock.patch.object(transfer, "_commit_install_transaction", side_effect=flaky_commit):
                with self.assertRaises(OSError):
                    transfer.install_transfer_bundle(
                        envelope,
                        install_root=install_root,
                        state_root=state_root,
                    )
            self.assertTrue((state_root / transfer.PENDING_CLAIM_FILENAME).exists())
            release_root = install_root / "releases" / transfer.RELEASE_IDENTITY
            self.assertTrue(release_root.exists())
            evidence = transfer.install_transfer_bundle(
                envelope,
                install_root=install_root,
                state_root=state_root,
            )
            self.assertEqual(evidence["outcome"], "TRANSFER_INSTALLED")
            self.assertFalse((state_root / transfer.PENDING_CLAIM_FILENAME).exists())
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_REPLAY_REFUSED"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=install_root,
                    state_root=state_root,
                )

    def test_orphan_release_with_forged_bytes_refused(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            release_root = install_root / "releases" / transfer.RELEASE_IDENTITY
            release_root.mkdir(parents=True, mode=0o700)
            forged_path = release_root / transfer.PINNED_FILE_PATHS[0]
            forged_path.parent.mkdir(parents=True, exist_ok=True)
            forged_path.write_bytes(b"forged-orphan-tree")
            manifest_bytes = envelope["files"]["manifest.json"]
            (release_root / transfer.MANIFEST_FILENAME).write_bytes(manifest_bytes)
            state_root.mkdir(mode=0o700)
            transfer._begin_install_transaction(state_root, envelope["manifest_sha256"])
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_INSTALL_INCOMPLETE"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=install_root,
                    state_root=state_root,
                )

    def test_orphan_release_pending_conflict_refused(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            state_root.mkdir(mode=0o700)
            release_root = install_root / "releases" / transfer.RELEASE_IDENTITY
            for rel_path, data in envelope["files"].items():
                target = release_root / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            transfer._atomic_write_private_json(
                state_root / transfer.PENDING_CLAIM_FILENAME,
                {
                    "release_identity": transfer.RELEASE_IDENTITY,
                    "manifest_sha256": "a" * 64,
                },
            )
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_CLAIM_PENDING_CONFLICT"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=install_root,
                    state_root=state_root,
                )

    def test_os_replace_failure_rolls_back_pending_claim(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        calls = {"count": 0}
        real_replace = os.replace

        def flaky_replace(src, dst):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("synthetic rename failure")
            return real_replace(src, dst)

        with tempfile.TemporaryDirectory() as temp:
            install_root = Path(temp) / "adjunct-v2"
            state_root = Path(temp) / "state"
            with mock.patch.object(transfer.os, "replace", side_effect=flaky_replace):
                with self.assertRaises(OSError):
                    transfer.install_transfer_bundle(
                        envelope,
                        install_root=install_root,
                        state_root=state_root,
                    )
            self.assertFalse((state_root / transfer.PENDING_CLAIM_FILENAME).exists())
            self.assertFalse((state_root / transfer.CLAIMS_FILENAME).exists())
            transfer.install_transfer_bundle(
                envelope,
                install_root=install_root,
                state_root=state_root,
            )

    def test_malformed_committed_claim_refused(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            state_root = Path(temp) / "state"
            state_root.mkdir(mode=0o700)
            (state_root / transfer.CLAIMS_FILENAME).write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_CLAIM_STATE_INVALID"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=Path(temp) / "adjunct-v2",
                    state_root=state_root,
                )

    def test_malformed_pending_claim_refused(self):
        payload = _build_envelope()
        envelope = transfer.validate_transfer_envelope(payload)
        with tempfile.TemporaryDirectory() as temp:
            state_root = Path(temp) / "state"
            state_root.mkdir(mode=0o700)
            (state_root / transfer.PENDING_CLAIM_FILENAME).write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(transfer.TransferError, "TRANSFER_CLAIM_STATE_INVALID"):
                transfer.install_transfer_bundle(
                    envelope,
                    install_root=Path(temp) / "adjunct-v2",
                    state_root=state_root,
                )

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
