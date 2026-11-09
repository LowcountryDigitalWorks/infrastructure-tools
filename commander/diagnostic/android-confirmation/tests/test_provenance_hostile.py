"""Hostile-input checks for the provenance manifest contract."""
from __future__ import annotations

import hashlib
import pathlib
import tempfile
import unittest

from provenance_contract import (
    ACCEPTED_WRAPPER_SHA256,
    ALLOWED_PACKAGE_ID,
    ProvenanceValidationError,
    build_release_neutral_manifest,
    dumps_manifest,
    inspect_source_manifest,
    loads_manifest,
    validate_manifest_document,
    verify_wrapper_before_execute,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = ROOT / "app" / "src" / "main" / "AndroidManifest.xml"
WRAPPER = ROOT / "gradle" / "wrapper" / "gradle-wrapper.jar"
COMMIT = "a" * 40
TREE = "b" * 40
PR_HEAD = "c" * 40


class ProvenanceHostileTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        wrapper_dir = self.tmp / "gradle" / "wrapper"
        wrapper_dir.mkdir(parents=True)
        wrapper_dir.joinpath("gradle-wrapper.jar").write_bytes(WRAPPER.read_bytes())
        self.apk = self.tmp / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        self.apk.parent.mkdir(parents=True, exist_ok=True)
        self.apk.write_bytes(b"debug-apk-bytes")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_under_tmp(self, **kwargs) -> dict:
        diagnostic_root = kwargs.pop("diagnostic_root", self.tmp)
        return build_release_neutral_manifest(
            git_commit=COMMIT,
            git_tree=TREE,
            pr_source_head=PR_HEAD,
            apk_path=kwargs.pop("apk_path", self.apk),
            diagnostic_root=diagnostic_root,
            source_manifest_path=kwargs.pop("source_manifest_path", SOURCE_MANIFEST),
            **kwargs,
        )

    def assert_code(self, exc: ProvenanceValidationError, code: str) -> None:
        self.assertEqual(exc.code, code)

    def test_wrapper_mismatch_before_execute(self) -> None:
        bad = self.tmp / "mismatch" / "gradle-wrapper.jar"
        bad.parent.mkdir(parents=True)
        bad.write_bytes(b"not-the-wrapper")
        with self.assertRaises(ProvenanceValidationError) as ctx:
            verify_wrapper_before_execute(bad)
        self.assert_code(ctx.exception, "PROV_ERR_WRAPPER_SHA_MISMATCH")

    def test_wrapper_ok_when_pinned(self) -> None:
        verify_wrapper_before_execute(WRAPPER, ACCEPTED_WRAPPER_SHA256)

    def test_missing_apk(self) -> None:
        missing = self.tmp / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        if missing.exists():
            missing.unlink()
        with self.assertRaises(ProvenanceValidationError) as ctx:
            self._build_under_tmp(apk_path=missing)
        self.assert_code(ctx.exception, "PROV_ERR_APK_MISSING")

    def test_tree_and_commit_mismatch_on_validate(self) -> None:
        manifest = self._build_under_tmp()
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(manifest, expected_commit="f" * 40, expected_tree=TREE)
        self.assert_code(ctx.exception, "PROV_ERR_COMMIT_MISMATCH")
        with self.assertRaises(ProvenanceValidationError) as ctx2:
            validate_manifest_document(manifest, expected_commit=COMMIT, expected_tree="d" * 40)
        self.assert_code(ctx2.exception, "PROV_ERR_TREE_MISMATCH")

    def test_apk_sha_mismatch(self) -> None:
        manifest = self._build_under_tmp()
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(manifest, expected_apk_sha256="0" * 64, expected_commit=COMMIT, expected_tree=TREE)
        self.assert_code(ctx.exception, "PROV_ERR_APK_SHA_MISMATCH")

    def test_manifest_permission_injection(self) -> None:
        injected = self.tmp / "AndroidManifest.xml"
        injected.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            '<uses-permission android:name="android.permission.INTERNET" />'
            "</manifest>",
            encoding="utf-8",
        )
        with self.assertRaises(ProvenanceValidationError) as ctx:
            inspect_source_manifest(injected)
        self.assert_code(ctx.exception, "PROV_ERR_PERMISSION_DECLARED")

    def test_duplicate_artifact_entries_rejected(self) -> None:
        manifest = self._build_under_tmp()
        manifest["artifacts"] = list(manifest["artifacts"]) + [dict(manifest["artifacts"][0])]
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(manifest)
        self.assert_code(ctx.exception, "PROV_ERR_DUPLICATE_ARTIFACT")

    def test_path_traversal_escape(self) -> None:
        escape_apk = self.tmp / ".." / "escape.apk"
        escape_apk.parent.mkdir(parents=True, exist_ok=True)
        escape_apk.write_bytes(b"x")
        with self.assertRaises(ProvenanceValidationError) as ctx:
            self._build_under_tmp(apk_path=escape_apk)
        self.assertIn(ctx.exception.code, {"PROV_ERR_PATH_ESCAPE", "PROV_ERR_APK_MISSING", "PROV_ERR_DUPLICATE_ARTIFACT"})

    def test_symlink_escape_is_rejected(self) -> None:
        if not hasattr(pathlib.Path, "symlink_to"):
            self.skipTest("platform cannot create symlinks")
        outside = self.tmp / "outside.apk"
        outside.write_bytes(b"outside")
        link = self.tmp / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.exists():
            link.unlink()
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("symlink creation blocked")
        # build_release_neutral_manifest resolves under diagnostic_root; symlink target may still be outside.
        wrapper_dir = self.tmp / "gradle" / "wrapper"
        wrapper_dir.mkdir(parents=True)
        wrapper_dir.joinpath("gradle-wrapper.jar").write_bytes(WRAPPER.read_bytes())
        with self.assertRaises(ProvenanceValidationError):
            build_release_neutral_manifest(
                git_commit=COMMIT,
                git_tree=TREE,
                pr_source_head=PR_HEAD,
                apk_path=link,
                diagnostic_root=self.tmp,
                source_manifest_path=SOURCE_MANIFEST,
            )

    def test_manifest_json_is_canonical_and_immutable_keys(self) -> None:
        manifest = self._build_under_tmp()
        text = dumps_manifest(manifest)
        roundtrip = loads_manifest(text)
        validate_manifest_document(roundtrip, expected_commit=COMMIT, expected_tree=TREE, expected_pr_head=PR_HEAD)
        tampered = dict(roundtrip)
        tampered["extra"] = "host-metadata"
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(tampered)
        self.assert_code(ctx.exception, "PROV_ERR_SCHEMA")

    def test_package_id_is_fixed(self) -> None:
        manifest = self._build_under_tmp()
        manifest["android"]["application_id"] = "evil.example"
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(manifest)
        self.assert_code(ctx.exception, "PROV_ERR_PACKAGE_ID")
        self.assertEqual(manifest["android"]["application_id"], "evil.example")
        self.assertEqual(ALLOWED_PACKAGE_ID, "com.lowcountrydigitalworks.commander.diagnostic")

    def test_error_messages_do_not_embed_host_metadata(self) -> None:
        manifest = self._build_under_tmp()
        bad = dict(manifest)
        bad["source"]["git_commit"] = "not-a-sha"
        with self.assertRaises(ProvenanceValidationError) as ctx:
            validate_manifest_document(bad)
        self.assertNotIn("username", str(ctx.exception).lower())
        self.assertNotIn("hostname", str(ctx.exception).lower())
        self.assertRegex(ctx.exception.code, r"^PROV_ERR_")


if __name__ == "__main__":
    unittest.main()
