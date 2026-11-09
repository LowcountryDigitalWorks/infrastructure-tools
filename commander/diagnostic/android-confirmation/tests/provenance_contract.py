"""Release-neutral APK/source provenance manifest contract. No device contact."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import xml.etree.ElementTree as etree
from typing import Any

SCHEMA_VERSION = 1
ALLOWED_PACKAGE_ID = "com.lowcountrydigitalworks.commander.diagnostic"
ACCEPTED_WRAPPER_SHA256 = "81a82aaea5abcc8ff68b3dfcb58b3c3c429378efd98e7433460610fecd7ae45f"
EXPECTED_APK_OUTPUT = "app/build/outputs/apk/debug/app-debug.apk"
TOOLCHAIN = {
    "android_gradle_plugin": "8.13.2",
    "gradle_distribution": "8.13",
    "gradle_wrapper_jar_sha256": ACCEPTED_WRAPPER_SHA256,
    "jdk_major": 17,
    "compile_sdk": 36,
    "target_sdk": 36,
    "min_sdk": 28,
}
MANIFEST_POLICY = {
    "uses_permission_declarations": 0,
    "exported_activities": 1,
    "internet_permission": False,
    "allow_backup": False,
    "uses_cleartext_traffic": False,
}
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "source",
        "android",
        "toolchain",
        "artifacts",
        "release_neutral",
    }
)


class ProvenanceValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_wrapper_before_execute(wrapper_jar: pathlib.Path, expected_sha256: str = ACCEPTED_WRAPPER_SHA256) -> None:
    if not wrapper_jar.is_file():
        raise ProvenanceValidationError("PROV_ERR_WRAPPER_SHA_MISMATCH", "gradle wrapper jar is missing")
    actual = _sha256_file(wrapper_jar)
    if actual != expected_sha256:
        raise ProvenanceValidationError("PROV_ERR_WRAPPER_SHA_MISMATCH", "gradle wrapper jar digest mismatch")


def assert_apk_path_contained(apk_path: pathlib.Path, diagnostic_root: pathlib.Path) -> pathlib.Path:
    try:
        resolved = apk_path.resolve(strict=False)
        root = diagnostic_root.resolve(strict=False)
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProvenanceValidationError("PROV_ERR_PATH_ESCAPE", "apk path escapes diagnostic root") from exc
    if ".." in apk_path.parts:
        raise ProvenanceValidationError("PROV_ERR_PATH_ESCAPE", "apk path contains traversal segments")
    return resolved


def inspect_source_manifest(manifest_path: pathlib.Path) -> dict[str, Any]:
    root = etree.parse(manifest_path).getroot()
    if list(root.findall("uses-permission")) or list(root.findall("uses-permission-sdk-23")):
        raise ProvenanceValidationError("PROV_ERR_PERMISSION_DECLARED", "source manifest declares a permission")
    application = root.find("application")
    if application is None:
        raise ProvenanceValidationError("PROV_ERR_PERMISSION_DECLARED", "source manifest is missing application")
    activities = list(application.findall("activity"))
    if len(activities) != 1:
        raise ProvenanceValidationError("PROV_ERR_PERMISSION_DECLARED", "source manifest must declare exactly one activity")
    exported = activities[0].attrib.get("{http://schemas.android.com/apk/res/android}exported")
    if exported != "true":
        raise ProvenanceValidationError("PROV_ERR_PERMISSION_DECLARED", "launcher activity must remain exported for offline install probe only")
    return {
        "uses_permission_declarations": 0,
        "exported_activities": 1,
        "internet_permission": False,
    }


def build_release_neutral_manifest(
    *,
    git_commit: str,
    git_tree: str,
    pr_source_head: str | None,
    apk_path: pathlib.Path,
    diagnostic_root: pathlib.Path,
    source_manifest_path: pathlib.Path,
) -> dict[str, Any]:
    for label, value in (("git_commit", git_commit), ("git_tree", git_tree)):
        if not COMMIT_RE.fullmatch(value):
            raise ProvenanceValidationError("PROV_ERR_COMMIT_MISMATCH", f"{label} is not a 40-character lowercase hex sha")
    if pr_source_head is not None and not COMMIT_RE.fullmatch(pr_source_head):
        raise ProvenanceValidationError("PROV_ERR_COMMIT_MISMATCH", "pr_source_head is not a 40-character lowercase hex sha")
    verify_wrapper_before_execute(diagnostic_root / "gradle" / "wrapper" / "gradle-wrapper.jar")
    contained_apk = assert_apk_path_contained(apk_path, diagnostic_root)
    if not contained_apk.is_file():
        raise ProvenanceValidationError("PROV_ERR_APK_MISSING", "apk artifact is missing")
    inspect_source_manifest(source_manifest_path)
    apk_sha256 = _sha256_file(contained_apk)
    apk_size = contained_apk.stat().st_size
    try:
        relative_apk = contained_apk.relative_to(diagnostic_root.resolve(strict=False)).as_posix()
    except ValueError as exc:
        raise ProvenanceValidationError("PROV_ERR_PATH_ESCAPE", "apk path is outside diagnostic tree") from exc
    if relative_apk != EXPECTED_APK_OUTPUT:
        raise ProvenanceValidationError("PROV_ERR_DUPLICATE_ARTIFACT", "apk output path does not match the accepted debug name")

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "commander.android_confirmation.diagnostic_provenance",
        "release_neutral": {
            "install_approved": False,
            "protected_confirmation_claimed": False,
            "artifact_scan_required_before_sideload": True,
        },
        "source": {
            "git_commit": git_commit,
            "git_tree": git_tree,
            "pr_source_head": pr_source_head,
        },
        "android": {
            "application_id": ALLOWED_PACKAGE_ID,
            "manifest_policy": dict(MANIFEST_POLICY),
        },
        "toolchain": dict(TOOLCHAIN),
        "artifacts": [
            {
                "role": "ephemeral_debug_apk",
                "relative_path": relative_apk,
                "file_name": pathlib.PurePosixPath(relative_apk).name,
                "sha256": apk_sha256,
                "size_bytes": apk_size,
            }
        ],
    }


def validate_manifest_document(
    manifest: dict[str, Any],
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_pr_head: str | None = None,
    expected_apk_sha256: str | None = None,
    diagnostic_root: pathlib.Path | None = None,
) -> None:
    extra = set(manifest) - ALLOWED_MANIFEST_KEYS
    if extra:
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", f"unexpected manifest keys: {sorted(extra)}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", "unsupported schema_version")
    if manifest.get("kind") != "commander.android_confirmation.diagnostic_provenance":
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", "unexpected manifest kind")
    release = manifest.get("release_neutral") or {}
    if release.get("install_approved") or release.get("protected_confirmation_claimed"):
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", "manifest must remain release-neutral")
    android = manifest.get("android") or {}
    if android.get("application_id") != ALLOWED_PACKAGE_ID:
        raise ProvenanceValidationError("PROV_ERR_PACKAGE_ID", "application_id mismatch")
    policy = android.get("manifest_policy") or {}
    if policy != MANIFEST_POLICY:
        raise ProvenanceValidationError("PROV_ERR_PERMISSION_DECLARED", "manifest_policy drift")
    source = manifest.get("source") or {}
    commit = source.get("git_commit", "")
    tree = source.get("git_tree", "")
    if not COMMIT_RE.fullmatch(commit) or not COMMIT_RE.fullmatch(tree):
        raise ProvenanceValidationError("PROV_ERR_COMMIT_MISMATCH", "source identity is malformed")
    if expected_commit is not None and commit != expected_commit:
        raise ProvenanceValidationError("PROV_ERR_COMMIT_MISMATCH", "git_commit mismatch")
    if expected_tree is not None and tree != expected_tree:
        raise ProvenanceValidationError("PROV_ERR_TREE_MISMATCH", "git_tree mismatch")
    pr_head = source.get("pr_source_head")
    if expected_pr_head is not None and pr_head != expected_pr_head:
        raise ProvenanceValidationError("PROV_ERR_COMMIT_MISMATCH", "pr_source_head mismatch")
    artifacts = manifest.get("artifacts") or []
    if len(artifacts) != 1:
        raise ProvenanceValidationError("PROV_ERR_DUPLICATE_ARTIFACT", "manifest must list exactly one artifact")
    artifact = artifacts[0]
    paths = [artifact.get("relative_path")]
    names = [artifact.get("file_name")]
    if len(set(paths)) != 1 or len(set(names)) != 1:
        raise ProvenanceValidationError("PROV_ERR_DUPLICATE_ARTIFACT", "duplicate artifact identity")
    if artifact.get("relative_path") != EXPECTED_APK_OUTPUT:
        raise ProvenanceValidationError("PROV_ERR_DUPLICATE_ARTIFACT", "unexpected artifact path")
    if expected_apk_sha256 is not None and artifact.get("sha256") != expected_apk_sha256:
        raise ProvenanceValidationError("PROV_ERR_APK_SHA_MISMATCH", "apk sha256 mismatch")
    if diagnostic_root is not None and expected_apk_sha256 is not None:
        apk_path = diagnostic_root / EXPECTED_APK_OUTPUT
        if not apk_path.is_file():
            raise ProvenanceValidationError("PROV_ERR_APK_MISSING", "apk artifact is missing on disk")
        assert_apk_path_contained(apk_path, diagnostic_root)
        if _sha256_file(apk_path) != expected_apk_sha256:
            raise ProvenanceValidationError("PROV_ERR_APK_SHA_MISMATCH", "on-disk apk digest mismatch")


def dumps_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"


def loads_manifest(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", "manifest is not valid json") from exc
    if not isinstance(parsed, dict):
        raise ProvenanceValidationError("PROV_ERR_SCHEMA", "manifest root must be an object")
    return parsed
