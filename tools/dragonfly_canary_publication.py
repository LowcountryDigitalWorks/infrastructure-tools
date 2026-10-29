#!/usr/bin/env python3
"""Deterministic source-package builder/verifier for Dragonfly canary publication.

Source-only: this helper never installs files, touches authorized_keys, reads
credentials, launches SSH/QEMU, or calls GitHub APIs. It packages exact accepted
Git objects for later separately gated publication/install helpers.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile

REPOSITORY = "LowcountryDigitalWorks/infrastructure-tools"
SOURCE_COMMIT = "78a3a23b1a9dac59698a09cec2dd6c9a81e4a3ca"
SOURCE_TREE = "5f54ee5b76f49250db1358f058745cb30b6587ef"
ROLLBACK_COMMIT = "4fed47d8d81833b2978f4ea03ffd0f5b86126008"
ROLLBACK_TREE = "076069fe4437cea2538a9333b45ee47025bc9f2d"
DISPATCH_COMMIT = "ce2bf253556a69dfb43de7bb8e8a4927c41c9e15"
DISPATCH_TREE = "57ceb47f2a0a40d3b176cde0818a0ad8c5891dca"
DISPATCH_BLOB = "c862dd503b98060ec984206e63ef9efa5f957e8f"
DISPATCH_RAW_SHA256 = "76092a5344746f4385a2b99ee0403c298ffed0458099444ddc82b67fd30f0675"
DISPATCH_WINDOWS_SHA256 = "0a41b338ca6b8b05ff31a26f30486381c7c836e484985a813b6fce6d07232c72"

REDRIX_PACKAGE = "ldw-dragonfly-canary-source-v1"
LDW01_PACKAGE = "ldw-dragonfly-canary-adjunct-source-v1"
OWNER = {"user": "eddie", "uid": 1000}

REDRIX_CURRENT = (
    ("dragonfly-jit/ssh_forced_receiver.py", "88b527fa4b9b7060216c661d58edf2e97034dafa", "~/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py", "0700"),
    ("dragonfly-jit/handoff_contract.py", "cedf75fb360f05893afea119782f646da8a2e28b", "~/.local/lib/ldw-dragonfly-jit/handoff_contract.py", "0600"),
    ("dragonfly-jit/canary_executor.py", "c8c51040b99b0f2f8fd6b10156395244505d61cc", "~/.local/lib/ldw-dragonfly-jit/canary_executor.py", "0600"),
    ("dragonfly-jit/dragonfly_jit.py", "dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a", "~/.local/lib/ldw-dragonfly-jit/dragonfly_jit.py", "0600"),
    ("dragonfly-jit/canary-guest/bootstrap.sh", "0fa167cba3f30652caac3bf822a616f31183d62a", "~/.local/lib/ldw-dragonfly-jit/canary-guest/bootstrap.sh", "0700"),
    ("ci-runner/guest/run-one.sh", "a17ee1fa2ae307ce142572eb7dff9b2bbcfb56ee", "~/.local/lib/ci-runner/guest/run-one.sh", "0755"),
    ("ci-runner/guest/ci7-runner.service", "b5a7cdad0d7ec457b3aacee59167454a5078022e", "~/.local/lib/ci-runner/guest/ci7-runner.service", "0644"),
)
REDRIX_ROLLBACK = (
    ("dragonfly-jit/ssh_forced_receiver.py", "bb7401de594623aa3f879150a92b20f0f6bbf607", "~/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py", "0700"),
    ("dragonfly-jit/handoff_contract.py", "2f7892275bacd9f56abaa0cdf204f46f79c046c0", "~/.local/lib/ldw-dragonfly-jit/handoff_contract.py", "0600"),
)
LDW01_FILES = (
    (SOURCE_COMMIT, "ci-dispatch/DragonflyCanary.psm1", "893c89ae65bd85464f404fa4a4ff762344915520", "raw"),
    (SOURCE_COMMIT, "ci-dispatch/DragonflyCanaryRuntime.psm1", "7730f473d2588e885fa6a4f3aec1b486b408dbda", "raw"),
    (DISPATCH_COMMIT, "ci-dispatch/Dispatch.psm1", DISPATCH_BLOB, "crlf"),
)


class PublicationError(RuntimeError):
    pass


def _git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=text,
    )
    if proc.returncode != 0:
        raise PublicationError("GIT_PROVENANCE_UNAVAILABLE")
    return proc.stdout


def _assert_repo(repo: Path) -> None:
    remote = str(_git(repo, "remote", "get-url", "origin")).strip()
    if re.fullmatch(r"(?:https://github\.com/|git@github\.com:)LowcountryDigitalWorks/infrastructure-tools(?:\.git)?", remote) is None:
        raise PublicationError("PUBLISH_REPOSITORY_REFUSED")
    if str(_git(repo, "status", "--porcelain", "--untracked-files=normal")).strip():
        raise PublicationError("PUBLISH_SOURCE_WORKTREE_DIRTY")
    for commit, tree in ((SOURCE_COMMIT, SOURCE_TREE), (ROLLBACK_COMMIT, ROLLBACK_TREE), (DISPATCH_COMMIT, DISPATCH_TREE)):
        if str(_git(repo, "rev-parse", f"{commit}^{{tree}}" )).strip() != tree:
            raise PublicationError("PUBLISH_COMMIT_TREE_MISMATCH")


def _blob(repo: Path, commit: str, path: str, expected_blob: str) -> bytes:
    actual = str(_git(repo, "rev-parse", f"{commit}:{path}")).strip()
    if actual != expected_blob:
        raise PublicationError("PUBLISH_BLOB_IDENTITY_MISMATCH")
    data = _git(repo, "cat-file", "blob", expected_blob, text=False)
    assert isinstance(data, bytes)
    actual_blob = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
    if actual_blob != expected_blob:
        raise PublicationError("PUBLISH_BLOB_CONTENT_MISMATCH")
    return data


def _epoch(repo: Path) -> int:
    value = str(_git(repo, "show", "-s", "--format=%ct", SOURCE_COMMIT)).strip()
    if re.fullmatch(r"[0-9]+", value) is None:
        raise PublicationError("PUBLISH_SOURCE_EPOCH_INVALID")
    return int(value)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _materialize(data: bytes, representation: str) -> bytes:
    if representation == "raw":
        return data
    if representation == "crlf":
        return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    raise PublicationError("PUBLISH_MATERIALIZATION_INVALID")


def _write(root: Path, relative: str, data: bytes, mode: str) -> None:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise PublicationError("PUBLISH_PACKAGE_PATH_INVALID")
    path = root.joinpath(*pure.parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, int(mode, 8))


def _record(role: str, package_path: str, commit: str, source_path: str, blob: str, source: bytes, data: bytes, mode: str, target: str | None = None, materialization: str = "raw") -> dict:
    record = {
        "role": role,
        "packagePath": package_path,
        "sourceCommit": commit,
        "sourcePath": source_path,
        "gitBlob": blob,
        "sourceSha256": hashlib.sha256(source).hexdigest(),
        "materialization": materialization,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "mode": mode,
    }
    if target is not None:
        record["targetPath"] = target
    return record


def _safe_name(name: str, package: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != package:
        raise PublicationError("PACKAGE_ARCHIVE_PATH_REFUSED")
    return pure


def _tar(root: Path, archive: Path, epoch: int) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
                paths = [root] + sorted(root.rglob("*"), key=lambda p: p.relative_to(root.parent).as_posix())
                for path in paths:
                    info = tf.gettarinfo(str(path), arcname=path.relative_to(root.parent).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    if info.isdir():
                        info.mode = 0o755
                        tf.addfile(info)
                    elif info.isfile():
                        with path.open("rb") as handle:
                            tf.addfile(info, handle)
                    else:
                        raise PublicationError("PACKAGE_MEMBER_TYPE_REFUSED")


def _zip(root: Path, archive: Path) -> None:
    fixed = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.relative_to(root.parent).as_posix()):
            info = zipfile.ZipInfo(path.relative_to(root.parent).as_posix(), fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
            zf.writestr(info, path.read_bytes())


def _checksum(archive: Path) -> Path:
    path = archive.with_name(archive.name + ".sha256")
    path.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n", encoding="ascii")
    return path


def build_redrix(repo: Path, output: Path) -> tuple[Path, Path]:
    _assert_repo(repo)
    if output.exists():
        raise PublicationError("PUBLISH_OUTPUT_EXISTS")
    root = output / REDRIX_PACKAGE
    root.mkdir(parents=True)
    records = []
    for source_path, blob, target, mode in REDRIX_CURRENT:
        source = _blob(repo, SOURCE_COMMIT, source_path, blob)
        package_path = "payload/" + source_path
        _write(root, package_path, source, mode)
        records.append(_record("current", package_path, SOURCE_COMMIT, source_path, blob, source, source, mode, target))
    for source_path, blob, target, mode in REDRIX_ROLLBACK:
        source = _blob(repo, ROLLBACK_COMMIT, source_path, blob)
        package_path = "rollback/" + source_path
        _write(root, package_path, source, mode)
        records.append(_record("rollback", package_path, ROLLBACK_COMMIT, source_path, blob, source, source, mode, target))
    manifest = {
        "schemaVersion": 1,
        "artifact": REDRIX_PACKAGE,
        "sourceCommit": SOURCE_COMMIT,
        "sourceTree": SOURCE_TREE,
        "rollbackCommit": ROLLBACK_COMMIT,
        "rollbackTree": ROLLBACK_TREE,
        "sourceDateEpoch": _epoch(repo),
        "owner": OWNER,
        "containsCredential": False,
        "containsBootstrap": False,
        "containsPrivateKey": False,
        "authorizedKeysMutationAuthorized": False,
        "entries": sorted(records, key=lambda item: item["packagePath"]),
    }
    _write(root, "manifest.json", _canonical(manifest), "0600")
    archive = output / f"{REDRIX_PACKAGE}.tar.gz"
    _tar(root, archive, manifest["sourceDateEpoch"])
    return archive, _checksum(archive)


def build_ldw01(repo: Path, output: Path) -> tuple[Path, Path]:
    _assert_repo(repo)
    if output.exists():
        raise PublicationError("PUBLISH_OUTPUT_EXISTS")
    root = output / LDW01_PACKAGE
    root.mkdir(parents=True)
    records = []
    for commit, source_path, blob, representation in LDW01_FILES:
        source = _blob(repo, commit, source_path, blob)
        data = _materialize(source, representation)
        if source_path == "ci-dispatch/Dispatch.psm1":
            if hashlib.sha256(source).hexdigest() != DISPATCH_RAW_SHA256 or hashlib.sha256(data).hexdigest() != DISPATCH_WINDOWS_SHA256:
                raise PublicationError("PUBLISH_DISPATCH_SHA256_MISMATCH")
        _write(root, source_path, data, "0600")
        records.append(_record("runtime-source", source_path, commit, source_path, blob, source, data, "0600", materialization=representation))
    manifest = {
        "schemaVersion": 1,
        "artifact": LDW01_PACKAGE,
        "sourceCommit": SOURCE_COMMIT,
        "sourceTree": SOURCE_TREE,
        "dispatcherAuthority": {
            "commit": DISPATCH_COMMIT,
            "tree": DISPATCH_TREE,
            "blob": DISPATCH_BLOB,
            "rawSha256": DISPATCH_RAW_SHA256,
            "windowsSha256": DISPATCH_WINDOWS_SHA256,
            "materialization": "crlf",
        },
        "containsCredential": False,
        "containsBootstrap": False,
        "containsPrivateEndpoint": False,
        "entries": sorted(records, key=lambda item: item["packagePath"]),
    }
    _write(root, "manifest.json", _canonical(manifest), "0600")
    archive = output / f"{LDW01_PACKAGE}.zip"
    _zip(root, archive)
    return archive, _checksum(archive)


def _verify_checksum(archive: Path, checksum: Path) -> None:
    lines = checksum.read_text(encoding="ascii").splitlines()
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", lines[0]) if len(lines) == 1 else None
    if match is None or match.group(2) != archive.name:
        raise PublicationError("PACKAGE_CHECKSUM_INVALID")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != match.group(1):
        raise PublicationError("PACKAGE_CHECKSUM_MISMATCH")


def _verify_record(repo: Path, root: Path, record: dict, expected: tuple[str, str, str, str], commit: str, role: str, package_mode: int) -> None:
    source_path, blob, target, mode = expected
    keys = {"role", "packagePath", "sourceCommit", "sourcePath", "gitBlob", "sourceSha256", "materialization", "sha256", "size", "mode"}
    if target:
        keys.add("targetPath")
    if set(record) != keys or record["role"] != role or record["sourceCommit"] != commit or record["sourcePath"] != source_path or record["gitBlob"] != blob or record["mode"] != mode:
        raise PublicationError("PACKAGE_MANIFEST_PROVENANCE_MISMATCH")
    if target and record.get("targetPath") != target:
        raise PublicationError("PACKAGE_MANIFEST_TARGET_MISMATCH")
    source = _blob(repo, commit, source_path, blob)
    if hashlib.sha256(source).hexdigest() != record["sourceSha256"]:
        raise PublicationError("PACKAGE_SOURCE_HASH_MISMATCH")
    expected_data = _materialize(source, record["materialization"])
    path = root.joinpath(*PurePosixPath(record["packagePath"]).parts)
    if not path.is_file() or path.is_symlink():
        raise PublicationError("PACKAGE_FILE_INVALID")
    data = path.read_bytes()
    if data != expected_data or len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise PublicationError("PACKAGE_FILE_HASH_MISMATCH")
    if package_mode != int(mode, 8):
        raise PublicationError("PACKAGE_FILE_MODE_MISMATCH")


def verify_redrix(repo: Path, archive: Path, checksum: Path) -> dict:
    _assert_repo(repo)
    _verify_checksum(archive, checksum)
    expected = {"payload/" + p: ((p, b, t, m), SOURCE_COMMIT, "current") for p, b, t, m in REDRIX_CURRENT}
    expected.update({"rollback/" + p: ((p, b, t, m), ROLLBACK_COMMIT, "rollback") for p, b, t, m in REDRIX_ROLLBACK})
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        modes = {}
        with tarfile.open(archive, "r:gz") as tf:
            members = tf.getmembers()
            if not members:
                raise PublicationError("PACKAGE_ARCHIVE_EMPTY")
            for member in members:
                pure = _safe_name(member.name, REDRIX_PACKAGE)
                if not (member.isdir() or member.isfile()) or member.issym() or member.islnk():
                    raise PublicationError("PACKAGE_MEMBER_TYPE_REFUSED")
                if member.isfile():
                    modes[PurePosixPath(*pure.parts[1:]).as_posix()] = member.mode & 0o777
            tf.extractall(work, filter="data")
        root = work / REDRIX_PACKAGE
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise PublicationError("PACKAGE_MANIFEST_MISSING")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_keys = {"schemaVersion", "artifact", "sourceCommit", "sourceTree", "rollbackCommit", "rollbackTree", "sourceDateEpoch", "owner", "containsCredential", "containsBootstrap", "containsPrivateKey", "authorizedKeysMutationAuthorized", "entries"}
        if set(manifest) != expected_keys or manifest.get("schemaVersion") != 1 or manifest.get("artifact") != REDRIX_PACKAGE or manifest.get("sourceCommit") != SOURCE_COMMIT or manifest.get("sourceTree") != SOURCE_TREE or manifest.get("rollbackCommit") != ROLLBACK_COMMIT or manifest.get("rollbackTree") != ROLLBACK_TREE or manifest.get("owner") != OWNER or manifest.get("containsCredential") is not False or manifest.get("containsBootstrap") is not False or manifest.get("containsPrivateKey") is not False or manifest.get("authorizedKeysMutationAuthorized") is not False:
            raise PublicationError("PACKAGE_MANIFEST_PROVENANCE_MISMATCH")
        records = manifest.get("entries")
        if not isinstance(records, list) or {r.get("packagePath") for r in records} != set(expected) or len(records) != len(expected):
            raise PublicationError("PACKAGE_INVENTORY_DRIFT")
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        if actual != set(expected) | {"manifest.json"}:
            raise PublicationError("PACKAGE_INVENTORY_DRIFT")
        if modes.get("manifest.json") != 0o600:
            raise PublicationError("PACKAGE_FILE_MODE_MISMATCH")
        for record in records:
            spec, commit, role = expected[record["packagePath"]]
            _verify_record(repo, root, record, spec, commit, role, modes.get(record["packagePath"], -1))
        return manifest


def verify_ldw01(repo: Path, archive: Path, checksum: Path) -> dict:
    _assert_repo(repo)
    _verify_checksum(archive, checksum)
    specs = {path: ((path, blob, "", "0600"), commit, materialization) for commit, path, blob, materialization in LDW01_FILES}
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        modes = {}
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                pure = _safe_name(info.filename, LDW01_PACKAGE)
                mode_type = (info.external_attr >> 16) & 0o170000
                if info.is_dir() or mode_type not in (0, stat.S_IFREG):
                    if not info.is_dir():
                        raise PublicationError("PACKAGE_MEMBER_TYPE_REFUSED")
                else:
                    modes[PurePosixPath(*pure.parts[1:]).as_posix()] = (info.external_attr >> 16) & 0o777
            zf.extractall(work)
        root = work / LDW01_PACKAGE
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise PublicationError("PACKAGE_MANIFEST_MISSING")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_keys = {"schemaVersion", "artifact", "sourceCommit", "sourceTree", "dispatcherAuthority", "containsCredential", "containsBootstrap", "containsPrivateEndpoint", "entries"}
        authority = {"commit": DISPATCH_COMMIT, "tree": DISPATCH_TREE, "blob": DISPATCH_BLOB, "rawSha256": DISPATCH_RAW_SHA256, "windowsSha256": DISPATCH_WINDOWS_SHA256, "materialization": "crlf"}
        if set(manifest) != expected_keys or manifest.get("schemaVersion") != 1 or manifest.get("artifact") != LDW01_PACKAGE or manifest.get("sourceCommit") != SOURCE_COMMIT or manifest.get("sourceTree") != SOURCE_TREE or manifest.get("dispatcherAuthority") != authority or manifest.get("containsCredential") is not False or manifest.get("containsBootstrap") is not False or manifest.get("containsPrivateEndpoint") is not False:
            raise PublicationError("PACKAGE_MANIFEST_PROVENANCE_MISMATCH")
        records = manifest.get("entries")
        if not isinstance(records, list) or {r.get("packagePath") for r in records} != set(specs) or len(records) != len(specs):
            raise PublicationError("PACKAGE_INVENTORY_DRIFT")
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        if actual != set(specs) | {"manifest.json"}:
            raise PublicationError("PACKAGE_INVENTORY_DRIFT")
        if modes.get("manifest.json") != 0o600:
            raise PublicationError("PACKAGE_FILE_MODE_MISMATCH")
        for record in records:
            spec, commit, representation = specs[record["packagePath"]]
            if record.get("materialization") != representation:
                raise PublicationError("PACKAGE_MANIFEST_PROVENANCE_MISMATCH")
            _verify_record(repo, root, record, spec, commit, "runtime-source", modes.get(record["packagePath"], -1))
        dispatch = next(item for item in records if item["packagePath"] == "ci-dispatch/Dispatch.psm1")
        if dispatch["sourceSha256"] != DISPATCH_RAW_SHA256 or dispatch["sha256"] != DISPATCH_WINDOWS_SHA256:
            raise PublicationError("PUBLISH_DISPATCH_SHA256_MISMATCH")
        return manifest


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build-redrix", "build-ldw01"):
        child = sub.add_parser(name)
        child.add_argument("output", type=Path)
    for name in ("verify-redrix", "verify-ldw01"):
        child = sub.add_parser(name)
        child.add_argument("archive", type=Path)
        child.add_argument("checksum", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _args()
    try:
        if args.command == "build-redrix":
            archive, checksum = build_redrix(args.repo_root, args.output)
        elif args.command == "build-ldw01":
            archive, checksum = build_ldw01(args.repo_root, args.output)
        elif args.command == "verify-redrix":
            verify_redrix(args.repo_root, args.archive, args.checksum)
            print("REDRIX_CANARY_PACKAGE_VERIFY=PASS")
            return 0
        else:
            verify_ldw01(args.repo_root, args.archive, args.checksum)
            print("LDW01_CANARY_ADJUNCT_VERIFY=PASS")
            return 0
        print(f"PACKAGE_ARCHIVE={archive}")
        print(f"PACKAGE_CHECKSUM={checksum}")
        return 0
    except (PublicationError, OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "DRAGONFLY_CANARY_PUBLICATION_FAILED"
        print("PUBLICATION=FAIL")
        print(f"CLASSIFICATION={code}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
