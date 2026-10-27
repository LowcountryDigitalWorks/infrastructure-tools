#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
  echo "usage: $0 <archive.tar.gz> <archive.sha256> <expected-source-commit>" >&2
  exit 2
fi

ARCHIVE="$(realpath -- "$1")"
CHECKSUM="$(realpath -- "$2")"
EXPECTED_COMMIT="$3"

if [[ ! "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "expected source commit must be an exact lowercase 40-character Git SHA" >&2
  exit 2
fi
if [[ ! -f "$ARCHIVE" || ! -f "$CHECKSUM" ]]; then
  echo "archive and checksum must both exist" >&2
  exit 2
fi

ARCHIVE_DIR="$(dirname -- "$ARCHIVE")"
ARCHIVE_NAME="$(basename -- "$ARCHIVE")"
CHECKSUM_NAME="$(basename -- "$CHECKSUM")"
if [[ "$CHECKSUM_NAME" != "$ARCHIVE_NAME.sha256" ]]; then
  echo "checksum filename must be <archive>.sha256" >&2
  exit 1
fi

(
  cd -- "$ARCHIVE_DIR"
  sha256sum --check --strict -- "$CHECKSUM_NAME"
)

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

ARCHIVE="$ARCHIVE" WORK="$WORK" EXPECTED_COMMIT="$EXPECTED_COMMIT" python3 - <<'PY'
import hashlib
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath

archive = Path(os.environ["ARCHIVE"])
work = Path(os.environ["WORK"])
expected_commit = os.environ["EXPECTED_COMMIT"]
package_name = "ldw-operations-bridge-dragonfly-linux-x64"

with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit("package archive is empty")
    for member in members:
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise SystemExit("package archive contains an unsafe path")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("package archive contains a non-file/non-directory member")
        if not name.parts or name.parts[0] != package_name:
            raise SystemExit("package archive escaped its fixed package root")
    tf.extractall(work, filter="data")

root = work / package_name
manifest_path = root / "manifest.json"
payload = root / "payload"
if not manifest_path.is_file() or not payload.is_dir():
    raise SystemExit("package manifest/payload layout is invalid")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
expected_exact = {
    "schemaVersion": 1,
    "artifact": package_name,
    "sourceCommit": expected_commit,
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
    "requiredHostBinaries": ["/usr/bin/python3", "/usr/bin/secret-tool"],
    "requiredExternalAdapter": {
        "path": "~/.local/lib/ldw-dragonfly-jit/bridge_adapter.py",
        "gitBlob": "9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf",
    },
}
for key, expected in expected_exact.items():
    if manifest.get(key) != expected:
        raise SystemExit(f"manifest field {key!r} is invalid")

source_epoch = manifest.get("sourceDateEpoch")
if not isinstance(source_epoch, int) or source_epoch < 0:
    raise SystemExit("manifest sourceDateEpoch is invalid")

sdk_version = manifest.get("dotnetSdkVersion")
if not isinstance(sdk_version, str) or not re.fullmatch(r"[0-9][0-9A-Za-z.+-]{2,31}", sdk_version):
    raise SystemExit("manifest dotnetSdkVersion is invalid")

records = manifest.get("files")
if not isinstance(records, list) or not records:
    raise SystemExit("manifest file inventory is missing")

actual_files = sorted(p for p in payload.rglob("*") if p.is_file())
actual_names = [p.relative_to(payload).as_posix() for p in actual_files]
record_names = []
for record in records:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
        raise SystemExit("manifest file record schema is invalid")
    relative = record["path"]
    if not isinstance(relative, str):
        raise SystemExit("manifest file path is invalid")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise SystemExit("manifest file path escaped payload")
    path = payload / Path(*pure.parts)
    if not path.is_file():
        raise SystemExit(f"manifest file is missing: {relative}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise SystemExit(f"manifest digest mismatch: {relative}")
    if len(data) != record["size"]:
        raise SystemExit(f"manifest size mismatch: {relative}")
    record_names.append(relative)

if sorted(record_names) != actual_names or len(set(record_names)) != len(record_names):
    raise SystemExit("manifest inventory does not exactly match payload")

entrypoint = root / manifest["entrypoint"]
if not entrypoint.is_file() or not (entrypoint.stat().st_mode & stat.S_IXUSR):
    raise SystemExit("self-contained entrypoint is missing or not owner-executable")

for forbidden in (root / "config.json", payload / "config.json"):
    if forbidden.exists():
        raise SystemExit("package unexpectedly contains runtime configuration")

print(f"PACKAGE_VERIFY=PASS source={expected_commit} sdk={sdk_version} files={len(actual_files)}")
PY
