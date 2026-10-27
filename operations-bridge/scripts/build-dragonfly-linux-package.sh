#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <source-commit> <source-date-epoch> [output-directory]" >&2
  exit 2
fi

SOURCE_COMMIT="$1"
SOURCE_DATE_EPOCH="$2"
OUTPUT_ROOT="${3:-${TMPDIR:-/tmp}/ldw-dragonfly-package}"

if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit must be an exact lowercase 40-character Git SHA" >&2
  exit 2
fi
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "source date epoch must be a non-negative integer" >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
PROJECT="$REPO_ROOT/operations-bridge/src/LDW.OperationsBridge.Runner/LDW.OperationsBridge.Runner.csproj"
PACKAGE_NAME="ldw-operations-bridge-dragonfly-linux-x64"
PACKAGE_ROOT="$OUTPUT_ROOT/$PACKAGE_NAME"
PAYLOAD_DIR="$PACKAGE_ROOT/payload"
ARCHIVE="$OUTPUT_ROOT/$PACKAGE_NAME.tar.gz"
ARCHIVE_SHA="$ARCHIVE.sha256"

rm -rf -- "$OUTPUT_ROOT"
mkdir -p -- "$PAYLOAD_DIR"

dotnet publish "$PROJECT" \
  --configuration Release \
  --runtime linux-x64 \
  --self-contained true \
  --output "$PAYLOAD_DIR" \
  --nologo \
  -p:ContinuousIntegrationBuild=true \
  -p:Deterministic=true \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -p:PublishSingleFile=false \
  -p:UseAppHost=true

ENTRYPOINT="$PAYLOAD_DIR/LDW.OperationsBridge.Runner"
if [[ ! -x "$ENTRYPOINT" ]]; then
  echo "self-contained Linux entrypoint was not produced" >&2
  exit 1
fi

# Normalize payload mtimes before hashing/archiving so repeated builds from the
# same exact source identity do not inherit wall-clock timestamps.
find "$PAYLOAD_DIR" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

SOURCE_COMMIT="$SOURCE_COMMIT" \
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
PAYLOAD_DIR="$PAYLOAD_DIR" \
PACKAGE_ROOT="$PACKAGE_ROOT" \
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

payload = Path(os.environ["PAYLOAD_DIR"])
package_root = Path(os.environ["PACKAGE_ROOT"])
records = []
for path in sorted(p for p in payload.rglob("*") if p.is_file()):
    relative = path.relative_to(payload).as_posix()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    records.append({"path": relative, "sha256": digest, "size": path.stat().st_size})

manifest = {
    "schemaVersion": 1,
    "artifact": "ldw-operations-bridge-dragonfly-linux-x64",
    "sourceCommit": os.environ["SOURCE_COMMIT"],
    "sourceDateEpoch": int(os.environ["SOURCE_DATE_EPOCH"]),
    "runtimeIdentifier": "linux-x64",
    "targetFramework": "net10.0",
    "selfContained": True,
    "installRoot": "~/.local/lib/ldw/operations-bridge/dragonfly",
    "entrypoint": "payload/LDW.OperationsBridge.Runner",
    "configurationPath": "~/.config/ldw/operations-bridge/dragonfly/config.json",
    "statePath": "~/.local/state/ldw/operations-bridge/dragonfly/health.json",
    "containsConfiguration": False,
    "containsCredential": False,
    "files": records,
}
(package_root / "manifest.json").write_text(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

touch -h -d "@${SOURCE_DATE_EPOCH}" "$PACKAGE_ROOT/manifest.json" "$PACKAGE_ROOT" "$PAYLOAD_DIR"

(
  cd -- "$OUTPUT_ROOT"
  tar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=gnu \
    -cf - "$PACKAGE_NAME" | gzip -n > "$ARCHIVE"
)

(
  cd -- "$OUTPUT_ROOT"
  sha256sum "$(basename -- "$ARCHIVE")" > "$(basename -- "$ARCHIVE_SHA")"
)

printf 'PACKAGE_ARCHIVE=%s\n' "$ARCHIVE"
printf 'PACKAGE_SHA256=%s\n' "$(cut -d ' ' -f1 "$ARCHIVE_SHA")"
printf 'PACKAGE_MANIFEST=%s\n' "$PACKAGE_ROOT/manifest.json"
