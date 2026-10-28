#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

EXPECTED_HELPER_COMMIT='bcd0e79c4f86433c474db66c9388bbea5148b799'
EXPECTED_HELPER_BLOB='69f8aaffb32352d4d539190a451ceb4f6c9d3499'
HELPER_URL="https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/${EXPECTED_HELPER_COMMIT}/operations-bridge/scripts/redrix-authenticated-proof.sh"

usage() {
  echo "usage: $0 <dragonfly-redrix-linux-x64-package.zip>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
ZIP_PATH="$(realpath -- "$1")"
[[ -f "$ZIP_PATH" ]] || { echo 'ERROR:ARTIFACT_ZIP_MISSING' >&2; exit 2; }

for cmd in bash curl git python3 mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR:REQUIRED_TOOL_MISSING:$cmd" >&2; exit 2; }
done

WORK="$(mktemp -d)"
cleanup() {
  local rc=$?
  trap - EXIT
  rm -rf -- "$WORK"
  exit "$rc"
}
trap cleanup EXIT

SOURCE_HELPER="$WORK/redrix-authenticated-proof.accepted.sh"
PATCHED_HELPER="$WORK/redrix-authenticated-proof.stabilized.sh"

curl -fL --retry 3 --connect-timeout 8 --max-time 30 "$HELPER_URL" -o "$SOURCE_HELPER"
[[ "$(git hash-object "$SOURCE_HELPER")" == "$EXPECTED_HELPER_BLOB" ]] || {
  echo 'ERROR:ACCEPTED_HELPER_BLOB_MISMATCH' >&2
  exit 1
}
echo 'ACCEPTED_HELPER_PROVENANCE=PASS'

SOURCE_HELPER="$SOURCE_HELPER" PATCHED_HELPER="$PATCHED_HELPER" python3 - <<'PY'
import os
from pathlib import Path

src = Path(os.environ['SOURCE_HELPER']).read_text(encoding='utf-8')
old = "echo 'BOOTSTRAP_SITE_TOKEN_ROTATION=PASS'\n\n# Start the accepted Bridge in the foreground model, but under this one-shot\n"
new = "echo 'BOOTSTRAP_SITE_TOKEN_ROTATION=PASS'\necho 'SITE_TOKEN_STABILIZATION_WAIT=12s'\nsleep 12\necho 'SITE_TOKEN_STABILIZATION_WAIT=PASS'\n\n# Start the accepted Bridge in the foreground model, but under this one-shot\n"
count = src.count(old)
if count != 1:
    raise SystemExit(f'ERROR:STABILIZATION_PATCH_ANCHOR_COUNT:{count}')
Path(os.environ['PATCHED_HELPER']).write_text(src.replace(old, new, 1), encoding='utf-8')
PY

chmod 700 "$PATCHED_HELPER"
bash -n "$PATCHED_HELPER"
echo 'STABILIZED_HELPER_RENDER=PASS'

bash "$PATCHED_HELPER" "$ZIP_PATH"
