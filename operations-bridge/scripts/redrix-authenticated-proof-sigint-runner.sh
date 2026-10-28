#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

EXPECTED_RUNNER_COMMIT='6c53eed757c4a47296bd50dca4ec8f555f2b99c7'
EXPECTED_RUNNER_BLOB='a842fd90f020f85cb1d89bc22e8e211b9baea1e1'
RUNNER_URL="https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/${EXPECTED_RUNNER_COMMIT}/operations-bridge/scripts/redrix-authenticated-proof-curl-runner.sh"

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

SOURCE_RUNNER="$WORK/redrix-authenticated-proof-curl-runner.accepted.sh"
PATCHED_RUNNER="$WORK/redrix-authenticated-proof-curl-sigint.sh"

curl -fL --retry 3 --connect-timeout 8 --max-time 30 "$RUNNER_URL" -o "$SOURCE_RUNNER"
[[ "$(git hash-object "$SOURCE_RUNNER")" == "$EXPECTED_RUNNER_BLOB" ]] || {
  echo 'ERROR:ACCEPTED_CURL_RUNNER_BLOB_MISMATCH' >&2
  exit 1
}
echo 'ACCEPTED_CURL_RUNNER_PROVENANCE=PASS'

SOURCE_RUNNER="$SOURCE_RUNNER" PATCHED_RUNNER="$PATCHED_RUNNER" python3 - <<'PY'
import os
from pathlib import Path

src = Path(os.environ['SOURCE_RUNNER']).read_text(encoding='utf-8')

anchor = "if 'urllib.request' in src or 'urllib.error' in src:\n"
if src.count(anchor) != 1:
    raise SystemExit('ERROR:SIGINT_PATCH_ANCHOR_DRIFT')

insertion = r'''# Non-interactive Bash background jobs can inherit SIGINT as ignored. The
# nested shell in the accepted helper cannot reliably reset a disposition that
# was already ignored on shell entry. Reset SIGINT in GNU env immediately
# before exec so the Bridge's existing Console.CancelKeyPress cancellation path
# receives the proof's bounded kill -INT shutdown.
launch_old = "bash -c 'trap - INT; exec \"$1\" --dragonfly-run' _ \"$ENTRYPOINT\" >\"$BRIDGE_STDOUT\" 2>\"$BRIDGE_STDERR\" &"
launch_new = "env --default-signal=INT \"$ENTRYPOINT\" --dragonfly-run >\"$BRIDGE_STDOUT\" 2>\"$BRIDGE_STDERR\" &"
if src.count(launch_old) != 1:
    raise SystemExit(f'ERROR:SIGINT_LAUNCH_ANCHOR_COUNT:{src.count(launch_old)}')
src = src.replace(launch_old, launch_new, 1)

'''

src = src.replace(anchor, insertion + anchor, 1)

if src.count("env --default-signal=INT") != 1:
    raise SystemExit('ERROR:SIGINT_RESET_PATCH_COUNT')

Path(os.environ['PATCHED_RUNNER']).write_text(src, encoding='utf-8')
PY

chmod 700 "$PATCHED_RUNNER"
bash -n "$PATCHED_RUNNER"
echo 'SIGINT_RESET_RUNNER_RENDER=PASS'
echo 'SIGINT_RESET_LAUNCH_PATCH=PASS'

bash "$PATCHED_RUNNER" "$ZIP_PATH"
