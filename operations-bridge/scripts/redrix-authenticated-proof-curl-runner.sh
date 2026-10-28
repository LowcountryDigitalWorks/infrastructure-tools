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
PATCHED_HELPER="$WORK/redrix-authenticated-proof.curl.sh"

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

# Preserve the previously reviewed post-secret stabilization gate.
wait_old = "echo 'BOOTSTRAP_SITE_TOKEN_ROTATION=PASS'\n\n# Start the accepted Bridge in the foreground model, but under this one-shot\n"
wait_new = "echo 'BOOTSTRAP_SITE_TOKEN_ROTATION=PASS'\necho 'SITE_TOKEN_STABILIZATION_WAIT=12s'\nsleep 12\necho 'SITE_TOKEN_STABILIZATION_WAIT=PASS'\n\n# Start the accepted Bridge in the foreground model, but under this one-shot\n"
if src.count(wait_old) != 1:
    raise SystemExit('ERROR:STABILIZATION_PATCH_ANCHOR_DRIFT')
src = src.replace(wait_old, wait_new, 1)

# Cloudflare Browser Integrity Check can reject the default Python urllib client
# at workers.dev before Worker code executes. Keep envelope construction/parsing
# in Python, but send HTTP with curl. The bearer is supplied to curl only through
# stdin via --header @-, never argv, environment, or a plaintext file.
imports_old = "import sys\nimport time\nimport urllib.error\nimport urllib.request\nimport uuid"
imports_new = "import subprocess\nimport sys\nimport time\nimport uuid"
if src.count(imports_old) != 2:
    raise SystemExit(f'ERROR:URLLIB_IMPORT_ANCHOR_COUNT:{src.count(imports_old)}')
src = src.replace(imports_old, imports_new)

request_start = src.index("def request(method,path,payload=None,bearer=None):\n")
request_end = src.index("\ndef iso(value):", request_start)
request_new = r'''def request(method,path,payload=None,bearer=None):
    data=None if payload is None else json.dumps(payload,separators=(',',':')).encode('utf-8')
    supplied=token if bearer is None else bearer
    argv=[
        'curl','--silent','--show-error','--connect-timeout','5','--max-time','10',
        '--request',method,'--header','@-','--output','-',
        '--write-out','\n__LDW_HTTP_STATUS__:%{http_code}'
    ]
    if data is not None:
        argv.extend(['--header','Content-Type: application/json','--data-binary',data.decode('utf-8')])
    argv.append(origin+path)
    try:
        result=subprocess.run(
            argv,
            input=('Authorization: Bearer '+supplied+'\n').encode('utf-8'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit('ERROR:CURL_TIMEOUT') from exc
    if result.returncode != 0:
        raise SystemExit(f'ERROR:CURL_EXIT:{result.returncode}')
    marker=b'\n__LDW_HTTP_STATUS__:'
    raw,sep,code_raw=result.stdout.rpartition(marker)
    if not sep:
        raise SystemExit('ERROR:CURL_STATUS_MISSING')
    try:
        code=int(code_raw.decode('ascii').strip())
    except Exception as exc:
        raise SystemExit('ERROR:CURL_STATUS_INVALID') from exc
    try:
        body=json.loads(raw.decode('utf-8')) if raw else {}
    except Exception:
        body={}
    return code,body
'''
src = src[:request_start] + request_new + src[request_end:]

call_start = src.index("def call(method,path,payload=None):\n")
call_end = src.index("\nnow=dt.datetime.now(dt.timezone.utc)", call_start)
call_new = r'''def call(method,path,payload=None):
    data=None if payload is None else json.dumps(payload,separators=(',',':')).encode('utf-8')
    argv=[
        'curl','--silent','--show-error','--connect-timeout','5','--max-time','10',
        '--request',method,'--header','@-','--output','-',
        '--write-out','\n__LDW_HTTP_STATUS__:%{http_code}'
    ]
    if data is not None:
        argv.extend(['--header','Content-Type: application/json','--data-binary',data.decode('utf-8')])
    argv.append(origin+path)
    try:
        result=subprocess.run(
            argv,
            input=('Authorization: Bearer '+token+'\n').encode('utf-8'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit('ERROR:CURL_TIMEOUT') from exc
    if result.returncode != 0:
        raise SystemExit(f'ERROR:CURL_EXIT:{result.returncode}')
    marker=b'\n__LDW_HTTP_STATUS__:'
    raw,sep,code_raw=result.stdout.rpartition(marker)
    if not sep:
        raise SystemExit('ERROR:CURL_STATUS_MISSING')
    try:
        code=int(code_raw.decode('ascii').strip())
    except Exception as exc:
        raise SystemExit('ERROR:CURL_STATUS_INVALID') from exc
    try:
        body=json.loads(raw.decode('utf-8')) if raw else {}
    except Exception:
        body={}
    return code,body
'''
src = src[:call_start] + call_new + src[call_end:]

if 'urllib.request' in src or 'urllib.error' in src:
    raise SystemExit('ERROR:URLLIB_REFERENCE_REMAINS')
if src.count("'--header','@-'") != 2:
    raise SystemExit('ERROR:CURL_STDIN_HEADER_PATCH_COUNT')

Path(os.environ['PATCHED_HELPER']).write_text(src, encoding='utf-8')
PY

chmod 700 "$PATCHED_HELPER"
bash -n "$PATCHED_HELPER"
echo 'CURL_TRANSPORT_HELPER_RENDER=PASS'
echo 'CURL_BEARER_STDIN_ONLY=PASS'

bash "$PATCHED_HELPER" "$ZIP_PATH"
