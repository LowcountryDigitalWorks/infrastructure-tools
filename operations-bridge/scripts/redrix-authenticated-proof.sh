#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

EXPECTED_USER='eddie'
EXPECTED_BRIDGE_ID='dragonfly-redrix-01'
EXPECTED_RELAY_URI='wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01'
WORKER='ldw-operations-bridge-relay'
WORKER_ORIGIN='https://ldw-operations-bridge-relay.locodw.workers.dev'
PACKAGE_NAME='ldw-operations-bridge-dragonfly-linux-x64'
VERIFIER_COMMIT='9cfcd6c363e1f8fe625fb654f602bcf743b9d2ca'
VERIFIER_BLOB='18a147ae8f3dee38fb62ee8340bb279660141465'
VERIFIER_URL="https://raw.githubusercontent.com/LowcountryDigitalWorks/infrastructure-tools/${VERIFIER_COMMIT}/operations-bridge/scripts/redrix-credential-free-proof.sh"
INSTALL_ROOT="${HOME:-}/.local/lib/ldw/operations-bridge/dragonfly"
CONFIG_DIR="${HOME:-}/.config/ldw/operations-bridge/dragonfly"
CONFIG_PATH="$CONFIG_DIR/config.json"
STATE_DIR="${HOME:-}/.local/state/ldw/operations-bridge/dragonfly"
HEALTH_PATH="$STATE_DIR/health.json"
RUNTIME_DIR="/run/user/$(id -u)"
LOCK_PATH="$RUNTIME_DIR/ldw-operations-bridge-dragonfly.lock"
ENTRYPOINT="$INSTALL_ROOT/payload/LDW.OperationsBridge.Runner"
CONTROLLER="${HOME:-}/.local/lib/ldw-dragonfly-jit/dragonfly_jit.py"
CF_CONFIG="${HOME:-}/ldw-redrix-relay-deploy/wrangler.toml"

usage() {
  echo "usage: $0 <dragonfly-redrix-linux-x64-package.zip>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
command -v realpath >/dev/null 2>&1 || { echo 'ERROR:REQUIRED_TOOL_MISSING:realpath' >&2; exit 2; }
ZIP_PATH="$(realpath -- "$1")"
[[ -f "$ZIP_PATH" ]] || { echo 'ERROR:ARTIFACT_ZIP_MISSING' >&2; exit 2; }

for cmd in curl git python3 tar sha256sum stat id mktemp env rm npx; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR:REQUIRED_TOOL_MISSING:$cmd" >&2; exit 2; }
done
[[ -x /usr/bin/secret-tool ]] || { echo 'ERROR:REQUIRED_TOOL_MISSING:/usr/bin/secret-tool' >&2; exit 2; }
[[ -x /usr/bin/python3 ]] || { echo 'ERROR:REQUIRED_TOOL_MISSING:/usr/bin/python3' >&2; exit 2; }
[[ -n "${HOME:-}" && "$HOME" == /* ]] || { echo 'ERROR:HOME_INVALID' >&2; exit 1; }
[[ "$(id -u)" != '0' ]] || { echo 'ERROR:ROOT_USER_REFUSED' >&2; exit 1; }
[[ "$(id -un)" == "$EXPECTED_USER" ]] || { echo "ERROR:UNEXPECTED_USER:$(id -un)" >&2; exit 1; }
[[ -d "$RUNTIME_DIR" && ! -L "$RUNTIME_DIR" ]] || { echo 'ERROR:RUNTIME_DIR_INVALID' >&2; exit 1; }
[[ "$(stat -c '%a' "$RUNTIME_DIR")" == '700' ]] || { echo 'ERROR:RUNTIME_DIR_NOT_PRIVATE' >&2; exit 1; }
[[ -S "$RUNTIME_DIR/bus" ]] || { echo 'ERROR:DBUS_SESSION_SOCKET_MISSING' >&2; exit 1; }
[[ -f "$CF_CONFIG" && ! -L "$CF_CONFIG" ]] || { echo 'ERROR:CLOUDFLARE_CONFIG_MISSING' >&2; exit 1; }
[[ -f "$CONTROLLER" && ! -L "$CONTROLLER" ]] || { echo 'ERROR:DRAGONFLY_CONTROLLER_MISSING' >&2; exit 1; }

WORK="$(mktemp -d)"
SUCCESS=0
INSTALL_CREATED=0
CONFIG_CREATED=0
STATE_CREATED=0
BRIDGE_PID=''
SITE_TOKEN=''
CF_TOKEN=''
CF_ACCOUNT_ID=''

safe_remove_owned_path() {
  local target="$1"
  TARGET="$target" HOME_DIR="$HOME" python3 - <<'PY'
import os, shutil
from pathlib import Path
home=Path(os.environ['HOME_DIR']).resolve(strict=True)
target=Path(os.environ['TARGET'])
allowed={
    home/'.local/lib/ldw/operations-bridge/dragonfly',
    home/'.config/ldw/operations-bridge/dragonfly',
    home/'.local/state/ldw/operations-bridge/dragonfly',
}
if target not in allowed:
    raise SystemExit('ERROR:CLEANUP_PATH_MISMATCH')
if target.is_symlink():
    raise SystemExit('ERROR:CLEANUP_SYMLINK_REFUSED')
if target.exists():
    shutil.rmtree(target)
PY
}

remove_owned_lock() {
  if [[ -e "$LOCK_PATH" || -L "$LOCK_PATH" ]]; then
    [[ ! -L "$LOCK_PATH" && -f "$LOCK_PATH" ]] || { echo 'ERROR:LOCK_PATH_INVALID' >&2; return 1; }
    [[ "$(stat -c '%U' "$LOCK_PATH")" == "$EXPECTED_USER" ]] || { echo 'ERROR:LOCK_OWNER_INVALID' >&2; return 1; }
    rm -f -- "$LOCK_PATH"
  fi
}

stop_bridge_bounded() {
  if [[ -n "$BRIDGE_PID" ]] && kill -0 "$BRIDGE_PID" 2>/dev/null; then
    kill -INT "$BRIDGE_PID" 2>/dev/null || true
    local i
    for i in $(seq 1 12); do
      kill -0 "$BRIDGE_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$BRIDGE_PID" 2>/dev/null; then
      kill -TERM "$BRIDGE_PID" 2>/dev/null || true
      sleep 1
    fi
    wait "$BRIDGE_PID" 2>/dev/null || true
  fi
  BRIDGE_PID=''
  remove_owned_lock >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  stop_bridge_bounded
  SITE_TOKEN=''
  CF_TOKEN=''
  CF_ACCOUNT_ID=''
  unset SITE_TOKEN CF_TOKEN CF_ACCOUNT_ID
  if [[ $SUCCESS -ne 1 ]]; then
    /usr/bin/python3 "$CONTROLLER" drain >/dev/null 2>&1 || true
    if [[ $STATE_CREATED -eq 1 ]]; then safe_remove_owned_path "$STATE_DIR" >/dev/null 2>&1 || true; fi
    if [[ $CONFIG_CREATED -eq 1 ]]; then safe_remove_owned_path "$CONFIG_DIR" >/dev/null 2>&1 || true; fi
    if [[ $INSTALL_CREATED -eq 1 ]]; then safe_remove_owned_path "$INSTALL_ROOT" >/dev/null 2>&1 || true; fi
  fi
  rm -rf -- "$WORK"
  exit "$rc"
}
trap cleanup EXIT

bridge_process_count() {
  ENTRYPOINT="$ENTRYPOINT" python3 - <<'PY'
import os
from pathlib import Path
entry=os.environ['ENTRYPOINT'].encode()
count=0
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    try:
        argv=(proc/'cmdline').read_bytes().split(b'\0')
    except (OSError, PermissionError):
        continue
    if argv and argv[0] == entry:
        count += 1
print(count)
PY
}

controller_snapshot() {
  /usr/bin/python3 "$CONTROLLER" status
}

require_clean_stopped_snapshot() {
  local label="$1"
  local snapshot="$2"
  LABEL="$label" SNAPSHOT="$snapshot" python3 - <<'PY'
import json, os
label=os.environ['LABEL']
try:
    v=json.loads(os.environ['SNAPSHOT'])
except Exception as exc:
    raise SystemExit(f'ERROR:{label}_JSON_INVALID') from exc
if v.get('marker') != 'CI-RUNNER-DRAGONFLY-JIT-001':
    raise SystemExit(f'ERROR:{label}_MARKER_INVALID')
if v.get('state') != 'STOPPED':
    raise SystemExit(f"ERROR:{label}_STATE:{v.get('state')}")
if v.get('run_id') is not None or v.get('qemu_pid') is not None:
    raise SystemExit(f'ERROR:{label}_IDENTITY_PRESENT')
if v.get('residue_count') != 0:
    raise SystemExit(f"ERROR:{label}_RESIDUE:{v.get('residue_count')}")
if v.get('base_present') is not True:
    raise SystemExit(f'ERROR:{label}_BASE_MISSING')
print(label+'=PASS')
PY
}

echo '=== REDRIX AUTHENTICATED BRIDGE PROOF ==='

# This one-shot proof deliberately requires a clean post-#109 Bridge install state.
[[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || { echo 'ERROR:INSTALL_ROOT_PREEXISTS' >&2; exit 1; }
[[ ! -e "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || { echo 'ERROR:CONFIG_DIR_PREEXISTS' >&2; exit 1; }
[[ ! -e "$STATE_DIR" && ! -L "$STATE_DIR" ]] || { echo 'ERROR:STATE_DIR_PREEXISTS' >&2; exit 1; }
[[ ! -e "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || { echo 'ERROR:LOCK_PREEXISTS' >&2; exit 1; }
[[ "$(bridge_process_count)" == '0' ]] || { echo 'ERROR:BRIDGE_PROCESS_PREEXISTS' >&2; exit 1; }

BASELINE="$(controller_snapshot)"
require_clean_stopped_snapshot 'JIT_BASELINE' "$BASELINE"

# Reuse the accepted #120 verifier in artifact-only mode rather than duplicating
# package trust logic in this authenticated helper.
VERIFY_HELPER="$WORK/redrix-credential-free-proof.sh"
curl -fL --retry 3 --connect-timeout 8 --max-time 30 "$VERIFIER_URL" -o "$VERIFY_HELPER"
[[ "$(git hash-object "$VERIFY_HELPER")" == "$VERIFIER_BLOB" ]] || { echo 'ERROR:VERIFIER_BLOB_MISMATCH' >&2; exit 1; }
chmod 700 "$VERIFY_HELPER"
bash "$VERIFY_HELPER" "$ZIP_PATH" --artifact-only
echo 'ARTIFACT_ONLY_VERIFY=PASS'

# Extract the already-verified transport and install only its fixed package root.
ZIP_PATH="$ZIP_PATH" WORK="$WORK" PACKAGE_NAME="$PACKAGE_NAME" python3 - <<'PY'
import os, tarfile, zipfile
from pathlib import Path, PurePosixPath
zip_path=Path(os.environ['ZIP_PATH'])
work=Path(os.environ['WORK'])
package=os.environ['PACKAGE_NAME']
with zipfile.ZipFile(zip_path) as zf:
    archive_name=f'{package}.tar.gz'
    target=work/archive_name
    target.write_bytes(zf.read(archive_name))
extract=work/'extract'
extract.mkdir(mode=0o700)
with tarfile.open(target,'r:gz') as tf:
    for member in tf.getmembers():
        p=PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != package:
            raise SystemExit('ERROR:TAR_PATH_INVALID')
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit('ERROR:TAR_SPECIAL_MEMBER_REFUSED')
    tf.extractall(extract, filter='data')
root=extract/package
if not root.is_dir():
    raise SystemExit('ERROR:PACKAGE_ROOT_MISSING')
PY

INSTALL_CREATED=1
SOURCE_ROOT="$WORK/extract/$PACKAGE_NAME"
SOURCE_ROOT="$SOURCE_ROOT" INSTALL_ROOT="$INSTALL_ROOT" python3 - <<'PY'
import os, shutil
from pathlib import Path
src=Path(os.environ['SOURCE_ROOT'])
dst=Path(os.environ['INSTALL_ROOT'])
if dst.exists() or dst.is_symlink():
    raise SystemExit('ERROR:INSTALL_ROOT_PREEXISTS')
dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
shutil.copytree(src,dst,symlinks=False)
PY
[[ -x "$ENTRYPOINT" ]] || { echo 'ERROR:ENTRYPOINT_NOT_EXECUTABLE' >&2; exit 1; }
echo 'BRIDGE_PACKAGE_INSTALL=PASS'

CONFIG_CREATED=1
mkdir -p -m 700 "$CONFIG_DIR"
CONFIG_PATH="$CONFIG_PATH" BRIDGE_ID="$EXPECTED_BRIDGE_ID" RELAY_URI="$EXPECTED_RELAY_URI" python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['CONFIG_PATH'])
payload={'bridgeId':os.environ['BRIDGE_ID'],'relayConnectUri':os.environ['RELAY_URI']}
data=(json.dumps(payload,separators=(',',':'))+'\n').encode('utf-8')
fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
try:
    os.write(fd,data)
    os.fsync(fd)
finally:
    os.close(fd)
PY
[[ "$(stat -c '%a' "$CONFIG_PATH")" == '600' ]] || { echo 'ERROR:CONFIG_MODE_INVALID' >&2; exit 1; }
echo 'BRIDGE_CONFIG_INSTALL=PASS'

# Prove the Dragonfly bearer exists in Secret Service without exposing it.
echo '=== KEYRING LOOKUP GATE ==='
set +e
env -i \
  XDG_RUNTIME_DIR="$RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
  /usr/bin/secret-tool lookup service ldw-operations-bridge bridge-id "$EXPECTED_BRIDGE_ID" \
  2>/dev/null | python3 -c 'import sys; value=sys.stdin.buffer.read(4097); raise SystemExit(0 if value and len(value) <= 4096 else 1)'
KEYRING_PIPESTATUS=("${PIPESTATUS[@]}")
set -e
KEYRING_RC=${KEYRING_PIPESTATUS[0]}
KEYRING_CHECK_RC=${KEYRING_PIPESTATUS[1]}
[[ $KEYRING_RC -eq 0 && $KEYRING_CHECK_RC -eq 0 ]] || { echo 'ERROR:DRAGONFLY_KEYRING_LOOKUP_FAILED' >&2; exit 1; }
echo 'DRAGONFLY_KEYRING_LOOKUP=PASS'

# The first bootstrap Site token was intentionally not retained. Rotate only
# that bootstrap role to an in-memory proof value; never store it locally.
read -rsp 'Paste scoped Cloudflare API token: ' CF_TOKEN
echo
read -rp 'Paste Cloudflare Account ID: ' CF_ACCOUNT_ID

cf_wrangler() {
  (
    export CLOUDFLARE_API_TOKEN="$CF_TOKEN"
    export CLOUDFLARE_ACCOUNT_ID="$CF_ACCOUNT_ID"
    export WRANGLER_SEND_METRICS=false
    npx --yes wrangler@4.154.0 "$@"
  )
}

SECRET_LIST="$WORK/secret-list.json"
cf_wrangler secret list --name "$WORKER" --config "$CF_CONFIG" --format json >"$SECRET_LIST" 2>/dev/null
python3 - "$SECRET_LIST" <<'PY'
import json, sys
expected={'SITE_DISPATCH_TOKEN','BRIDGE_CLIENT_TOKEN','DRAGONFLY_BRIDGE_CLIENT_TOKEN'}
data=json.load(open(sys.argv[1],encoding='utf-8'))
names={x.get('name') for x in data if isinstance(x,dict)}
if names != expected:
    raise SystemExit('ERROR:CLOUDFLARE_SECRET_SET_DRIFT')
print('CLOUDFLARE_SECRET_SET_PRECHECK=PASS')
PY

SITE_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
[[ -n "$SITE_TOKEN" ]] || { echo 'ERROR:SITE_TOKEN_GENERATION_FAILED' >&2; exit 1; }
printf '%s' "$SITE_TOKEN" | cf_wrangler secret put SITE_DISPATCH_TOKEN --name "$WORKER" --config "$CF_CONFIG" >/dev/null 2>&1
echo 'BOOTSTRAP_SITE_TOKEN_ROTATION=PASS'

# Start the accepted Bridge in the foreground model, but under this one-shot
# supervisor so the proof can submit owner-control dispatches and stop cleanly.
STATE_CREATED=1
BRIDGE_STDOUT="$WORK/bridge.stdout"
BRIDGE_STDERR="$WORK/bridge.stderr"
bash -c 'trap - INT; exec "$1" --dragonfly-run' _ "$ENTRYPOINT" >"$BRIDGE_STDOUT" 2>"$BRIDGE_STDERR" &
BRIDGE_PID=$!

CONNECTED=0
LAST_STATE='unknown'
for _ in $(seq 1 30); do
  kill -0 "$BRIDGE_PID" 2>/dev/null || { echo 'ERROR:BRIDGE_EXITED_BEFORE_CONNECT' >&2; exit 1; }
  LAST_STATE="$($ENTRYPOINT --dragonfly-status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state","unknown"))' 2>/dev/null || echo unknown)"
  if [[ "$LAST_STATE" == 'connected' ]]; then
    CONNECTED=1
    break
  fi
  sleep 1
done
[[ $CONNECTED -eq 1 ]] || { echo "ERROR:BRIDGE_CONNECT_TIMEOUT:$LAST_STATE" >&2; exit 1; }
echo 'BRIDGE_AUTHENTICATED_CONNECT=PASS'

# Keep the Site bearer off argv/env/files. Python reads it from anonymous fd 3
# and owns the complete bounded HTTP proof sequence in memory.
python3 - "$WORKER_ORIGIN" 3<<<"$SITE_TOKEN" <<'PY'
import datetime as dt
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid

origin=sys.argv[1].rstrip('/')
token=os.read(3,4096).decode('ascii').strip()
if len(token) < 32:
    raise SystemExit('ERROR:SITE_TOKEN_INPUT_INVALID')

def request(method,path,payload=None,bearer=None):
    data=None if payload is None else json.dumps(payload,separators=(',',':')).encode()
    headers={'Authorization':'Bearer '+(token if bearer is None else bearer)}
    if data is not None:
        headers['Content-Type']='application/json'
    req=urllib.request.Request(origin+path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            raw=r.read(65536)
            code=r.status
    except urllib.error.HTTPError as e:
        code=e.code
        raw=e.read(65536)
    try:
        body=json.loads(raw.decode('utf-8')) if raw else {}
    except Exception:
        body={}
    return code,body

def iso(value):
    return value.isoformat(timespec='milliseconds').replace('+00:00','Z')

def envelope(operation,args=None,*,bridge='dragonfly-redrix-01',issued=None,ttl=60,dispatch_id=None,idem=None,corr=None):
    issued=issued or dt.datetime.now(dt.timezone.utc)
    return {
        'protocolVersion':'1.0',
        'dispatchId':dispatch_id or str(uuid.uuid4()),
        'bridgeId':bridge,
        'operation':operation,
        'args':{} if args is None else args,
        'idempotencyKey':idem or str(uuid.uuid4()),
        'correlationId':corr or str(uuid.uuid4()),
        'issuedAt':iso(issued),
        'expiresAt':iso(issued+dt.timedelta(seconds=ttl)),
    }

def submit(env,expected=200):
    code,body=request('POST','/relay/dragonfly/dispatch',env)
    if code != expected:
        raise SystemExit(f'ERROR:DISPATCH_HTTP:{code}:expected={expected}')
    return body

def poll(dispatch_id,timeout=20):
    deadline=time.time()+timeout
    while time.time() < deadline:
        code,body=request('GET','/relay/dragonfly/dispatch/'+dispatch_id)
        if code != 200:
            raise SystemExit(f'ERROR:RESULT_HTTP:{code}')
        if body.get('lifecycle') == 'terminal':
            return body
        time.sleep(0.4)
    raise SystemExit('ERROR:RESULT_TIMEOUT')

def pass_operation(operation,expected_state):
    env=envelope(operation)
    accepted=submit(env)
    dispatch_id=accepted.get('dispatchId')
    if dispatch_id != env['dispatchId']:
        raise SystemExit('ERROR:DISPATCH_ID_DRIFT')
    record=poll(dispatch_id)
    if record.get('terminal_status') != 'PASS':
        raise SystemExit(f"ERROR:TERMINAL_STATUS:{operation}:{record.get('terminal_status')}")
    try:
        payload=json.loads(record.get('terminal_payload_json') or '{}')
    except Exception as exc:
        raise SystemExit('ERROR:TERMINAL_PAYLOAD_INVALID') from exc
    if payload.get('state') != expected_state:
        raise SystemExit(f"ERROR:STATE:{operation}:{payload.get('state')}:expected={expected_state}")
    if operation == 'dragonfly.runner.status':
        if payload.get('residue_count') != '0' or payload.get('base_present') != 'true':
            raise SystemExit('ERROR:STATUS_CLEANLINESS_FAILED')
    return env,record

initial_env,_=pass_operation('dragonfly.runner.status','STOPPED')
print('REMOTE_STATUS_INITIAL=PASS')
pass_operation('dragonfly.runner.start','AVAILABLE')
print('REMOTE_START=PASS')
pass_operation('dragonfly.runner.status','AVAILABLE')
print('REMOTE_STATUS_AVAILABLE=PASS')
pass_operation('dragonfly.runner.drain','STOPPED')
print('REMOTE_DRAIN=PASS')
pass_operation('dragonfly.runner.status','STOPPED')
print('REMOTE_STATUS_FINAL=PASS')

# Replay/idempotency: exact duplicate must resolve to the original dispatch.
replay=submit(initial_env)
if replay.get('dispatchId') != initial_env['dispatchId']:
    raise SystemExit('ERROR:REPLAY_DISPATCH_DRIFT')
record=poll(initial_env['dispatchId'])
if record.get('terminal_status') != 'PASS':
    raise SystemExit('ERROR:REPLAY_TERMINAL_DRIFT')
print('REPLAY_SUPPRESSION=PASS')

bad=envelope('dragonfly.runner.status',bridge='dragonfly-redrix-unknown')
submit(bad,400)
print('UNKNOWN_BRIDGE_NEGATIVE=PASS')
bad=envelope('dragonfly.runner.recover')
submit(bad,400)
print('UNKNOWN_OPERATION_NEGATIVE=PASS')
bad=envelope('dragonfly.runner.status',{'unexpected':'value'})
submit(bad,400)
print('NONEMPTY_ARGS_NEGATIVE=PASS')
bad=envelope('dragonfly.runner.status')
bad.pop('args')
submit(bad,400)
print('OMITTED_ARGS_NEGATIVE=PASS')
issued=dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=10)
bad=envelope('dragonfly.runner.status',issued=issued,ttl=60)
submit(bad,400)
print('STALE_DISPATCH_NEGATIVE=PASS')
code,_=request('POST','/relay/dragonfly/dispatch',envelope('dragonfly.runner.status'),bearer=secrets.token_hex(32))
if code != 403:
    raise SystemExit(f'ERROR:WRONG_SITE_BEARER_HTTP:{code}')
print('WRONG_SITE_BEARER_NEGATIVE=PASS')
print('REMOTE_SEQUENCE_PHASE_ONE=PASS')
PY

# Stop the Bridge cleanly and prove the relay resolves an undeliverable dispatch
# to STALE after expiry rather than manufacturing success.
kill -INT "$BRIDGE_PID"
for _ in $(seq 1 12); do
  kill -0 "$BRIDGE_PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$BRIDGE_PID" 2>/dev/null && { echo 'ERROR:BRIDGE_DID_NOT_EXIT_CLEANLY' >&2; exit 1; }
set +e
wait "$BRIDGE_PID"
BRIDGE_RC=$?
set -e
BRIDGE_PID=''
[[ $BRIDGE_RC -eq 0 ]] || { echo "ERROR:BRIDGE_EXIT:$BRIDGE_RC" >&2; exit 1; }
remove_owned_lock
STOP_STATE="$($ENTRYPOINT --dragonfly-status | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state","unknown"))')"
[[ "$STOP_STATE" == 'stopped' ]] || { echo "ERROR:BRIDGE_FINAL_STATE:$STOP_STATE" >&2; exit 1; }
echo 'BRIDGE_CLEAN_EXIT=PASS'
sleep 2

python3 - "$WORKER_ORIGIN" 3<<<"$SITE_TOKEN" <<'PY'
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
origin=sys.argv[1].rstrip('/')
token=os.read(3,4096).decode('ascii').strip()

def call(method,path,payload=None):
    data=None if payload is None else json.dumps(payload,separators=(',',':')).encode()
    headers={'Authorization':'Bearer '+token}
    if data is not None: headers['Content-Type']='application/json'
    req=urllib.request.Request(origin+path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            return r.status,json.loads(r.read(65536).decode('utf-8'))
    except urllib.error.HTTPError as e:
        raw=e.read(65536)
        try: body=json.loads(raw.decode('utf-8'))
        except Exception: body={}
        return e.code,body
now=dt.datetime.now(dt.timezone.utc)
iso=lambda x:x.isoformat(timespec='milliseconds').replace('+00:00','Z')
dispatch_id=str(uuid.uuid4())
env={
 'protocolVersion':'1.0','dispatchId':dispatch_id,'bridgeId':'dragonfly-redrix-01',
 'operation':'dragonfly.runner.status','args':{},'idempotencyKey':str(uuid.uuid4()),
 'correlationId':str(uuid.uuid4()),'issuedAt':iso(now),'expiresAt':iso(now+dt.timedelta(seconds=4))
}
code,body=call('POST','/relay/dragonfly/dispatch',env)
if code != 200 or body.get('dispatchId') != dispatch_id:
    raise SystemExit(f'ERROR:DISCONNECT_DISPATCH:{code}')
time.sleep(6)
code,body=call('GET','/relay/dragonfly/dispatch/'+dispatch_id)
if code != 200 or body.get('terminal_status') != 'STALE':
    raise SystemExit(f"ERROR:DISCONNECT_RESOLUTION:{code}:{body.get('terminal_status')}")
print('DISCONNECT_EXPIRY_NEGATIVE=PASS')
PY

FINAL="$(controller_snapshot)"
require_clean_stopped_snapshot 'JIT_FINAL_STATE' "$FINAL"
[[ "$(bridge_process_count)" == '0' ]] || { echo 'ERROR:BRIDGE_PROCESS_RESIDUE' >&2; exit 1; }
[[ ! -e "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || { echo 'ERROR:BRIDGE_LOCK_RESIDUE' >&2; exit 1; }

SITE_TOKEN=''
CF_TOKEN=''
CF_ACCOUNT_ID=''
unset SITE_TOKEN CF_TOKEN CF_ACCOUNT_ID
SUCCESS=1
echo 'AUTHENTICATED_REDRIX_PROOF=PASS'
echo 'NO_AUTOSTART_SERVICE_SCHEDULE=PASS'
echo 'BOOTSTRAP_SITE_TOKEN_LOCAL_RETENTION=NONE'
