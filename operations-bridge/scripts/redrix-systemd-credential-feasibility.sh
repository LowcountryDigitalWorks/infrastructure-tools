#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

# Synthetic-only proof for the proposed unattended REDRIX credential path.
# This helper NEVER creates /var/lib/systemd/credential.secret and NEVER reads
# or migrates the real Operations Bridge bearer. A separately authorized owner
# action must create the root-only host credential key before this proof can pass.

HOST_KEY='/var/lib/systemd/credential.secret'
CREDENTIAL_ID='dragonfly-bridge-token'
SYSTEMD_CREDS='/usr/bin/systemd-creds'
SYSTEMD_RUN='/usr/bin/systemd-run'
SYSTEMCTL='/usr/bin/systemctl'
PYTHON3='/usr/bin/python3'
TIMEOUT='/usr/bin/timeout'
SHA256SUM='/usr/bin/sha256sum'

WORK=''
SYNTHETIC=''
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  SYNTHETIC=''
  unset SYNTHETIC
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    rm -rf -- "$WORK"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'ERROR:%s\n' "$1" >&2
  exit 1
}

[[ "$(id -u)" != '0' ]] || fail 'ROOT_USER_REFUSED'

for cmd in "$SYSTEMD_CREDS" "$SYSTEMD_RUN" "$SYSTEMCTL" "$PYTHON3" "$TIMEOUT" "$SHA256SUM"; do
  [[ -x "$cmd" ]] || fail 'REQUIRED_TOOL_MISSING'
done

runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
[[ "$runtime_dir" == "/run/user/$(id -u)" ]] || fail 'XDG_RUNTIME_DIR_UNEXPECTED'
[[ -d "$runtime_dir" && ! -L "$runtime_dir" ]] || fail 'USER_RUNTIME_DIR_INVALID'

RUNTIME_DIR="$runtime_dir" "$PYTHON3" - <<'PY'
import os
import stat
from pathlib import Path

path = Path(os.environ['RUNTIME_DIR'])
st = path.stat()
if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
    raise SystemExit('ERROR:USER_RUNTIME_DIR_NOT_PRIVATE')
print('USER_RUNTIME_DIR=PASS')
PY

"$TIMEOUT" 5s "$SYSTEMCTL" --user show-environment >/dev/null 2>&1 \
  || fail 'USER_SYSTEMD_UNAVAILABLE'
echo 'USER_SYSTEMD=PASS'

read -r _ systemd_version _ < <("$SYSTEMD_CREDS" --version | head -n1)
[[ "$systemd_version" =~ ^[0-9]+$ ]] || fail 'SYSTEMD_VERSION_UNPARSEABLE'
(( systemd_version >= 256 )) || fail 'SYSTEMD_VERSION_TOO_OLD'
echo "SYSTEMD_VERSION=$systemd_version"

[[ -f "$HOST_KEY" && ! -L "$HOST_KEY" ]] || fail 'HOST_CREDENTIAL_KEY_MISSING'
HOST_KEY="$HOST_KEY" "$PYTHON3" - <<'PY'
import os
import stat
from pathlib import Path

path = Path(os.environ['HOST_KEY'])
st = path.stat()
if not stat.S_ISREG(st.st_mode):
    raise SystemExit('ERROR:HOST_CREDENTIAL_KEY_NOT_REGULAR')
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o077:
    raise SystemExit('ERROR:HOST_CREDENTIAL_KEY_PERMISSIONS')
print('HOST_CREDENTIAL_KEY=PASS')
PY

# Read JIT state directly. Do not invoke the controller status command because
# its accepted implementation may ensure/create state roots.
jit_snapshot() {
  JIT_STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/ldw-dragonfly-jit" "$PYTHON3" - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ['JIT_STATE_ROOT']).absolute()
status_path = root / 'status.json'
runs_root = root / 'runs'
value = {
    'schema': 1,
    'marker': 'CI-RUNNER-DRAGONFLY-JIT-001',
    'state': 'STOPPED',
    'run_id': None,
    'qemu_pid': None,
}
if status_path.exists() or status_path.is_symlink():
    if status_path.is_symlink() or not status_path.is_file():
        raise SystemExit('ERROR:JIT_STATUS_PATH_INVALID')
    value = json.loads(status_path.read_text(encoding='utf-8'))
if value.get('schema') != 1 or value.get('marker') != 'CI-RUNNER-DRAGONFLY-JIT-001':
    raise SystemExit('ERROR:JIT_STATUS_CONTRACT_INVALID')
residue = 0
if runs_root.exists():
    if runs_root.is_symlink() or not runs_root.is_dir():
        raise SystemExit('ERROR:JIT_RUNS_ROOT_INVALID')
    residue = sum(1 for entry in runs_root.iterdir())
print(json.dumps({
    'state': value.get('state'),
    'run_id': value.get('run_id'),
    'qemu_pid': value.get('qemu_pid'),
    'residue_count': residue,
}, separators=(',', ':')))
PY
}

require_clean_jit() {
  SNAPSHOT="$1" "$PYTHON3" - <<'PY'
import json
import os

v = json.loads(os.environ['SNAPSHOT'])
ok = (
    v.get('state') == 'STOPPED'
    and v.get('run_id') is None
    and v.get('qemu_pid') is None
    and v.get('residue_count') == 0
)
if not ok:
    raise SystemExit('ERROR:JIT_NOT_CLEAN_STOPPED')
PY
}

before="$(jit_snapshot)"
require_clean_jit "$before"
echo 'JIT_BASELINE=PASS'

WORK="$(mktemp -d "$runtime_dir/ldw-systemd-cred-proof.XXXXXX")"
chmod 700 "$WORK"
CIPHER="$WORK/$CREDENTIAL_ID.cred"
ENCRYPT_DIAG="$WORK/encrypt.stderr"
DECRYPT_DIAG="$WORK/decrypt.stderr"
SERVICE_DIAG="$WORK/service.stderr"

SYNTHETIC="$($PYTHON3 - <<'PY'
import secrets
print(secrets.token_hex(32), end='')
PY
)"
expected_digest="$(printf '%s' "$SYNTHETIC" | "$SHA256SUM" | awk '{print $1}')"

if ! printf '%s' "$SYNTHETIC" | "$SYSTEMD_CREDS" encrypt \
    --user \
    --with-key=host \
    --name="$CREDENTIAL_ID" \
    - "$CIPHER" \
    >/dev/null 2>"$ENCRYPT_DIAG"; then
  fail 'SYSTEMD_USER_ENCRYPT_FAILED'
fi
SYNTHETIC=''
unset SYNTHETIC

[[ -s "$CIPHER" && -f "$CIPHER" && ! -L "$CIPHER" ]] || fail 'CIPHERTEXT_INVALID'
chmod 600 "$CIPHER"
echo 'SYSTEMD_USER_ENCRYPT=PASS'

actual_cli_digest="$({ "$SYSTEMD_CREDS" decrypt \
    --user \
    --name="$CREDENTIAL_ID" \
    "$CIPHER" - 2>"$DECRYPT_DIAG"; } | "$SHA256SUM" | awk '{print $1}')" \
  || fail 'SYSTEMD_USER_DECRYPT_FAILED'
[[ "$actual_cli_digest" == "$expected_digest" ]] || fail 'SYSTEMD_USER_DECRYPT_DIGEST_MISMATCH'
echo 'SYSTEMD_USER_CLI_DECRYPT_DIGEST=PASS'

service_output="$($TIMEOUT 20s "$SYSTEMD_RUN" \
    --user \
    --wait \
    --collect \
    --pipe \
    --quiet \
    --property="LoadCredentialEncrypted=$CREDENTIAL_ID:$CIPHER" \
    "$PYTHON3" -c 'import hashlib, os; from pathlib import Path; d=os.environ.get("CREDENTIALS_DIRECTORY"); p=Path(d or "")/"dragonfly-bridge-token"; data=p.read_bytes(); print(hashlib.sha256(data).hexdigest())' \
    2>"$SERVICE_DIAG")" \
  || fail 'SYSTEMD_USER_SERVICE_CREDENTIAL_FAILED'

service_digest="$(printf '%s\n' "$service_output" | tail -n1 | tr -d '\r\n')"
[[ "$service_digest" == "$expected_digest" ]] || fail 'SYSTEMD_USER_SERVICE_DIGEST_MISMATCH'
echo 'SYSTEMD_USER_SERVICE_CREDENTIAL=PASS'

rm -f -- "$CIPHER" "$ENCRYPT_DIAG" "$DECRYPT_DIAG" "$SERVICE_DIAG"
[[ -z "$(find "$WORK" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail 'SYNTHETIC_SECRET_RESIDUE'
echo 'SYNTHETIC_SECRET_RESIDUE=NONE'

after="$(jit_snapshot)"
require_clean_jit "$after"
[[ "$after" == "$before" ]] || fail 'JIT_STATE_CHANGED'
echo 'JIT_FINAL_STATE=PASS'

echo 'REAL_BRIDGE_BEARER_TOUCHED=no'
echo 'HOST_CREDENTIAL_KEY_CREATED=no'
echo 'SYSTEMD_CREDENTIAL_FEASIBILITY=PASS'
