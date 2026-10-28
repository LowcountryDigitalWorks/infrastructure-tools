#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

# Synthetic-only proof for the proposed unattended REDRIX credential path.
# REDRIX currently runs systemd 257, where upstream documents a known-broken
# per-user LoadCredentialEncrypted path. This proof therefore uses the system
# manager to decrypt a host-key-backed synthetic credential while executing the
# transient proof payload as the fixed normal user eddie (uid 1000).
#
# This helper NEVER reads, migrates, rotates, deletes, or exposes the real
# Operations Bridge bearer. It requires an already-existing root-only host
# credential key and refuses to create/setup one. Creation of that key remains
# a separate owner-authorized security action.

HOST_KEY='/var/lib/systemd/credential.secret'
CREDENTIAL_ID='dragonfly-bridge-token'
OWNER_USER='eddie'
OWNER_UID='1000'
OWNER_HOME='/home/eddie'
SYSTEMD_CREDS='/usr/bin/systemd-creds'
SYSTEMD_RUN='/usr/bin/systemd-run'
SYSTEMCTL='/usr/bin/systemctl'
PYTHON3='/usr/bin/python3'
TIMEOUT='/usr/bin/timeout'
SHA256SUM='/usr/bin/sha256sum'
STAT='/usr/bin/stat'

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

for cmd in id mktemp chmod rm find awk head tail tr; do
  command -v "$cmd" >/dev/null 2>&1 || fail "REQUIRED_TOOL_MISSING:$cmd"
done
for cmd in "$SYSTEMD_CREDS" "$SYSTEMD_RUN" "$SYSTEMCTL" "$PYTHON3" "$TIMEOUT" "$SHA256SUM" "$STAT"; do
  [[ -x "$cmd" ]] || fail 'REQUIRED_TOOL_MISSING'
done

[[ "$(id -u)" == '0' ]] || fail 'ROOT_REQUIRED_FOR_SYSTEM_MANAGER_PROOF'
[[ "$(id -u "$OWNER_USER")" == "$OWNER_UID" ]] || fail 'OWNER_UID_MISMATCH'

OWNER_USER="$OWNER_USER" OWNER_UID="$OWNER_UID" OWNER_HOME="$OWNER_HOME" "$PYTHON3" - <<'PY'
import os
import pwd

entry = pwd.getpwnam(os.environ['OWNER_USER'])
if entry.pw_uid != int(os.environ['OWNER_UID']) or entry.pw_dir != os.environ['OWNER_HOME']:
    raise SystemExit('ERROR:OWNER_ACCOUNT_MISMATCH')
print('OWNER_ACCOUNT=PASS')
PY

"$TIMEOUT" 5s "$SYSTEMCTL" show-environment >/dev/null 2>&1 \
  || fail 'SYSTEM_MANAGER_UNAVAILABLE'
echo 'SYSTEM_MANAGER=PASS'

read -r _ systemd_version _ < <("$SYSTEMD_CREDS" --version | head -n1)
[[ "$systemd_version" =~ ^[0-9]+$ ]] || fail 'SYSTEMD_VERSION_UNPARSEABLE'
(( systemd_version >= 257 )) || fail 'SYSTEMD_VERSION_TOO_OLD'
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

# Freeze identity + digest before encryption. systemd-creds may implicitly call
# setup if a host key is absent; this proof therefore requires the already-
# authorized key to remain the same object and bytes across the operation.
host_inode_before="$($STAT -Lc '%d:%i' "$HOST_KEY")"
host_digest_before="$($SHA256SUM "$HOST_KEY" | awk '{print $1}')"

# Read JIT state directly. Do not invoke the controller status command because
# its accepted implementation may ensure/create state roots.
jit_snapshot() {
  JIT_STATE_ROOT="$OWNER_HOME/.local/state/ldw-dragonfly-jit" "$PYTHON3" - <<'PY'
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

WORK="$(mktemp -d /run/ldw-systemd-cred-proof.XXXXXX)"
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

if ! printf '%s' "$SYNTHETIC" | "$SYSTEMD_CREDS" \
    --with-key=host \
    --name="$CREDENTIAL_ID" \
    encrypt - "$CIPHER" \
    >/dev/null 2>"$ENCRYPT_DIAG"; then
  fail 'SYSTEMD_SYSTEM_ENCRYPT_FAILED'
fi
SYNTHETIC=''
unset SYNTHETIC

[[ -f "$HOST_KEY" && ! -L "$HOST_KEY" ]] || fail 'HOST_CREDENTIAL_KEY_CHANGED'
host_inode_after="$($STAT -Lc '%d:%i' "$HOST_KEY")"
host_digest_after="$($SHA256SUM "$HOST_KEY" | awk '{print $1}')"
[[ "$host_inode_after" == "$host_inode_before" && "$host_digest_after" == "$host_digest_before" ]] \
  || fail 'HOST_CREDENTIAL_KEY_CHANGED'
echo 'HOST_CREDENTIAL_KEY_UNCHANGED=PASS'

[[ -s "$CIPHER" && -f "$CIPHER" && ! -L "$CIPHER" ]] || fail 'CIPHERTEXT_INVALID'
chmod 600 "$CIPHER"
echo 'SYSTEMD_SYSTEM_ENCRYPT=PASS'

actual_cli_digest="$({ "$SYSTEMD_CREDS" \
    --name="$CREDENTIAL_ID" \
    decrypt "$CIPHER" - 2>"$DECRYPT_DIAG"; } | "$SHA256SUM" | awk '{print $1}')" \
  || fail 'SYSTEMD_SYSTEM_DECRYPT_FAILED'
[[ "$actual_cli_digest" == "$expected_digest" ]] || fail 'SYSTEMD_SYSTEM_DECRYPT_DIGEST_MISMATCH'
echo 'SYSTEMD_SYSTEM_CLI_DECRYPT_DIGEST=PASS'

service_output="$($TIMEOUT 20s "$SYSTEMD_RUN" \
    --wait \
    --collect \
    --pipe \
    --quiet \
    --property="User=$OWNER_USER" \
    --property="LoadCredentialEncrypted=$CREDENTIAL_ID:$CIPHER" \
    --property='NoNewPrivileges=yes' \
    --property='PrivateTmp=yes' \
    --property='PrivateDevices=yes' \
    --property='ProtectSystem=strict' \
    --property='ProtectHome=yes' \
    --property='RestrictAddressFamilies=AF_UNIX' \
    "$PYTHON3" -c 'import hashlib, json, os; from pathlib import Path; d=os.environ.get("CREDENTIALS_DIRECTORY"); p=Path(d or "")/"dragonfly-bridge-token"; data=p.read_bytes(); print(json.dumps({"uid":os.geteuid(),"digest":hashlib.sha256(data).hexdigest()},separators=(",",":")))' \
    2>"$SERVICE_DIAG")" \
  || fail 'SYSTEMD_SYSTEM_SERVICE_CREDENTIAL_FAILED'

SERVICE_OUTPUT="$service_output" EXPECTED_DIGEST="$expected_digest" OWNER_UID="$OWNER_UID" "$PYTHON3" - <<'PY'
import json
import os

lines = [line for line in os.environ['SERVICE_OUTPUT'].splitlines() if line.strip()]
if not lines:
    raise SystemExit('ERROR:SYSTEM_SERVICE_OUTPUT_MISSING')
try:
    value = json.loads(lines[-1])
except Exception as exc:
    raise SystemExit('ERROR:SYSTEM_SERVICE_OUTPUT_INVALID') from exc
if set(value) != {'uid', 'digest'}:
    raise SystemExit('ERROR:SYSTEM_SERVICE_OUTPUT_FIELDS')
if value['uid'] != int(os.environ['OWNER_UID']):
    raise SystemExit('ERROR:SYSTEM_SERVICE_WRONG_UID')
if value['digest'] != os.environ['EXPECTED_DIGEST']:
    raise SystemExit('ERROR:SYSTEM_SERVICE_DIGEST_MISMATCH')
print('SYSTEMD_SYSTEM_SERVICE_USER=PASS')
print('SYSTEMD_SYSTEM_SERVICE_CREDENTIAL=PASS')
PY

rm -f -- "$CIPHER" "$ENCRYPT_DIAG" "$DECRYPT_DIAG" "$SERVICE_DIAG"
[[ -z "$(find "$WORK" -mindepth 1 -maxdepth 1 -print -quit)" ]] || fail 'SYNTHETIC_SECRET_RESIDUE'
echo 'SYNTHETIC_SECRET_RESIDUE=NONE'

after="$(jit_snapshot)"
require_clean_jit "$after"
[[ "$after" == "$before" ]] || fail 'JIT_STATE_CHANGED'
echo 'JIT_FINAL_STATE=PASS'

echo 'REAL_BRIDGE_BEARER_TOUCHED=no'
echo 'HOST_CREDENTIAL_KEY_CREATED=no'
echo 'PERSISTENT_SERVICE_CREATED=no'
echo 'SYSTEMD_CREDENTIAL_FEASIBILITY=PASS'
