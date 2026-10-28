#!/usr/bin/env bash
set -euo pipefail
umask 077

ORIGINAL_ARTIFACT_ZIP_SHA256='e0091c03c7a0e0c3bdf01c51e8c29fcf70e51788c1a9d3d84a91226cea6b01d4'
EXPECTED_TAR_SHA256='27835aad28f13723c831ad4c8d0c5b8a2110cb22eb55e1387199eb8fff960f71'
EXPECTED_SOURCE_COMMIT='bcbdfb181f18eacfbceef2bf990c07a0b612915a'
EXPECTED_ADAPTER_BLOB='9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf'
EXPECTED_BASE_SHA512='3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e'
EXPECTED_BRIDGE_ID='dragonfly-redrix-01'
EXPECTED_RELAY_URI='wss://ldw-operations-bridge-relay.locodw.workers.dev/relay/connect?bridgeId=dragonfly-redrix-01'
PACKAGE_NAME='ldw-operations-bridge-dragonfly-linux-x64'
EXPECTED_USER='eddie'

usage() {
  cat >&2 <<USAGE
usage: $0 <dragonfly-redrix-linux-x64-package.zip> [--artifact-only]

Default mode performs the bounded credential-free REDRIX proof. It temporarily
installs only the accepted package + exact non-secret config, requires no real
Bridge credential to be available, expects --dragonfly-run to exit 6/blocked,
verifies the Dragonfly JIT controller remains STOPPED/clean, and rolls back only
artifacts that this helper created.

The outer ZIP is only a transport container and may be reproduced after the
original Actions artifact expires. Trust is bound to the exact three-member ZIP
layout plus the deterministic inner package SHA/manifest/provenance.

--artifact-only verifies the accepted package and performs no device proof.
USAGE
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
command -v realpath >/dev/null 2>&1 || { echo 'ERROR:REQUIRED_TOOL_MISSING:realpath' >&2; exit 2; }
ZIP_PATH="$(realpath -- "$1")"
MODE="${2:-}"
[[ -f "$ZIP_PATH" ]] || { echo 'ERROR:ARTIFACT_ZIP_MISSING' >&2; exit 2; }
[[ -z "$MODE" || "$MODE" == '--artifact-only' ]] || usage

for cmd in sha256sum sha512sum python3 tar stat awk id mktemp env rm rmdir dirname; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR:REQUIRED_TOOL_MISSING:$cmd" >&2; exit 2; }
done

WORK="$(mktemp -d)"
INSTALL_ROOT="${HOME:-}/.local/lib/ldw/operations-bridge/dragonfly"
CONFIG_DIR="${HOME:-}/.config/ldw/operations-bridge/dragonfly"
CONFIG_PATH="$CONFIG_DIR/config.json"
STATE_DIR="${HOME:-}/.local/state/ldw/operations-bridge/dragonfly"
HEALTH_PATH="$STATE_DIR/health.json"
RUNTIME_UID="$(id -u)"
RUNTIME_DIR="/run/user/$RUNTIME_UID"
LOCK_PATH="$RUNTIME_DIR/ldw-operations-bridge-dragonfly.lock"
ENTRYPOINT="$INSTALL_ROOT/payload/LDW.OperationsBridge.Runner"
ADAPTER="${HOME:-}/.local/lib/ldw-dragonfly-jit/bridge_adapter.py"
CONTROLLER="${HOME:-}/.local/lib/ldw-dragonfly-jit/dragonfly_jit.py"
OWNER_CONTROLS="${HOME:-}/.local/lib/ldw-dragonfly-jit/owner_controls.py"
BASE="${XDG_DATA_HOME:-${HOME:-}/.local/share}/ldw-jit/base/debian-13-genericcloud-amd64.qcow2"
DESKTOP_DIR="${HOME:-}/.local/share/applications"
JIT_STATE_ROOT="${XDG_STATE_HOME:-${HOME:-}/.local/state}/ldw-dragonfly-jit"

INSTALL_CREATED=0
CONFIG_CREATED=0
HEALTH_CREATED=0
LOCK_CREATED=0
CREATED_DIRS_FILE="$WORK/created-dirs.txt"
: > "$CREATED_DIRS_FILE"

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
        raw=(proc/'cmdline').read_bytes()
    except (OSError, PermissionError):
        continue
    argv=raw.split(b'\0')
    if argv and argv[0] == entry:
        count += 1
print(count)
PY
}

jit_status_snapshot() {
  JIT_STATE_ROOT="$JIT_STATE_ROOT" BASE="$BASE" python3 - <<'PY'
import json, os, uuid
from pathlib import Path
root=Path(os.environ['JIT_STATE_ROOT']).absolute()
status_path=root/'status.json'
runs_root=root/'runs'
base=Path(os.environ['BASE']).absolute()
if root.is_symlink(): raise SystemExit('ERROR:JIT_STATE_ROOT_SYMLINK')
value={
 'schema':1,'marker':'CI-RUNNER-DRAGONFLY-JIT-001','state':'STOPPED',
 'updated_at':None,'run_id':None,'qemu_pid':None,'reason':None,
}
if status_path.exists() or status_path.is_symlink():
    if status_path.is_symlink() or not status_path.is_file(): raise SystemExit('ERROR:JIT_STATUS_PATH_INVALID')
    try: value=json.loads(status_path.read_text(encoding='utf-8'))
    except Exception as exc: raise SystemExit('ERROR:JIT_STATUS_JSON_INVALID') from exc
    if not isinstance(value,dict): raise SystemExit('ERROR:JIT_STATUS_OBJECT_REQUIRED')
allowed={'schema','marker','state','updated_at','run_id','qemu_pid','reason'}
if set(value)-allowed: raise SystemExit('ERROR:JIT_STATUS_FIELDS_INVALID')
if value.get('schema')!=1 or value.get('marker')!='CI-RUNNER-DRAGONFLY-JIT-001': raise SystemExit('ERROR:JIT_STATUS_CONTRACT_INVALID')
state=value.get('state')
if state not in {'STOPPED','AVAILABLE','RUNNING','DRAINING','HOLD','FAILED'}: raise SystemExit('ERROR:JIT_STATUS_STATE_INVALID')
run_id=value.get('run_id')
if run_id is not None:
    try: uuid.UUID(run_id)
    except Exception as exc: raise SystemExit('ERROR:JIT_STATUS_RUN_ID_INVALID') from exc
qemu=value.get('qemu_pid')
if qemu is not None and (not isinstance(qemu,int) or isinstance(qemu,bool) or qemu<=0): raise SystemExit('ERROR:JIT_STATUS_PID_INVALID')
if qemu is not None and run_id is None: raise SystemExit('ERROR:JIT_STATUS_IDENTITY_INVALID')
if state in {'STOPPED','AVAILABLE'} and (run_id is not None or qemu is not None): raise SystemExit('ERROR:JIT_STATUS_IDENTITY_INVALID')
if state == 'RUNNING' and (run_id is None or qemu is None): raise SystemExit('ERROR:JIT_STATUS_IDENTITY_INVALID')
if state == 'DRAINING' and ((run_id is None) != (qemu is None)): raise SystemExit('ERROR:JIT_STATUS_IDENTITY_INVALID')
if runs_root.is_symlink(): raise SystemExit('ERROR:JIT_RUNS_ROOT_SYMLINK')
residue=0
if runs_root.exists():
    if not runs_root.is_dir(): raise SystemExit('ERROR:JIT_RUNS_ROOT_INVALID')
    for entry in runs_root.iterdir():
        if entry.is_symlink() or not entry.is_dir(): raise SystemExit('ERROR:JIT_RUN_ROOT_CONTAMINATED')
        residue += 1
base_present=base.is_file() and not base.is_symlink()
out={
 'marker':'CI-RUNNER-DRAGONFLY-JIT-001',
 'state':state,
 'run_id':run_id,
 'qemu_pid':qemu,
 'residue_count':residue,
 'base_present':base_present,
}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
PY
}

safe_remove_created_tree() {
  local path="$1"
  TARGET="$path" HOME_DIR="$HOME" python3 - <<'PY'
import os, shutil
from pathlib import Path
p=Path(os.environ['TARGET'])
home=Path(os.environ['HOME_DIR']).resolve(strict=True)
expected=(home/'.local/lib/ldw/operations-bridge/dragonfly')
if p != expected:
    raise SystemExit('ERROR:CLEANUP_INSTALL_PATH_MISMATCH')
if p.is_symlink():
    raise SystemExit('ERROR:CLEANUP_INSTALL_SYMLINK')
if p.exists():
    shutil.rmtree(p)
PY
}

cleanup() {
  local rc="${1:-0}"
  local cleanup_failed=0
  set +e
  local procs
  procs="$(bridge_process_count 2>/dev/null || echo 1)"
  if [[ "$procs" != '0' ]]; then
    echo 'CLEANUP_BLOCKED=BRIDGE_PROCESS_STILL_PRESENT' >&2
    echo "MANUAL_REVIEW_INSTALL_ROOT=$INSTALL_ROOT" >&2
    cleanup_failed=1
  else
    if [[ $LOCK_CREATED -eq 1 && -e "$LOCK_PATH" ]]; then
      if [[ -L "$LOCK_PATH" ]]; then
        echo 'CLEANUP_BLOCKED=LOCK_SYMLINK' >&2
        cleanup_failed=1
      elif ! rm -f -- "$LOCK_PATH"; then
        echo 'CLEANUP_BLOCKED=LOCK_REMOVE_FAILED' >&2
        cleanup_failed=1
      fi
    fi
    if [[ $HEALTH_CREATED -eq 1 && -e "$HEALTH_PATH" ]]; then
      if [[ -L "$HEALTH_PATH" ]]; then
        echo 'CLEANUP_BLOCKED=HEALTH_SYMLINK' >&2
        cleanup_failed=1
      elif ! rm -f -- "$HEALTH_PATH"; then
        echo 'CLEANUP_BLOCKED=HEALTH_REMOVE_FAILED' >&2
        cleanup_failed=1
      fi
    fi
    if [[ $CONFIG_CREATED -eq 1 && -e "$CONFIG_PATH" ]]; then
      if [[ -L "$CONFIG_PATH" ]]; then
        echo 'CLEANUP_BLOCKED=CONFIG_SYMLINK' >&2
        cleanup_failed=1
      elif ! rm -f -- "$CONFIG_PATH"; then
        echo 'CLEANUP_BLOCKED=CONFIG_REMOVE_FAILED' >&2
        cleanup_failed=1
      fi
    fi
    if [[ $INSTALL_CREATED -eq 1 && -e "$INSTALL_ROOT" ]]; then
      if ! safe_remove_created_tree "$INSTALL_ROOT"; then
        echo 'CLEANUP_BLOCKED=INSTALL_REMOVE_FAILED' >&2
        cleanup_failed=1
      fi
    fi

    if [[ -s "$CREATED_DIRS_FILE" ]]; then
      mapfile -t created_dirs < "$CREATED_DIRS_FILE"
      local i d
      for ((i=${#created_dirs[@]}-1; i>=0; i--)); do
        d="${created_dirs[$i]}"
        [[ -n "$d" ]] || continue
        if [[ -d "$d" ]]; then
          if ! rmdir -- "$d" 2>/dev/null; then
            echo "CLEANUP_BLOCKED=CREATED_DIR_NOT_EMPTY:$d" >&2
            cleanup_failed=1
          fi
        elif [[ -e "$d" || -L "$d" ]]; then
          echo "CLEANUP_BLOCKED=CREATED_DIR_REPLACED:$d" >&2
          cleanup_failed=1
        fi
      done
    fi
  fi

  rm -rf -- "$WORK"
  if [[ $cleanup_failed -ne 0 && $rc -eq 0 ]]; then
    rc=1
  fi
  return "$rc"
}
trap 'cleanup "$?"' EXIT

# Verify the exact accepted inner package and fully reconcile its payload
# inventory before any device-local proof action. The original Actions ZIP is
# recorded as evidence but may be safely repacked after finite artifact expiry.
actual_zip_sha="$(sha256sum "$ZIP_PATH" | awk '{print $1}')"
if [[ "$actual_zip_sha" == "$ORIGINAL_ARTIFACT_ZIP_SHA256" ]]; then
  echo 'ZIP_TRANSPORT=ORIGINAL_ACCEPTED_RUN'
else
  echo 'ZIP_TRANSPORT=REPACKED_OR_REPRODUCED'
fi

ZIP_PATH="$ZIP_PATH" WORK="$WORK" \
EXPECTED_TAR_SHA256="$EXPECTED_TAR_SHA256" EXPECTED_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT" \
EXPECTED_ADAPTER_BLOB="$EXPECTED_ADAPTER_BLOB" PACKAGE_NAME="$PACKAGE_NAME" python3 - <<'PY'
import hashlib, json, os, stat, tarfile, zipfile
from pathlib import Path, PurePosixPath

zip_path=Path(os.environ['ZIP_PATH'])
work=Path(os.environ['WORK'])
package=os.environ['PACKAGE_NAME']
expected_tar=os.environ['EXPECTED_TAR_SHA256']

def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()

expected_zip_names={
    f'{package}.tar.gz',
    f'{package}.tar.gz.sha256',
    'manifest.json',
}
try:
    with zipfile.ZipFile(zip_path) as zf:
        infos=zf.infolist()
        names=[i.filename for i in infos]
        if len(infos)!=3 or set(names)!=expected_zip_names or len(set(names))!=3:
            raise SystemExit('ERROR:ZIP_LAYOUT_INVALID')
        for info in infos:
            p=PurePosixPath(info.filename)
            if p.is_absolute() or '..' in p.parts or len(p.parts) != 1:
                raise SystemExit('ERROR:ZIP_PATH_INVALID')
            mode=(info.external_attr >> 16) & 0xffff
            if mode and stat.S_ISLNK(mode):
                raise SystemExit('ERROR:ZIP_SYMLINK_REFUSED')
            target=work/info.filename
            target.write_bytes(zf.read(info))
except zipfile.BadZipFile as exc:
    raise SystemExit('ERROR:ZIP_INVALID') from exc

archive=work/f'{package}.tar.gz'
checksum=work/f'{package}.tar.gz.sha256'
external_manifest=work/'manifest.json'
if sha256(archive) != expected_tar:
    raise SystemExit('ERROR:TAR_SHA256_MISMATCH')
line=checksum.read_text(encoding='ascii').strip()
if line != f'{expected_tar}  {archive.name}':
    raise SystemExit('ERROR:CHECKSUM_RECORD_INVALID')

manifest=json.loads(external_manifest.read_text(encoding='utf-8'))
exact={
 'schemaVersion':1,
 'artifact':package,
 'sourceCommit':os.environ['EXPECTED_SOURCE_COMMIT'],
 'dotnetSdkVersion':'10.0.403',
 'runtimeIdentifier':'linux-x64',
 'targetFramework':'net10.0',
 'selfContained':True,
 'requiresSystemDotnet':False,
 'installRoot':'~/.local/lib/ldw/operations-bridge/dragonfly',
 'entrypoint':'payload/LDW.OperationsBridge.Runner',
 'configurationPath':'~/.config/ldw/operations-bridge/dragonfly/config.json',
 'statePath':'~/.local/state/ldw/operations-bridge/dragonfly/health.json',
 'containsConfiguration':False,
 'containsCredential':False,
 'requiredHostBinaries':['/usr/bin/python3','/usr/bin/secret-tool'],
 'requiredExternalAdapter':{
    'path':'~/.local/lib/ldw-dragonfly-jit/bridge_adapter.py',
    'gitBlob':os.environ['EXPECTED_ADAPTER_BLOB'],
 },
}
for k,v in exact.items():
    if manifest.get(k) != v:
        raise SystemExit(f'ERROR:MANIFEST_FIELD:{k}')
files=manifest.get('files')
if not isinstance(files,list) or len(files) != 193:
    raise SystemExit('ERROR:MANIFEST_FILE_COUNT')

extract_root=work/'package-extract'
extract_root.mkdir(mode=0o700)
with tarfile.open(archive,'r:gz') as tf:
    members=tf.getmembers()
    if not members:
        raise SystemExit('ERROR:TAR_EMPTY')
    for member in members:
        p=PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != package:
            raise SystemExit('ERROR:TAR_PATH_INVALID')
        if not (member.isdir() or member.isfile()):
            raise SystemExit('ERROR:TAR_SPECIAL_MEMBER')
    tf.extractall(extract_root, filter='data')

root=extract_root/package
internal_manifest=root/'manifest.json'
payload=root/'payload'
if not internal_manifest.is_file() or not payload.is_dir():
    raise SystemExit('ERROR:PACKAGE_LAYOUT_INVALID')
if internal_manifest.read_bytes() != external_manifest.read_bytes():
    raise SystemExit('ERROR:INTERNAL_EXTERNAL_MANIFEST_MISMATCH')

actual_files=sorted(p for p in payload.rglob('*') if p.is_file())
actual_names=[p.relative_to(payload).as_posix() for p in actual_files]
record_names=[]
for rec in files:
    if not isinstance(rec,dict) or set(rec) != {'path','sha256','size'}:
        raise SystemExit('ERROR:MANIFEST_RECORD_SCHEMA')
    rel=rec['path']
    if not isinstance(rel,str):
        raise SystemExit('ERROR:MANIFEST_RECORD_PATH')
    pure=PurePosixPath(rel)
    if pure.is_absolute() or '..' in pure.parts or not pure.parts:
        raise SystemExit('ERROR:MANIFEST_RECORD_PATH')
    p=payload/Path(*pure.parts)
    if not p.is_file() or p.is_symlink():
        raise SystemExit(f'ERROR:PAYLOAD_FILE_INVALID:{rel}')
    data=p.read_bytes()
    if hashlib.sha256(data).hexdigest() != rec['sha256'] or len(data) != rec['size']:
        raise SystemExit(f'ERROR:PAYLOAD_INTEGRITY:{rel}')
    record_names.append(rel)
if sorted(record_names) != actual_names or len(set(record_names)) != len(record_names):
    raise SystemExit('ERROR:PAYLOAD_INVENTORY_MISMATCH')
entry=root/manifest['entrypoint']
if not entry.is_file() or not (entry.stat().st_mode & stat.S_IXUSR):
    raise SystemExit('ERROR:ENTRYPOINT_INVALID')

print('ARTIFACT_VERIFY=PASS')
print('SOURCE_COMMIT='+manifest['sourceCommit'])
print('PACKAGE_SHA256='+expected_tar)
print('PAYLOAD_FILES='+str(len(actual_files)))
PY

echo "ZIP_TRANSPORT_SHA256=$actual_zip_sha"

[[ "$MODE" == '--artifact-only' ]] && exit 0

[[ -n "${HOME:-}" && "$HOME" == /* ]] || { echo 'ERROR:HOME_INVALID' >&2; exit 1; }
[[ "$(id -u)" != '0' ]] || { echo 'ERROR:ROOT_USER_REFUSED' >&2; exit 1; }
[[ "$(id -un)" == "$EXPECTED_USER" ]] || { echo "ERROR:UNEXPECTED_USER:$(id -un)" >&2; exit 1; }

# Match accepted runtime prerequisites: Python is invoked at the fixed
# /usr/bin/python3 path and may be the normal Debian alternatives/symlink path;
# secret-tool is separately provenance-checked below with the runtime's stricter
# regular-file/non-symlink/non-group/world-writable rule.
[[ -x /usr/bin/python3 ]] || { echo 'ERROR:REQUIRED_BINARY_INVALID:/usr/bin/python3' >&2; exit 1; }
[[ -x /usr/bin/timeout ]] || { echo 'ERROR:REQUIRED_BINARY_INVALID:/usr/bin/timeout' >&2; exit 1; }
[[ -x /usr/bin/secret-tool ]] || { echo 'ERROR:REQUIRED_BINARY_INVALID:/usr/bin/secret-tool' >&2; exit 1; }

# Match the accepted runtime's private per-user lock boundary.
[[ -d "$RUNTIME_DIR" && ! -L "$RUNTIME_DIR" ]] || { echo 'ERROR:USER_RUNTIME_DIR_INVALID' >&2; exit 1; }
[[ "$(stat -c '%u' "$RUNTIME_DIR")" == "$RUNTIME_UID" ]] || { echo 'ERROR:USER_RUNTIME_OWNER_INVALID' >&2; exit 1; }
[[ "$(stat -c '%a' "$RUNTIME_DIR")" == '700' ]] || { echo 'ERROR:USER_RUNTIME_MODE_INVALID' >&2; exit 1; }
[[ -S "$RUNTIME_DIR/bus" ]] || { echo 'ERROR:USER_DBUS_SOCKET_MISSING' >&2; exit 1; }

# First proof must be clean and non-destructive. Refuse to clobber any prior
# Bridge install/config/health/lock state.
[[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || { echo 'ERROR:INSTALL_ROOT_PREEXISTS' >&2; exit 1; }
[[ ! -e "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || { echo 'ERROR:CONFIG_DIR_PREEXISTS' >&2; exit 1; }
[[ ! -e "$STATE_DIR" && ! -L "$STATE_DIR" ]] || { echo 'ERROR:STATE_DIR_PREEXISTS' >&2; exit 1; }
[[ ! -e "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || { echo 'ERROR:CONFIG_PREEXISTS' >&2; exit 1; }
[[ ! -e "$HEALTH_PATH" && ! -L "$HEALTH_PATH" ]] || { echo 'ERROR:HEALTH_PREEXISTS' >&2; exit 1; }
[[ ! -e "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || { echo 'ERROR:LOCK_PREEXISTS' >&2; exit 1; }
[[ "$(bridge_process_count)" == '0' ]] || { echo 'ERROR:BRIDGE_PROCESS_PREEXISTS' >&2; exit 1; }

# Verify fixed host dependencies/provenance before installation.
ADAPTER="$ADAPTER" EXPECTED_ADAPTER_BLOB="$EXPECTED_ADAPTER_BLOB" RUNTIME_UID="$RUNTIME_UID" python3 - <<'PY'
import hashlib, os, stat
from pathlib import Path

def no_symlink_chain(path):
    p=path.absolute(); cur=Path(p.anchor)
    for part in p.parts[1:]:
        cur=cur/part
        if cur.is_symlink(): raise SystemExit('ERROR:ADAPTER_SYMLINK_PATH')
    return p
p=no_symlink_chain(Path(os.environ['ADAPTER']))
if not p.is_file(): raise SystemExit('ERROR:ADAPTER_MISSING')
st=p.stat()
if st.st_uid != int(os.environ['RUNTIME_UID']): raise SystemExit('ERROR:ADAPTER_OWNER_INVALID')
if stat.S_IMODE(st.st_mode) & (stat.S_IWGRP|stat.S_IWOTH): raise SystemExit('ERROR:ADAPTER_MODE_INVALID')
data=p.read_bytes(); h=hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()
if h != os.environ['EXPECTED_ADAPTER_BLOB']: raise SystemExit('ERROR:ADAPTER_BLOB_MISMATCH')
print('ADAPTER_PROVENANCE=PASS')
PY

# Verify /usr/bin/secret-tool itself matches the runtime's non-symlink/non-writable
# assumptions, then perform a bounded lookup. Never print a returned secret.
SECRET_TOOL=/usr/bin/secret-tool python3 - <<'PY'
import os, stat
from pathlib import Path
p=Path(os.environ['SECRET_TOOL'])
st=p.lstat()
if not stat.S_ISREG(st.st_mode) or p.is_symlink(): raise SystemExit('ERROR:SECRET_TOOL_INVALID')
if stat.S_IMODE(st.st_mode) & (stat.S_IWGRP|stat.S_IWOTH): raise SystemExit('ERROR:SECRET_TOOL_WRITABLE')
print('SECRET_TOOL_PROVENANCE=PASS')
PY

SECRET_STDOUT="$WORK/secret.stdout"
SECRET_STDERR="$WORK/secret.stderr"
set +e
env -i \
  XDG_RUNTIME_DIR="$RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME_DIR/bus" \
  /usr/bin/timeout --kill-after=2s 12s \
  /usr/bin/secret-tool lookup service ldw-operations-bridge bridge-id "$EXPECTED_BRIDGE_ID" \
  </dev/null >"$SECRET_STDOUT" 2>"$SECRET_STDERR"
secret_rc=$?
set -e
[[ "$(stat -c '%s' "$SECRET_STDOUT")" -le 4098 && "$(stat -c '%s' "$SECRET_STDERR")" -le 4096 ]] || { echo 'ERROR:SECRET_LOOKUP_OUTPUT_BOUND' >&2; exit 1; }
if [[ $secret_rc -eq 124 || $secret_rc -eq 137 ]]; then
  echo 'ERROR:SECRET_LOOKUP_TIMEOUT' >&2
  exit 1
fi
if [[ $secret_rc -eq 0 || -s "$SECRET_STDOUT" ]]; then
  echo 'ERROR:BRIDGE_CREDENTIAL_PRESENT_OR_AMBIGUOUS' >&2
  exit 1
fi
# `secret-tool lookup` returns 1 with no stdout/stderr when no matching item exists.
# Any other failure is not proof of credential absence; stop rather than treating
# a locked/broken keyring or D-Bus failure as credential-free evidence.
if [[ $secret_rc -ne 1 || -s "$SECRET_STDERR" ]]; then
  echo "ERROR:BRIDGE_CREDENTIAL_ABSENCE_NOT_PROVEN:rc=$secret_rc" >&2
  exit 1
fi
echo 'CREDENTIAL_LOOKUP_NO_TOKEN_RC=1'

# Snapshot the exact existing JIT/owner-control/base state. These are the
# invariants the proof must preserve.
for p in "$CONTROLLER" "$OWNER_CONTROLS" "$ADAPTER" \
         "$DESKTOP_DIR/ldw-runner-start.desktop" \
         "$DESKTOP_DIR/ldw-runner-drain-stop.desktop" \
         "$DESKTOP_DIR/ldw-runner-status.desktop" \
         "$BASE"; do
  [[ -f "$p" && ! -L "$p" ]] || { echo "ERROR:BASELINE_FILE_INVALID:$p" >&2; exit 1; }
done

CONTROLLER_SHA_BEFORE="$(sha256sum "$CONTROLLER" | awk '{print $1}')"
OWNER_CONTROLS_SHA_BEFORE="$(sha256sum "$OWNER_CONTROLS" | awk '{print $1}')"
ADAPTER_SHA_BEFORE="$(sha256sum "$ADAPTER" | awk '{print $1}')"
START_SHA_BEFORE="$(sha256sum "$DESKTOP_DIR/ldw-runner-start.desktop" | awk '{print $1}')"
DRAIN_SHA_BEFORE="$(sha256sum "$DESKTOP_DIR/ldw-runner-drain-stop.desktop" | awk '{print $1}')"
STATUS_SHA_BEFORE="$(sha256sum "$DESKTOP_DIR/ldw-runner-status.desktop" | awk '{print $1}')"
BASE_SHA_BEFORE="$(sha512sum "$BASE" | awk '{print $1}')"
[[ "$BASE_SHA_BEFORE" == "$EXPECTED_BASE_SHA512" ]] || { echo 'ERROR:BASE_PROVENANCE_MISMATCH' >&2; exit 1; }

controller_status_before="$(jit_status_snapshot)"
CONTROLLER_STATUS="$controller_status_before" python3 - <<'PY'
import json, os
v=json.loads(os.environ['CONTROLLER_STATUS'])
if v.get('marker')!='CI-RUNNER-DRAGONFLY-JIT-001': raise SystemExit('ERROR:JIT_MARKER')
if v.get('state')!='STOPPED': raise SystemExit('ERROR:JIT_NOT_STOPPED')
if v.get('run_id') is not None or v.get('qemu_pid') is not None: raise SystemExit('ERROR:JIT_IDENTITY_PRESENT')
if v.get('residue_count') != 0: raise SystemExit('ERROR:JIT_RESIDUE')
if v.get('base_present') is not True: raise SystemExit('ERROR:JIT_BASE_NOT_PRESENT')
print('JIT_BASELINE=PASS')
PY

# Safe-create missing private parent directories and track only the directories
# created by this helper so cleanup can rmdir them if they remain empty.
ensure_private_parent() {
  local dir="$1"
  DIR="$dir" HOME_DIR="$HOME" CREATED_DIRS_FILE="$CREATED_DIRS_FILE" RUNTIME_UID="$RUNTIME_UID" python3 - <<'PY'
import os, stat
from pathlib import Path
p=Path(os.environ['DIR']).absolute()
home=Path(os.environ['HOME_DIR']).resolve(strict=True)
try:
    p.relative_to(home)
except ValueError:
    raise SystemExit('ERROR:TARGET_OUTSIDE_HOME')
cur=home
created=[]
for part in p.relative_to(home).parts:
    cur=cur/part
    if cur.is_symlink(): raise SystemExit('ERROR:TARGET_SYMLINK_PATH')
    if cur.exists():
        st=cur.stat()
        if not stat.S_ISDIR(st.st_mode): raise SystemExit('ERROR:TARGET_PARENT_NOT_DIR')
        if st.st_uid != int(os.environ['RUNTIME_UID']): raise SystemExit('ERROR:TARGET_PARENT_OWNER')
    else:
        cur.mkdir(mode=0o700)
        created.append(cur)
with open(os.environ['CREATED_DIRS_FILE'],'a',encoding='utf-8') as f:
    for d in created: f.write(str(d)+'\n')
PY
}

ensure_private_parent "$(dirname "$INSTALL_ROOT")"
ensure_private_parent "$CONFIG_DIR"
ensure_private_parent "$STATE_DIR"

# Copy the already-verified extracted package root to its exact accepted install
# location without touching any pre-existing file. Any partial copy belongs to
# this proof because the target was proven absent, so cleanup owns it.
INSTALL_CREATED=1
SRC_ROOT="$WORK/package-extract/$PACKAGE_NAME" TARGET_ROOT="$INSTALL_ROOT" HOME_DIR="$HOME" python3 - <<'PY'
import os, shutil
from pathlib import Path
src=Path(os.environ['SRC_ROOT'])
target=Path(os.environ['TARGET_ROOT'])
home=Path(os.environ['HOME_DIR']).resolve(strict=True)
expected=home/'.local/lib/ldw/operations-bridge/dragonfly'
if target != expected or target.exists() or target.is_symlink(): raise SystemExit('ERROR:INSTALL_TARGET_INVALID')
shutil.copytree(src,target,symlinks=False)
PY

# Create only the exact fixed non-secret config, mode 0600, exclusively.
# The path was proven absent, so cleanup owns any file created here.
CONFIG_CREATED=1
CONFIG_PATH="$CONFIG_PATH" BRIDGE_ID="$EXPECTED_BRIDGE_ID" RELAY_URI="$EXPECTED_RELAY_URI" python3 - <<'PY'
import json, os
from pathlib import Path
p=Path(os.environ['CONFIG_PATH'])
payload={'bridgeId':os.environ['BRIDGE_ID'],'relayConnectUri':os.environ['RELAY_URI']}
data=(json.dumps(payload,separators=(',',':'))+'\n').encode('utf-8')
fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
try:
    os.write(fd,data); os.fsync(fd)
finally:
    os.close(fd)
PY

[[ -x "$ENTRYPOINT" ]] || { echo 'ERROR:INSTALLED_ENTRYPOINT_NOT_EXECUTABLE' >&2; exit 1; }

status_before="$($ENTRYPOINT --dragonfly-status)"
[[ "$status_before" == '{"state":"unknown"}' ]] || { echo "ERROR:UNEXPECTED_PRE_STATUS:$status_before" >&2; exit 1; }
echo 'BRIDGE_STATUS_BEFORE=unknown'

# Run the exact accepted credential-free runtime path. With no Bridge token
# available it must fail closed before any relay connection attempt, persist
# blocked health, and exit 6. timeout bounds any unexpected hidden prompt/hang.
# Health/lock paths were proven absent, so cleanup owns them if runtime creates them.
HEALTH_CREATED=1
LOCK_CREATED=1
RUNTIME_STDOUT="$WORK/runtime.stdout"
RUNTIME_STDERR="$WORK/runtime.stderr"
set +e
/usr/bin/timeout --kill-after=2s 20s "$ENTRYPOINT" --dragonfly-run \
  </dev/null >"$RUNTIME_STDOUT" 2>"$RUNTIME_STDERR"
runtime_rc=$?
set -e
[[ $runtime_rc -ne 124 && $runtime_rc -ne 137 ]] || { echo 'ERROR:BRIDGE_RUNTIME_TIMEOUT' >&2; exit 1; }
[[ $runtime_rc -eq 6 ]] || { echo "ERROR:UNEXPECTED_BRIDGE_EXIT:$runtime_rc" >&2; exit 1; }
[[ "$(stat -c '%s' "$RUNTIME_STDOUT")" -le 4096 && "$(stat -c '%s' "$RUNTIME_STDERR")" -le 4096 ]] || { echo 'ERROR:BRIDGE_OUTPUT_BOUND' >&2; exit 1; }
echo 'BRIDGE_RUN_EXIT=6'

[[ -f "$HEALTH_PATH" && ! -L "$HEALTH_PATH" ]] || { echo 'ERROR:HEALTH_NOT_WRITTEN' >&2; exit 1; }
[[ -f "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || { echo 'ERROR:LOCK_NOT_CREATED' >&2; exit 1; }

status_after="$($ENTRYPOINT --dragonfly-status)"
[[ "$status_after" == '{"state":"blocked"}' ]] || { echo "ERROR:UNEXPECTED_POST_STATUS:$status_after" >&2; exit 1; }
echo 'BRIDGE_STATUS_AFTER=blocked'
[[ "$(bridge_process_count)" == '0' ]] || { echo 'ERROR:BRIDGE_PROCESS_LINGERING' >&2; exit 1; }
echo 'BRIDGE_PROCESS_CLEANUP=PASS'

controller_status_after="$(jit_status_snapshot)"
CONTROLLER_STATUS="$controller_status_after" python3 - <<'PY'
import json, os
v=json.loads(os.environ['CONTROLLER_STATUS'])
if v.get('marker')!='CI-RUNNER-DRAGONFLY-JIT-001': raise SystemExit('ERROR:JIT_MARKER_AFTER')
if v.get('state')!='STOPPED': raise SystemExit('ERROR:JIT_NOT_STOPPED_AFTER')
if v.get('run_id') is not None or v.get('qemu_pid') is not None: raise SystemExit('ERROR:JIT_IDENTITY_AFTER')
if v.get('residue_count') != 0: raise SystemExit('ERROR:JIT_RESIDUE_AFTER')
if v.get('base_present') is not True: raise SystemExit('ERROR:JIT_BASE_AFTER')
print('JIT_FINAL_STATE=PASS')
PY

[[ "$(sha256sum "$CONTROLLER" | awk '{print $1}')" == "$CONTROLLER_SHA_BEFORE" ]] || { echo 'ERROR:CONTROLLER_CHANGED' >&2; exit 1; }
[[ "$(sha256sum "$OWNER_CONTROLS" | awk '{print $1}')" == "$OWNER_CONTROLS_SHA_BEFORE" ]] || { echo 'ERROR:OWNER_CONTROLS_CHANGED' >&2; exit 1; }
[[ "$(sha256sum "$ADAPTER" | awk '{print $1}')" == "$ADAPTER_SHA_BEFORE" ]] || { echo 'ERROR:ADAPTER_CHANGED' >&2; exit 1; }
[[ "$(sha256sum "$DESKTOP_DIR/ldw-runner-start.desktop" | awk '{print $1}')" == "$START_SHA_BEFORE" ]] || { echo 'ERROR:START_LAUNCHER_CHANGED' >&2; exit 1; }
[[ "$(sha256sum "$DESKTOP_DIR/ldw-runner-drain-stop.desktop" | awk '{print $1}')" == "$DRAIN_SHA_BEFORE" ]] || { echo 'ERROR:DRAIN_LAUNCHER_CHANGED' >&2; exit 1; }
[[ "$(sha256sum "$DESKTOP_DIR/ldw-runner-status.desktop" | awk '{print $1}')" == "$STATUS_SHA_BEFORE" ]] || { echo 'ERROR:STATUS_LAUNCHER_CHANGED' >&2; exit 1; }
[[ "$(sha512sum "$BASE" | awk '{print $1}')" == "$BASE_SHA_BEFORE" ]] || { echo 'ERROR:BASE_CHANGED' >&2; exit 1; }
echo 'EXISTING_DRAGONFLY_ASSETS_UNCHANGED=PASS'

# Complete rollback before declaring the proof terminal PASS. The EXIT trap remains
# as failure cleanup until this explicit rollback succeeds.
if ! cleanup 0; then
  echo 'ERROR:ROLLBACK_INCOMPLETE' >&2
  exit 1
fi
trap - EXIT
[[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || { echo 'ERROR:ROLLBACK_INSTALL_REMAINS' >&2; exit 1; }
[[ ! -e "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || { echo 'ERROR:ROLLBACK_CONFIG_DIR_REMAINS' >&2; exit 1; }
[[ ! -e "$STATE_DIR" && ! -L "$STATE_DIR" ]] || { echo 'ERROR:ROLLBACK_STATE_DIR_REMAINS' >&2; exit 1; }
[[ ! -e "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || { echo 'ERROR:ROLLBACK_LOCK_REMAINS' >&2; exit 1; }
echo 'ROLLBACK=PASS'
echo 'CREDENTIAL_FREE_REDRIX_PROOF=PASS'
