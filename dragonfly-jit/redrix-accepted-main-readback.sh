#!/usr/bin/env bash
set -euo pipefail
umask 077

EXPECTED_ZIP_SHA256='e0091c03c7a0e0c3bdf01c51e8c29fcf70e51788c1a9d3d84a91226cea6b01d4'
EXPECTED_TAR_SHA256='27835aad28f13723c831ad4c8d0c5b8a2110cb22eb55e1387199eb8fff960f71'
EXPECTED_SOURCE_COMMIT='bcbdfb181f18eacfbceef2bf990c07a0b612915a'
EXPECTED_ADAPTER_BLOB='9ffbfd1dd2ea63fd7eece24e1f3eb791c92da0bf'
EXPECTED_BASE_SHA512='3ace18e33bdd036edb49d1f79342bd01d2ab980e35194edb0b410435cd543538d286a0bd13bbb0835f7862306e3d385ce2f6a70d8ecf0bd961111166adbc1b8e'
PACKAGE_NAME='ldw-operations-bridge-dragonfly-linux-x64'

usage() {
  echo "usage: $0 <dragonfly-redrix-linux-x64-main-bcbdfb181.zip> [--artifact-only]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
command -v realpath >/dev/null || { echo 'ERROR:REQUIRED_TOOL_MISSING:realpath' >&2; exit 2; }
ZIP_PATH="$(realpath -- "$1")"
MODE="${2:-}"
[[ -f "$ZIP_PATH" ]] || { echo 'ERROR:ARTIFACT_ZIP_MISSING' >&2; exit 2; }
[[ -z "$MODE" || "$MODE" == '--artifact-only' ]] || usage

for cmd in sha256sum sha512sum unzip tar python3 mktemp stat awk id head grep basename rm; do
  command -v "$cmd" >/dev/null || { echo "ERROR:REQUIRED_TOOL_MISSING:$cmd" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

actual_zip_sha="$(sha256sum "$ZIP_PATH" | awk '{print $1}')"
[[ "$actual_zip_sha" == "$EXPECTED_ZIP_SHA256" ]] || { echo "ERROR:ZIP_SHA256_MISMATCH:$actual_zip_sha" >&2; exit 1; }
unzip -q "$ZIP_PATH" -d "$WORK"

TAR="$WORK/$PACKAGE_NAME.tar.gz"
CHECKSUM="$TAR.sha256"
MANIFEST="$WORK/manifest.json"
[[ -f "$TAR" && -f "$CHECKSUM" && -f "$MANIFEST" ]] || { echo 'ERROR:ARTIFACT_LAYOUT_INVALID' >&2; exit 1; }
actual_tar_sha="$(sha256sum "$TAR" | awk '{print $1}')"
[[ "$actual_tar_sha" == "$EXPECTED_TAR_SHA256" ]] || { echo "ERROR:TAR_SHA256_MISMATCH:$actual_tar_sha" >&2; exit 1; }
(
  cd "$WORK"
  sha256sum --check --strict "$(basename "$CHECKSUM")" >/dev/null
)

ZIP_PATH="$ZIP_PATH" MANIFEST="$MANIFEST" TAR="$TAR" EXPECTED_SOURCE_COMMIT="$EXPECTED_SOURCE_COMMIT" EXPECTED_ADAPTER_BLOB="$EXPECTED_ADAPTER_BLOB" PACKAGE_NAME="$PACKAGE_NAME" python3 - <<'PY'
import hashlib, json, os, tarfile
from pathlib import PurePosixPath
m=json.load(open(os.environ['MANIFEST'], encoding='utf-8'))
exact={
 'schemaVersion':1,
 'artifact':os.environ['PACKAGE_NAME'],
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
    if m.get(k)!=v: raise SystemExit(f'ERROR:MANIFEST_FIELD:{k}')
files=m.get('files')
if not isinstance(files,list) or len(files)!=193: raise SystemExit('ERROR:MANIFEST_FILE_COUNT')
with tarfile.open(os.environ['TAR'],'r:gz') as tf:
    members=tf.getmembers()
    if not members: raise SystemExit('ERROR:TAR_EMPTY')
    for member in members:
        p=PurePosixPath(member.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!=os.environ['PACKAGE_NAME']:
            raise SystemExit('ERROR:TAR_PATH')
        if not (member.isdir() or member.isfile()):
            raise SystemExit('ERROR:TAR_SPECIAL_MEMBER')
print('ARTIFACT_VERIFY=PASS')
print('SOURCE_COMMIT='+m['sourceCommit'])
print('DOTNET_SDK='+m['dotnetSdkVersion'])
print('PAYLOAD_FILES='+str(len(files)))
PY

echo "ZIP_SHA256=$actual_zip_sha"
echo "PACKAGE_SHA256=$actual_tar_sha"

[[ "$MODE" == '--artifact-only' ]] && exit 0

# Everything below is read-only local capability/state discovery. It makes no
# package, keyring, SSH, Tailscale, service, firewall, runner, or VM changes.
echo "USER_NAME=$(id -un)"
echo "USER_UID=$(id -u)"
if [[ "$(id -u)" == '0' ]]; then echo 'ERROR:ROOT_USER_REFUSED' >&2; exit 1; fi

if [[ -d "/run/user/$(id -u)" ]]; then
  echo "USER_RUNTIME_DIR=present"
  stat -c 'USER_RUNTIME_MODE=%a' "/run/user/$(id -u)"
else
  echo "USER_RUNTIME_DIR=missing"
fi
[[ -S "/run/user/$(id -u)/bus" ]] && echo 'USER_DBUS_SOCKET=present' || echo 'USER_DBUS_SOCKET=missing'
[[ -x /usr/bin/python3 ]] && echo 'PYTHON3=present' || echo 'PYTHON3=missing'
[[ -x /usr/bin/secret-tool ]] && echo 'SECRET_TOOL=present' || echo 'SECRET_TOOL=missing'

ADAPTER="$HOME/.local/lib/ldw-dragonfly-jit/bridge_adapter.py"
if [[ -f "$ADAPTER" && ! -L "$ADAPTER" ]]; then
  ADAPTER="$ADAPTER" python3 - <<'PY'
import hashlib, os, pathlib, stat
p=pathlib.Path(os.environ['ADAPTER'])
data=p.read_bytes(); h=hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()
st=p.stat()
print('ADAPTER=present')
print('ADAPTER_GIT_BLOB='+h)
print('ADAPTER_MODE='+oct(stat.S_IMODE(st.st_mode))[2:])
print('ADAPTER_UID='+str(st.st_uid))
PY
else
  echo 'ADAPTER=missing_or_symlink'
fi

CONTROLLER="$HOME/.local/lib/ldw-dragonfly-jit/dragonfly_jit.py"
if [[ -f "$CONTROLLER" && ! -L "$CONTROLLER" ]]; then
  echo "CONTROLLER_SHA256=$(sha256sum "$CONTROLLER" | awk '{print $1}')"
  set +e
  controller_status="$(/usr/bin/python3 "$CONTROLLER" status 2>&1)"; controller_rc=$?
  set -e
  echo "CONTROLLER_STATUS_RC=$controller_rc"
  printf 'CONTROLLER_STATUS=%s\n' "$controller_status"
else
  echo 'CONTROLLER=missing_or_symlink'
fi

for f in ldw-runner-start.desktop ldw-runner-drain-stop.desktop ldw-runner-status.desktop; do
  p="$HOME/.local/share/applications/$f"
  if [[ -f "$p" && ! -L "$p" ]]; then
    echo "LAUNCHER_${f//[^A-Za-z0-9]/_}_SHA256=$(sha256sum "$p" | awk '{print $1}')"
  else
    echo "LAUNCHER_${f//[^A-Za-z0-9]/_}=missing_or_symlink"
  fi
done

BASE="${XDG_DATA_HOME:-$HOME/.local/share}/ldw-jit/base/debian-13-genericcloud-amd64.qcow2"
if [[ -f "$BASE" && ! -L "$BASE" ]]; then
  base_sha="$(sha512sum "$BASE" | awk '{print $1}')"
  echo "BASE_SHA512=$base_sha"
  [[ "$base_sha" == "$EXPECTED_BASE_SHA512" ]] && echo 'BASE_PROVENANCE=PASS' || echo 'BASE_PROVENANCE=MISMATCH'
else
  echo 'BASE=missing_or_symlink'
fi

if [[ -x /usr/sbin/sshd ]]; then
  echo 'SSHD_BINARY=present'
  sshd_version="$(/usr/sbin/sshd -V 2>&1 | head -n1 || true)"
  printf 'SSHD_VERSION=%s\n' "$sshd_version"
else
  echo 'SSHD_BINARY=missing'
fi

if [[ -f /usr/share/man/man5/authorized_keys.5.gz ]]; then
  if command -v zgrep >/dev/null; then
    if zgrep -Eq '(^|[^[:alnum:]_])restrict([^[:alnum:]_]|$)' /usr/share/man/man5/authorized_keys.5.gz; then
      echo 'AUTHORIZED_KEYS_RESTRICT_DOC=present'
    else
      echo 'AUTHORIZED_KEYS_RESTRICT_DOC=not_found'
    fi
  else
    echo 'AUTHORIZED_KEYS_RESTRICT_DOC=probe_tool_missing'
  fi
else
  echo 'AUTHORIZED_KEYS_RESTRICT_DOC=manpage_missing'
fi

if command -v systemctl >/dev/null; then
  ssh_unit=''
  for u in ssh.service sshd.service; do
    if systemctl status "$u" >/dev/null 2>&1 || systemctl is-enabled "$u" >/dev/null 2>&1; then ssh_unit="$u"; break; fi
  done
  if [[ -n "$ssh_unit" ]]; then
    echo "SSH_UNIT=$ssh_unit"
    echo "SSH_UNIT_ACTIVE=$(systemctl is-active "$ssh_unit" 2>/dev/null || true)"
    echo "SSH_UNIT_ENABLED=$(systemctl is-enabled "$ssh_unit" 2>/dev/null || true)"
  else
    echo 'SSH_UNIT=not_detected'
  fi
fi
if command -v ss >/dev/null; then
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:|\])22$'; then echo 'TCP22_LISTENING=yes'; else echo 'TCP22_LISTENING=no'; fi
fi

if command -v tailscale >/dev/null; then
  echo 'TAILSCALE_CLI=present'
  set +e
  ts_json="$(tailscale status --json 2>/dev/null)"; ts_rc=$?
  set -e
  echo "TAILSCALE_STATUS_RC=$ts_rc"
  if [[ $ts_rc -eq 0 && -n "$ts_json" ]]; then
    TS_JSON="$ts_json" python3 - <<'PY'
import json, os
try:
 d=json.loads(os.environ['TS_JSON'])
 print('TAILSCALE_BACKEND_STATE='+str(d.get('BackendState','unknown')))
 print('TAILSCALE_SELF_PRESENT='+('yes' if bool(d.get('Self')) else 'no'))
except Exception:
 print('TAILSCALE_STATUS_JSON=invalid')
PY
  fi
else
  echo 'TAILSCALE_CLI=missing'
fi

HOST_PUB=/etc/ssh/ssh_host_ed25519_key.pub
if [[ -r "$HOST_PUB" ]] && command -v ssh-keygen >/dev/null; then
  echo 'ED25519_HOST_KEY=present_readable'
  ssh-keygen -lf "$HOST_PUB" -E sha256 | awk '{print "ED25519_HOST_FINGERPRINT=" $2}'
else
  echo 'ED25519_HOST_KEY=missing_or_unreadable'
fi

echo 'READBACK_COMPLETE=PASS'
