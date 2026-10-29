#!/bin/bash
set -Eeuo pipefail
umask 077

MODE="${1:-plan}"
if [[ "$MODE" != "plan" && "$MODE" != "migrate" ]]; then
  echo 'ERROR:MODE_INVALID' >&2
  exit 2
fi

OWNER_USER='eddie'
OWNER_UID='1000'
SECRET_TOOL='/usr/bin/secret-tool'
RUNUSER='/usr/sbin/runuser'
SYSTEMD_CREDS='/usr/bin/systemd-creds'
HOST_KEY='/var/lib/systemd/credential.secret'
TARGET_DIR='/etc/credstore.encrypted'
TARGET_FILE='/etc/credstore.encrypted/dragonfly-bridge-token'
CREDENTIAL_NAME='dragonfly-bridge-token'
RUNTIME_DIR='/run/user/1000'
DBUS_ADDRESS='unix:path=/run/user/1000/bus'
SERVICE_ATTRIBUTE='ldw-operations-bridge'
BRIDGE_ID='dragonfly-redrix-01'

created_target=0
tmp=''
cleanup() {
  rc=$?
  trap - EXIT
  if [[ "$rc" -ne 0 && "$created_target" -eq 1 ]]; then
    rm -f -- "$TARGET_FILE"
    echo 'CIPHERTEXT_ROLLBACK=PASS'
  fi
  if [[ -n "$tmp" ]]; then
    rm -rf -- "$tmp"
  fi
  exit "$rc"
}
trap cleanup EXIT

fail() {
  echo "ERROR:$1" >&2
  exit 1
}

[[ "$(id -u)" == '0' ]] || fail 'ROOT_REQUIRED'
[[ "$(id -u "$OWNER_USER")" == "$OWNER_UID" ]] || fail 'OWNER_IDENTITY_INVALID'
[[ -x "$SYSTEMD_CREDS" && ! -L "$SYSTEMD_CREDS" ]] || fail 'SYSTEMD_CREDS_INVALID'
[[ -x "$RUNUSER" && ! -L "$RUNUSER" ]] || fail 'RUNUSER_INVALID'
[[ -x "$SECRET_TOOL" && ! -L "$SECRET_TOOL" ]] || fail 'SECRET_TOOL_INVALID'
[[ -f "$HOST_KEY" && ! -L "$HOST_KEY" ]] || fail 'HOST_KEY_MISSING'
[[ "$(stat -c '%u:%a' "$HOST_KEY")" == '0:400' ]] || fail 'HOST_KEY_METADATA_INVALID'
[[ -d "$RUNTIME_DIR" && ! -L "$RUNTIME_DIR" ]] || fail 'OWNER_RUNTIME_DIRECTORY_INVALID'
[[ -S "$RUNTIME_DIR/bus" && ! -L "$RUNTIME_DIR/bus" ]] || fail 'OWNER_DBUS_UNAVAILABLE'

if [[ -e "$TARGET_FILE" || -L "$TARGET_FILE" ]]; then
  fail 'CIPHERTEXT_TARGET_ALREADY_EXISTS'
fi

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  [[ -d "$TARGET_DIR" && ! -L "$TARGET_DIR" ]] || fail 'CREDSTORE_DIRECTORY_INVALID'
  [[ "$(stat -c '%u' "$TARGET_DIR")" == '0' ]] || fail 'CREDSTORE_DIRECTORY_OWNER_INVALID'
  target_mode="$(stat -c '%a' "$TARGET_DIR")"
  (( (8#$target_mode & 8#077) == 0 )) || fail 'CREDSTORE_DIRECTORY_MODE_INVALID'
fi

echo 'HOST_CREDENTIAL_KEY=PASS'
echo 'SECRET_SERVICE_SOURCE_PATH=PASS'
echo 'CIPHERTEXT_TARGET_PRECHECK=PASS'
echo 'PLAINTEXT_FILE_CREATED=no'
echo 'SECRET_SERVICE_SOURCE_DELETE_AUTHORIZED=no'

if [[ "$MODE" == 'plan' ]]; then
  echo 'REDRIX_BRIDGE_CREDENTIAL_MIGRATION_PLAN=PASS'
  trap - EXIT
  exit 0
fi

mkdir -p -- "$TARGET_DIR"
chown root:root "$TARGET_DIR"
chmod 0700 "$TARGET_DIR"

tmp="$(mktemp -d /run/ldw-bridge-credential-migrate.XXXXXX)"
chmod 0700 "$tmp"
source_digest="$tmp/source.sha256"
decrypted_digest="$tmp/decrypted.sha256"
encrypted_tmp="$tmp/dragonfly-bridge-token.cred"

# Secret bytes exist only in process pipes/memory. tee writes only to the
# systemd-creds stdin and to sha256sum; no plaintext file, argv or environment
# variable is created.
"$RUNUSER" -u "$OWNER_USER" -- env \
  XDG_RUNTIME_DIR="$RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="$DBUS_ADDRESS" \
  "$SECRET_TOOL" lookup service "$SERVICE_ATTRIBUTE" bridge-id "$BRIDGE_ID" \
  | tee >(sha256sum | awk '{print $1}' > "$source_digest") \
  | "$SYSTEMD_CREDS" encrypt --with-key=host --name="$CREDENTIAL_NAME" - "$encrypted_tmp" >/dev/null

[[ -s "$source_digest" && -s "$encrypted_tmp" ]] || fail 'ENCRYPTION_OUTPUT_INVALID'
chmod 0600 "$encrypted_tmp"

"$SYSTEMD_CREDS" decrypt --name="$CREDENTIAL_NAME" "$encrypted_tmp" - 2>/dev/null \
  | sha256sum | awk '{print $1}' > "$decrypted_digest"
[[ -s "$decrypted_digest" ]] || fail 'DECRYPTION_VERIFY_INVALID'
cmp -s "$source_digest" "$decrypted_digest" || fail 'ENCRYPTION_ROUNDTRIP_MISMATCH'

install -o root -g root -m 0600 -- "$encrypted_tmp" "$TARGET_FILE"
created_target=1
[[ -f "$TARGET_FILE" && ! -L "$TARGET_FILE" ]] || fail 'CIPHERTEXT_INSTALL_INVALID'
[[ "$(stat -c '%u:%a' "$TARGET_FILE")" == '0:600' ]] || fail 'CIPHERTEXT_METADATA_INVALID'

"$SYSTEMD_CREDS" decrypt --name="$CREDENTIAL_NAME" "$TARGET_FILE" - 2>/dev/null \
  | sha256sum | awk '{print $1}' > "$decrypted_digest"
cmp -s "$source_digest" "$decrypted_digest" || fail 'INSTALLED_CIPHERTEXT_VERIFY_FAILED'

created_target=0
rm -rf -- "$tmp"
tmp=''
trap - EXIT

echo 'SYSTEMD_HOST_ENCRYPT=PASS'
echo 'SYSTEMD_HOST_DECRYPT_DIGEST=PASS'
echo 'CIPHERTEXT_INSTALL=PASS'
echo 'CIPHERTEXT_OWNER=root'
echo 'CIPHERTEXT_MODE=0600'
echo 'PLAINTEXT_FILE_CREATED=no'
echo 'SECRET_SERVICE_SOURCE_RETAINED=yes'
echo 'REDRIX_BRIDGE_CREDENTIAL_MIGRATION=PASS'
