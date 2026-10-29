#!/bin/bash
set -Eeuo pipefail
umask 077

MODE="${1:-plan}"
case "$MODE" in
  plan|install|enable|rollback) ;;
  *) echo 'ERROR:MODE_INVALID' >&2; exit 2 ;;
esac

UNIT_NAME='ldw-operations-bridge-dragonfly.service'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_UNIT="$(cd -- "$SCRIPT_DIR/../systemd" && pwd -P)/$UNIT_NAME"
TARGET_UNIT="/etc/systemd/system/$UNIT_NAME"
RUNNER='/home/eddie/.local/lib/ldw/operations-bridge/dragonfly/payload/LDW.OperationsBridge.Runner'
CONFIG='/home/eddie/.config/ldw/operations-bridge/dragonfly/config.json'
STATE_DIR='/home/eddie/.local/state/ldw/operations-bridge/dragonfly'
CIPHERTEXT='/etc/credstore.encrypted/dragonfly-bridge-token'

fail() {
  echo "ERROR:$1" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == '0' ]] || fail 'ROOT_REQUIRED'
}

assert_regular_nonwritable() {
  local path="$1"
  local label="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "${label}_INVALID"
  local mode
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 8#022) == 0 )) || fail "${label}_WRITABLE_BY_OTHERS"
}

assert_runtime() {
  [[ "$(id -u eddie)" == '1000' ]] || fail 'OWNER_IDENTITY_INVALID'
  assert_regular_nonwritable "$RUNNER" 'RUNNER'
  [[ -x "$RUNNER" ]] || fail 'RUNNER_NOT_EXECUTABLE'
  assert_regular_nonwritable "$CONFIG" 'CONFIG'
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || fail 'STATE_DIRECTORY_INVALID'
  [[ "$(stat -c '%u:%a' "$STATE_DIR")" == '1000:700' ]] || fail 'STATE_DIRECTORY_METADATA_INVALID'
}

assert_source_unit() {
  assert_regular_nonwritable "$SOURCE_UNIT" 'SOURCE_UNIT'
  grep -Fxq 'User=eddie' "$SOURCE_UNIT" || fail 'SOURCE_UNIT_USER_INVALID'
  grep -Fxq "ExecStart=$RUNNER --dragonfly-run" "$SOURCE_UNIT" || fail 'SOURCE_UNIT_EXECSTART_INVALID'
  grep -Fxq 'LoadCredentialEncrypted=dragonfly-bridge-token:/etc/credstore.encrypted/dragonfly-bridge-token' "$SOURCE_UNIT" || fail 'SOURCE_UNIT_CREDENTIAL_INVALID'
}

assert_ciphertext() {
  [[ -f "$CIPHERTEXT" && ! -L "$CIPHERTEXT" ]] || fail 'CIPHERTEXT_MISSING'
  [[ "$(stat -c '%u:%a' "$CIPHERTEXT")" == '0:600' ]] || fail 'CIPHERTEXT_METADATA_INVALID'
}

assert_installed_unit_exact() {
  [[ -f "$TARGET_UNIT" && ! -L "$TARGET_UNIT" ]] || fail 'INSTALLED_UNIT_MISSING'
  cmp -s "$SOURCE_UNIT" "$TARGET_UNIT" || fail 'INSTALLED_UNIT_DRIFT'
  [[ "$(stat -c '%u:%a' "$TARGET_UNIT")" == '0:644' ]] || fail 'INSTALLED_UNIT_METADATA_INVALID'
}

assert_source_unit
assert_runtime

echo 'SOURCE_UNIT=PASS'
echo 'RUNNER_PREREQUISITES=PASS'
echo 'STATE_DIRECTORY=PASS'

if [[ "$MODE" == 'plan' ]]; then
  if [[ -e "$TARGET_UNIT" || -L "$TARGET_UNIT" ]]; then
    assert_installed_unit_exact
    echo 'INSTALLED_UNIT=EXACT'
  else
    echo 'INSTALLED_UNIT=ABSENT'
  fi
  if [[ -e "$CIPHERTEXT" || -L "$CIPHERTEXT" ]]; then
    assert_ciphertext
    echo 'CIPHERTEXT=READY'
  else
    echo 'CIPHERTEXT=ABSENT'
  fi
  echo 'SERVICE_MUTATION_PERFORMED=no'
  echo 'REDRIX_BRIDGE_SYSTEMD_PLAN=PASS'
  exit 0
fi

require_root

if [[ "$MODE" == 'install' ]]; then
  if [[ -e "$TARGET_UNIT" || -L "$TARGET_UNIT" ]]; then
    assert_installed_unit_exact
    echo 'UNIT_INSTALL=ALREADY_EXACT'
  else
    install -o root -g root -m 0644 -- "$SOURCE_UNIT" "$TARGET_UNIT"
    assert_installed_unit_exact
    echo 'UNIT_INSTALL=PASS'
  fi
  systemctl daemon-reload
  echo 'UNIT_ENABLED_BY_INSTALL=no'
  echo 'UNIT_STARTED_BY_INSTALL=no'
  echo 'REDRIX_BRIDGE_SYSTEMD_INSTALL=PASS'
  exit 0
fi

if [[ "$MODE" == 'enable' ]]; then
  assert_installed_unit_exact
  assert_ciphertext
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME"
  [[ "$(systemctl is-enabled "$UNIT_NAME")" == 'enabled' ]] || fail 'UNIT_ENABLE_UNCONFIRMED'
  [[ "$(systemctl is-active "$UNIT_NAME")" == 'active' ]] || fail 'UNIT_START_UNCONFIRMED'
  echo 'UNIT_ENABLE=PASS'
  echo 'UNIT_START=PASS'
  echo 'REDRIX_BRIDGE_SYSTEMD_ENABLE=PASS'
  exit 0
fi

# Rollback is intentionally limited to the exact reviewed unit. It never
# deletes encrypted credential material or the retained Secret Service source.
if [[ -e "$TARGET_UNIT" || -L "$TARGET_UNIT" ]]; then
  assert_installed_unit_exact
  systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f -- "$TARGET_UNIT"
  systemctl daemon-reload
  [[ ! -e "$TARGET_UNIT" && ! -L "$TARGET_UNIT" ]] || fail 'UNIT_ROLLBACK_REMOVE_FAILED'
  echo 'UNIT_ROLLBACK=PASS'
else
  echo 'UNIT_ROLLBACK=ALREADY_ABSENT'
fi

echo 'CIPHERTEXT_DELETED=no'
echo 'SECRET_SERVICE_SOURCE_DELETED=no'
echo 'REDRIX_BRIDGE_SYSTEMD_ROLLBACK=PASS'
