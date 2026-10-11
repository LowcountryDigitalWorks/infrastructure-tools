#!/bin/bash
set -euo pipefail
check() {
  classification="$1"
  shift
  if ! "$@"; then
    printf 'SYNTHETIC_ASSERTION_FAILED=%s\n' "$classification"
    exit 1
  fi
}
check NON_ROOT test "$(id -u)" != 0
check UNPRIVILEGED_GROUPS test "$(id -Gn)" = ldw-runner
check FRESH_BOOTSTRAP_MARKER test -f /run/ci7/run-id
check NO_DOCKER_SOCKET test ! -S /var/run/docker.sock
# Cloud-init may create an empty .ssh directory/authorized_keys file. No keys
# or trust contents are permitted, and no management SSH identity is supplied.
ssh_contents=0
if [[ -d /home/ldw-runner/.ssh ]]; then
  ssh_contents="$(find /home/ldw-runner/.ssh -type f -size +0c | wc -l)"
fi
check NO_SSH_KEY_OR_TRUST_CONTENT test "$ssh_contents" = 0
check NO_GH_SESSION test ! -d /home/ldw-runner/.config/gh
check NO_CURSOR_SESSION test ! -d /home/ldw-runner/.config/Cursor
check NO_OWNER_GIT_CREDENTIALS test ! -e /home/ldw-runner/.git-credentials
check NO_PREVIOUS_WORKSPACE test ! -e /opt/actions-runner/_work/previous-job-marker
if findmnt -rn -t cifs,nfs,nfs4,9p,virtiofs,vboxsf,fuse.sshfs | read -r _; then echo SYNTHETIC_ASSERTION_FAILED=NO_HOST_MOUNT; exit 1; fi
if sudo -n true >/dev/null 2>&1; then echo SYNTHETIC_ASSERTION_FAILED=NO_SUDO; exit 1; fi
touch /opt/actions-runner/_work/previous-job-marker
printf '%s\n' 'SYNTHETIC_NON_ROOT_JOB_IDENTITY=PASS' \
  'SYNTHETIC_NO_HOST_CREDENTIAL_INHERITANCE=PASS' \
  'SYNTHETIC_NO_HOST_MOUNT=PASS' 'SYNTHETIC_NO_DOCKER_SOCKET=PASS' \
  'SYNTHETIC_DISPOSABLE_GUEST_FRESH=PASS'
