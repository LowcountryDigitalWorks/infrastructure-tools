#!/bin/bash
set -euo pipefail
test "$(id -u)" != 0
test "$(id -Gn)" = ldw-runner
test -f /run/ci7/run-id
test ! -S /var/run/docker.sock
test ! -d /home/ldw-runner/.ssh
test ! -d /home/ldw-runner/.config/gh
test ! -d /home/ldw-runner/.config/Cursor
test ! -e /home/ldw-runner/.git-credentials
test ! -e /opt/actions-runner/_work/previous-job-marker
if findmnt -rn -t cifs,nfs,nfs4,9p,virtiofs,vboxsf,fuse.sshfs | read -r _; then exit 1; fi
if sudo -n true >/dev/null 2>&1; then exit 1; fi
touch /opt/actions-runner/_work/previous-job-marker
printf '%s\n' 'SYNTHETIC_NON_ROOT_JOB_IDENTITY=PASS' \
  'SYNTHETIC_NO_HOST_CREDENTIAL_INHERITANCE=PASS' \
  'SYNTHETIC_NO_HOST_MOUNT=PASS' 'SYNTHETIC_NO_DOCKER_SOCKET=PASS' \
  'SYNTHETIC_DISPOSABLE_GUEST_FRESH=PASS'
