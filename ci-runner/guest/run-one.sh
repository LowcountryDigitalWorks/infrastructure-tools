#!/bin/bash
set -euo pipefail
umask 077
test "$(id -u)" != 0
test -s /run/ci7/jit
cd /opt/actions-runner
# JIT is short-lived repository-scoped registration material, never a PAT.
# Listener exits after exactly one job; service restart is forbidden.
exec ./run.sh --jitconfig "$(cat /run/ci7/jit)"
