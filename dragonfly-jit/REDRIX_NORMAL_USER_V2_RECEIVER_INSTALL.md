# REDRIX normal-user V2 forced-receiver adjunct install (source-only)

Status: **not authorized for physical execution** by merge of this documentation alone.

## Purpose

Provide a closed, fail-closed **plan and offline tests** for installing the pinned main-tree
`ssh_forced_receiver.py` and `inbound_transfer_v2.py` adjunct under
`~/.local/lib/ldw-dragonfly-jit/` when the device currently carries receiver Git blob
`88b527fa4b9b7060216c661d58edf2e97034dafa` and **does not** yet have `inbound_transfer_v2.py`.

This does **not** replace the accepted #115 synthetic handoff proof, does **not** authorize
`authorized_keys`, sshd, or Tailscale changes, and does **not** admit live JIT.

Machine contract: `redrix_normal_user_v2_receiver_install.json`
Installer module: `redrix_normal_user_v2_receiver_install.py` (`PHYSICAL_INSTALL_ENABLED = false`)

Source safety (this PR): nonblocking `flock` on the resolved trusted home directory under root-owned `/home`
(`BLOCKED_LOCK_TRUST_ROOT` otherwise); `invoke.kernel.lock` is a durable record only (not exclusivity); durable
transaction journal (`PREPARED` → `INBOUND_COMMITTED` → `RECEIVER_COMMITTED` → `CLEANUP`/`FAILED`); inbound committed
before receiver; receipt commit fail-closed (`INSTALL_POST_RECEIPT_HOLD` if receipt bytes durable after `os.replace`);
exclusive staging directory create; fail-closed recovery when journal or mixed blobs remain.

## Out of scope

- `host-agent/*`, Gate A4 privileged proof artifacts, production controller, CI7, ChromeOS policy
- Generic updater or caller-selected paths
- Password, private key, or SSH key content handling
- Network transfer or elevation

## Owner-operated physical gate (NOT authorized by source merge)

1. Confirm independent exact-head IR on the installer branch (canonical Git blob pins at `source_commit`; not working-tree CRLF bytes).
2. On REDRIX as UID 1000, build the bounded package directory from immutable `git cat-file` bytes at `source_commit` only (payload + rollback + manifest).
3. Run `plan` dry-run; verify `receiverInboundPinCoherent` is true and `eligibleForPhysicalInstall` would be true only after a separate reviewed commit flips `PHYSICAL_INSTALL_ENABLED`.
4. Owner executes one bounded install invocation with a fresh `operation_id`; record sanitized receipt digests only.
5. Re-read installed receiver and inbound Git blobs and modes (`0700` / `0600`); confirm forced command string unchanged.
6. Preserve `rollback-receiver-v1.bin` until a separate rollback decision.
7. Do **not** add transfer sentinel keys, reload sshd, or run live package transfer until #139 and V2 transfer gates accept.

Until those steps complete, do not claim physical V2 receiver admission.
