# REDRIX V2 adjunct package transfer (source-only)

This document describes the **separate** normal-user package transfer profile for the pinned Dragonfly adjunct V2 release. It does **not** authorize production transfer, alter `authorized_keys`, or replace the accepted #115 synthetic handoff proof.

## Boundary

| Item | Policy |
|------|--------|
| Sender identity | LDW01 **normal user** only; elevated publisher remains separate |
| Transport | Existing pinned OpenSSH client plan; **closed** `TRANSFER_REMOTE_SENTINEL` forced command |
| Receiver | Existing `ssh_forced_receiver.py` dispatches to pinned `inbound_transfer_v2.py` |
| Credential surface | No endpoint/token in repository; owner-local transport config only |
| Bundle | Frozen `78a3a23…-e53e016…` release manifest and four pinned `ci-dispatch` files only |
| #115 proof | Synthetic handoff only; **does not** prove this package transfer until physically gated |

## Source modules

- `ci-dispatch/DragonflyAdjunctV2Transfer.psm1` — builds a bounded transfer envelope from `%LOCALAPPDATA%\LDW\DragonflyCanaryAdjunct\normal-user-staging\<release>` after normal-user staging; refuses elevation.
- `dragonfly-jit/inbound_transfer_v2.py` — validates manifest pins, decodes bounded payloads, stages `0700` / `0600`, atomic install, sender/receiver manifest SHA256 readback, replay refusal.
- `dragonfly-jit/ssh_transport_contract.py` — `build_openssh_transfer_plan()` for the closed transfer remote command (no agent forwarding, stdin envelope only).

## Physical gate (not satisfied by this source)

1. Independent exact-head IR on this branch.
2. Owner one-time install of pinned `inbound_transfer_v2.py` beside the accepted receiver under `~/.local/lib/ldw-dragonfly-jit/` **without** widening forced-command options.
3. Separate `authorized_keys` line or equivalent host rule for `TRANSFER_REMOTE_SENTINEL` **only if** IR accepts distinct closed command mapping (no generic shell).
4. Normal-user staging path populated from the already reviewed elevated V2 publisher output, then one bounded transfer with digests recorded.
5. A4 guest reserve 2048+8192 MiB and exact #10 job admission remain mandatory before any live JIT.

Until those gates complete, treat this as **source + deterministic tests only**.
