# REDRIX offline guest capacity executor

Status: **SOURCE-ONLY DRAFT**. Distinct from `redrix_capacity_guest_benchmark.py` (non-executing decision table, PR257) and from the protected `dragonfly_jit.py` controller (2048 MiB guest + **8192 MiB** reserve unchanged).

This module implements a **fixed one-shot** offline nested-KVM experiment for research **2+6** floor (8192 MiB) only. It never sets `jit_admission_authorized`, `provider_admission_authorized`, or `production_policy_changed`. ChromeOS host headroom is **UNVERIFIED**.

## Invocation

- Only `python3 redrix_capacity_guest_executor.py --run-once-local` is accepted; any other argv is refused.
- **DRAFT `RUNTIME_NO_START`:** physical execution is **disabled** in source (`PHYSICAL_EXECUTION_ENABLED = false`) until independent H0/M0 security review and Product ORCH admission flip that flag in a separate reviewed change.
- `run_once_local()` and `wire_linux_executor()` are guarded: imports cannot launch QEMU while the flag is false unless tests set `RunContext.synthetic_test_admission` (not exposed to CLI).
- When enabled in a future reviewed release: Linux UID 1000 only; acquires the **existing** controller `guest.lock` (O_NOFOLLOW where supported, no parent mkdir on the physical path) without writing `status.json` or controller `runs/`.
- Serial success proof uses a **bounded tail read** (256 KiB) with duplicate/forged marker rejection; RSS/dirty-memory and PSI/OOM caveats remain **research / not production admission**.
- Author tasks must **not** invoke the CLI on physical REDRIX while `RUNTIME_NO_START` is in effect.

## Residual HOLD (source-only hardening)

- Base image inode-stable shared read lock through qemu-img overlay creation is not fully proven in this module; ChromeOS headroom remains **UNVERIFIED**.
- Full QEMU host process census and guest.lock inode identity against a fixed install layout require physical IR before enabling execution.
- `state.lock` passive readback holds when the lock file is missing (`STATE_LOCK_UNAVAILABLE`); controller continues to own authoritative state transitions.

## Guest profile

2 vCPU, 2048 MiB RAM, `-nic none`, NoCloud seed, network disabled in cloud-config, serial log to a private 0700 temp dir, 210s wall bound, nonce-bound success line on serial (`LDW_REDRIX_GUEST_EXEC_OK nonce=<hex>`).

OOM counters are read from the **process leaf cgroup** `memory.events` (not root cgroup when absent). Balloon vmstat must be adjacent-stable; PSI avg10 steady across 3–6 preflight samples.

## Rollback

Delete only owned temp artifacts. Never lower the protected 8192 MiB reserve or edit pinned controller blobs. Do not change ChromeOS VM settings without host proof.
