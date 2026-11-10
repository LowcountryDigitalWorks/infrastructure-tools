# REDRIX offline guest capacity executor

Status: **SOURCE-ONLY DRAFT**. Distinct from `redrix_capacity_guest_benchmark.py` (non-executing decision table, PR257) and from the protected `dragonfly_jit.py` controller (2048 MiB guest + **8192 MiB** reserve unchanged).

This module implements a **fixed one-shot** offline nested-KVM experiment for research **2+6** floor (8192 MiB) only. It never sets `jit_admission_authorized`, `provider_admission_authorized`, or `production_policy_changed`. ChromeOS host headroom is **UNVERIFIED**.

## HW&VM product admission (source-only; issue #139 / owner #96)

- **Research profile is explicit 2 GiB guest + 6 GiB Linux reserve (8192 MiB floor).** Production controller policy remains **2 GiB + 8 GiB (10240 MiB)** and is unchanged.
- Machine-readable contract: `redrix_capacity_guest_executor_admission.json`. Readiness evaluator: `redrix_capacity_guest_executor_admission.py` → `READY_FOR_HW_VM_INDEPENDENT_REVIEW` only while `PHYSICAL_EXECUTION_ENABLED` stays false.
- `RUNTIME_NO_START` reports embed `product_admission_readiness` (pins, required pre/during/post evidence phases, ChromeOS **UNVERIFIED**, owner-interactivity corroboration required). This is **not** provider/JIT admission.
- **Runtime enablement gate:** a **separate reviewed source commit** must flip `PHYSICAL_EXECUTION_ENABLED` after independent H0/M0 security review and Product ORCH acceptance. No environment-variable or context bypass exists.
- **Same-UID limitation:** staged private base mitigates external-path reuse only; hostile co-resident same-UID write/race risk remains disclosed in source and must not be overstated in review.
- **One `guest.lock`:** non-blocking exclusive flock on `~/.local/state/ldw-dragonfly-jit/guest.lock` (controller path); no parent mkdir on physical path; no `status.json` / `runs/` writes.

## Invocation

- Only `python3 redrix_capacity_guest_executor.py --run-once-local` is accepted; any other argv is refused.
- **DRAFT `RUNTIME_NO_START`:** physical execution is **disabled** in source (`PHYSICAL_EXECUTION_ENABLED = false`) until independent H0/M0 security review and Product ORCH admission flip that flag in a separate reviewed change.
- `run_once_local()` returns `RUNTIME_NO_START` while the flag is false; there is no alternate runtime admission via imports, environment, or context fields. Unit tests exercise `_run_once_local_impl()` with injected fakes only.
- When enabled in a future reviewed release: Linux UID 1000 only; acquires the **existing** controller `guest.lock` (O_NOFOLLOW where supported, no parent mkdir on the physical path) without writing `status.json` or controller `runs/`.
- Serial success proof uses a **bounded tail read** (256 KiB) with duplicate/forged marker rejection; RSS/dirty-memory and PSI/OOM caveats remain **research / not production admission**.
- Author tasks must **not** invoke the CLI on physical REDRIX while `RUNTIME_NO_START` is in effect.

## Residual HOLD (source-only hardening)

- **This source candidate now stages a verified private base** before qemu-img: open the external pinned base with `O_NOFOLLOW`, retain its file descriptor while copying, bound to 4 GiB, SHA-512 verify the copied bytes against the protected expected base hash, write with exclusive `O_CREAT|O_EXCL` and mode 0600 in an owner-only 0700 temporary directory, `fsync`, then reopen and rehash the **same private inode**. The fixed `qemu-img create -b` now names **only** `pinned-base.qcow2` in that private directory; it never points at the external mutable base path. Existing owned cleanup includes this additional regular file. Negative tests reject an external replacement between preflight and staging, source symlinks, unsafe staging directories, size overrun, preexisting target, and staged inode replacement before qemu-img. **Do not characterize this as protecting against a malicious co-resident process under the same Linux UID**; same-UID write/race risk remains for any future physical proof. The protected public/runner JIT controller is not modified. Physical flag remains `False` until separate independent security/product admission, and ChromeOS host headroom is **UNVERIFIED** by the guest workload executor itself.
- **Prior HOLD superseded only for external-path reuse:** the earlier source would reopen the original external image path during qemu-img overlay creation after an earlier digest verification. The new source stage avoids that specific external-path race, but has not been independently reviewed or accepted for real deployment. It is not a privileged A4 proof or a production-grade hostile-same-UID guarantee.
- A normal-user `/proc` census is not a privileged A4 scan. Any unreadable pid, symlink, empty listing, or scan over 4096 pids is `QEMU_CENSUS_UNAVAILABLE`. Seeing no QEMU name is not a clean host. Provider JIT still needs a separate privileged A4 proof. `guest.lock` and `runs/` are checked on the exact controller paths; an unverifiable lock is `GUEST_LOCK_BUSY`.
- `state.lock` passive readback holds when the lock file is missing (`STATE_LOCK_UNAVAILABLE`); controller continues to own authoritative state transitions.

## Owner memory interpretation (avoid false hardware capacity diagnosis)

[REDRIX #96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96) is canonical: the 32 GB ChromeOS host consistently shows ~17–20 GB available to Eddie, whereas Crostini has separately shown ~9,378 MiB `MemAvailable` at idle. This guest-visible observation is not proof ChromeOS physical RAM is exhausted. Neither this offline executor, the 2+6 research floor nor any future isolated JIT should weaken the live 2 GiB guest + **8 GiB reserve** admission policy without a separately reviewed host+guest dynamic-balloon/owner-interactivity proof. Keep advancing source and hosted tests when guest idle RAM alone is low; do not repeatedly demand owner RAM screenshots/SSH work or recommend hardware purchases. No host balloon changes or production policy update are part of this PR.

## Guest profile

2 vCPU, 2048 MiB RAM, `-nic none`, NoCloud seed, network disabled in cloud-config, serial log to a private 0700 temp dir, 210s wall bound, nonce-bound success line on serial (`LDW_REDRIX_GUEST_EXEC_OK nonce=<hex>`).

OOM counters are read from the **process leaf cgroup** `memory.events` (not root cgroup when absent). Balloon vmstat must be adjacent-stable; PSI avg10 steady across 3–6 preflight samples.

## Rollback

Delete only owned temp artifacts. Never lower the protected 8192 MiB reserve or edit pinned controller blobs. Do not change ChromeOS VM settings without host proof.
