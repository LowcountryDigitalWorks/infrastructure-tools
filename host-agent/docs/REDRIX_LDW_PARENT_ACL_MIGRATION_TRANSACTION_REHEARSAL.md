# REDRIX — LDW parent ACL migration transaction rehearsal (source-only)

**Classification: DESIGN / NON_EXECUTABLE / NOT OWNER-AUTHORIZED**

**Authority:** `NOT_PHYSICAL_AUTHORITY` — mock in-memory states only; `Invoke-RedrixLdwParentAclMigrationApplyBoundary` always returns `BLOCKED_APPROVAL`.

**Verification:** `SOURCE_REHEARSAL_SYNTHETIC` — WinPS 5.1 tests in `host-agent/deploy/tests/Test-RedrixLdwParentAclMigrationTransaction.ps1`.

Owning issue: https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186

Merged PR301 supplies the **explicit in-memory target** (SHA `d0d4816b…`). Merged PR300 supplies **read-only** preimage/child/task observations (root SHA `d7262f4d…`, six protected child SDDL hashes, task `LDW-ADMIN-REVIEWED-OPERATION`). Live host may drift; pins are drift detectors, **not** authority to mutate.

## Non-executing rehearsal artifacts

| Artifact | Role |
|----------|------|
| `host-agent/deploy/RedrixLdwParentAclMigrationTransaction.ps1` | Fixed-path mock snapshots, precondition gates, ledger/recovery/rollback policy, rehearsal orchestration |
| `host-agent/deploy/data/RedrixLdwParentAclMigrationTransactionReference.json` | Immutable pins (no caller args) |
| `host-agent/docs/REDRIX_LDW_PARENT_ACL_TRANSACTION_DESIGN.md` | Target shape and rejected patterns |

**Forbidden in this packet:** `Set-Acl`, host writes, stock `C:\ProgramData` DACL changes, new privileged launcher, scheduled-task mutation, secrets/network.

ProgramData root trust uses **machine-known** `[Environment]::GetFolderPath(CommonApplicationData)` only; untrusted caller paths are refused. That binding is **not** a reparse-point, junction, or live ACL readback proof — physical LDW01 review (#186 / #139) remains required before any future host action. Rehearsal mock snapshots do not assert host LDW ACL or memory truth (`syntheticSnapshotOnly = true`, `hostRootTrustAsserted = false`); green rehearsal or ledger recovery strings are source-model checks only, not physical authorization.

## Owner-reviewed checklist (rehearsal stages)

1. **Fresh read-only preflight** — run `Test-RedrixLdwParentAclReadiness.ps1` on LDW01; must classify `READ_ONLY_PREIMAGE_MATCH_NOT_AUTHORIZED` or `HOLD_READ_ONLY` (no authorization either way).
2. **Independent exact-head review** — author-excluded H0/M0 on frozen source commit before any physical packet.
3. **Quiescence** — existing `LDW-ADMIN-REVIEWED-OPERATION` Ready, zero triggers (no new task names invented here).
4. **Preimage freeze** — capture exact parent SDDL UTF-8 SHA; compare to observation pin only; synthetic `d0d4816b…` does **not** authorize apply.
5. **Explicit target parity** — in-memory build must match PR301 canonical SDDL/SHA (ACE allowlist: SY/BA FA, BU `0x1200a9`; no CREATOR OWNER / Users write).
6. **Six-child immutability** — all six directory SDDL hashes unchanged pre/post (mock rehearsal enforces hash map parity).
7. **Owner journal** — protected storage stage append; incomplete journal → `HOLD_RECOVERY_AMBIGUOUS`; rollback without journal → `ROLLBACK_REFUSED_NO_JOURNAL`.
8. **Apply boundary** — source returns `BLOCKED_APPROVAL`; physical step is **not** in this repository path.

## Manually authorized final host step (document only — do not run from this PR)

After separate owner sign-off and post-merge physical packet (not this artifact):

1. Owner elevation on LDW01 only; re-run read-only preflight immediately before change.
2. Apply **only** the reviewed explicit parent DACL under `%ProgramData%\LDW` using owner-operated, reviewed tooling defined in that physical packet — **not** this rehearsal module.
3. Do **not** modify stock `C:\ProgramData`, any of the six child DACLs, or the existing V1 task definition.
4. Native elevated readback of parent SDDL UTF-8 SHA → expect `d0d4816b…` only if live `.Sddl` matches frozen string; else HOLD.
5. Re-read all six child SDDL hashes and task identity; any ambiguity → HOLD, no guessed rollback.

Eddie is **not** asked to execute these steps from the source-only PR.

## Disjoint tracks

Does not modify capacity PR302, CI7, Gate B one-shot authority, or dragonfly-jit receiver install (#298).
