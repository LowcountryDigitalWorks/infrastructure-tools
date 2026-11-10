# REDRIX — LDW parent ACL transaction design (source-only)

**Classification: DESIGN / NOT EXECUTABLE / NOT OWNER-AUTHORIZED**

**Authority:** `NOT_PHYSICAL_AUTHORITY` — in-memory synthetic candidate only.
**Verification:** `SOURCE_SYNTHETIC_VERIFIED` when WinPS 5.1 tests pin canonical UTF-8 `.Sddl` SHA `d0d4816b…` (not an authorized host ACL).

Owning issue: https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186

This document **supersedes** any earlier proposal that instructed preserving **CREATOR OWNER** (`S-1-3-0`) inherit-only **GENERIC_ALL** on the `%ProgramData%\LDW` parent or achieving a protected DACL via `SetAccessRuleProtection($true, $true)` followed by `RemoveAccessRule*` on copied inherited ACEs (issue comment 6756782022 and dependent drafts).

Independent challenge `c029cc82-1012-4e60-9bb7-a0356c8b9ce6` (issue comment 6757651419) is accepted as architecture input:

## Rejected patterns

1. **Preserve CREATOR OWNER generic-all** on the LDW parent — PR295 `Assert-TrustedDirectoryAcl` and PR300 `Assert-NoBroadWrite` reject it; stock ProgramData baseline rules apply only at the OS root, not under `LDW`.
2. **Copy-inherited-then-strip** — on Windows PowerShell 5.1, `SetAccessRuleProtection($true, $true)` leaves inherited ACE materialization flags that can make `RemoveAccessRule*` fail silently, retaining **BUILTIN\Users** write surfaces.
3. **Unjournaled rollback to old SDDL** — restoring the preimage re-opens parent write; any future physical transaction requires immutable preimage/target pins, protected owner journal, and fixed guards (no guessed auto-rollback).

## Accepted source-only candidate shape (synthetic, in-memory)

Build a **fresh explicit** protected DACL in memory (never `Set-Acl` on a host path from this lane):

| Principal | Access |
|-----------|--------|
| `S-1-5-18` (SYSTEM) | Full control, container+object inherit |
| `S-1-5-32-544` (Administrators) | Full control, container+object inherit |
| `S-1-5-32-545` (Users) | `0x1200a9` (ReadAndExecute \| Synchronize) only |

**Omit:** CREATOR OWNER (`S-1-3-0`), Users write (`0x116` / write surfaces), generic write/all on non-trusted principals.

Synthetic preimage for negative tests (historical LDW parent shape):

`O:SYG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)`

**Canonical target** (in-memory WinPS 5.1 on LDW01, UTF-8 hash of `DirectorySecurity.Sddl`):

`O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`

SHA-256: `d0d4816b0b001698a7f49ee24dab0eff49f784bcd9164ad5504b6e45f47f0a41`

Earlier challenger pin `a11c28fd…` for the same nominal string is **incorrect** for these exact bytes — tests must reject it. Synthetic preimage literal `(A;CIID;0x116;;;BU)` normalizes in .NET to `(A;CIID;DCLCRPCR;;;BU)`; hash the `.Sddl` property, not the unnormalized literal. Live LDW01 preimage observer pin `d7262f4d…` (PR300) remains independent from this synthetic fixture.

Pure in-memory proof: `host-agent/deploy/RedrixLdwParentAclSyntheticTarget.ps1` and `host-agent/deploy/tests/Test-RedrixLdwParentAclSyntheticTarget.ps1`.

## Future physical transaction (NOT in this artifact)

Any owner-only host change remains a **separate** gate after independent H0/M0 review:

1. Reconcile live six-child inventory, reparse, task quiescence, and exact preimage SDDL (PR300 observer — **read-only**; HOLD after mutation until new ledger).
2. No reliance on normal-user parent create/write; preserve existing six protected children unchanged.
3. Journal preimage in owner-only protected storage under verified `PrivilegedControl`; refuse ambiguous journaling.
4. Apply **only** the reviewed explicit target; native elevated readback; refuse ambiguous results (HOLD, no guessed rollback).
5. Re-verify all six child SDDL hashes and reviewed task identity after commit.

**No** executable transaction, rollback script, `Set-Acl`, scheduled task, or ProgramData mutation is included in the synthetic design PR.
