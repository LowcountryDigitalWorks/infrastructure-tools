# V2 publisher bootstrap — first-install Stage issuer (LDW01 owner-admin)

**Status:** source-only specification; **does not authorize installation or execution on LDW01**.

This document freezes the protected first-install Stage issuer path required by [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186) / `ADMIN_BROKER_PROMOTION_TRUST_GATE.md`. The download bundle is **five immutable DATA files** from one accepted `main` commit. Normal-user verification precedes elevation. **Elevated execution must not use `-File` on anything under Downloads or a checkout** (D0 TOCTOU boundary).

## Frozen download layout (normal user)

Root: `%USERPROFILE%\Downloads\LDW-V2-Publisher-Bootstrap-Review`

| File | Role |
|------|------|
| `AdminBrokerV2BootstrapIssuerManifest.json` | Lists install bundle + Stage digests (no self-entry). |
| `AdminBrokerV2BootstrapReviewManifest.json` | Install/worker cross-manifest. |
| `Install-AdminBrokerV2PublisherBootstrap.ps1` | Privileged bootstrap (protected staging only). |
| `Invoke-AdminBrokerV2PublisherWorker.ps1` | V2 worker bundle. |
| `Stage-AdminBrokerV2PublisherBootstrap.ps1` | Protected staging orchestrator (ProgramData only). |

**Prohibited:** any downloadable elevated launcher under Downloads. Never `powershell -File` a path under Downloads while elevated.

Verify each file hash in a **non-elevated** Windows PowerShell 5.1 session:

```powershell
Get-FileHash -LiteralPath $HOME\Downloads\LDW-V2-Publisher-Bootstrap-Review\*.ps1, `
  $HOME\Downloads\LDW-V2-Publisher-Bootstrap-Review\*.json -Algorithm SHA256
```

Compare to literals in the accepted source PR / contract test output. **HOLD** on any mismatch; do not elevate.

## Fixed owner-admin route (elevated inline only)

1. Open **native 64-bit** `System32\WindowsPowerShell\v1.0\powershell.exe` **as Administrator** (pinned shortcut or `Run as administrator` — not PATH, not `WindowsApps`, no `-ExecutionPolicy Bypass`).
2. Confirm `([Environment]::Is64BitProcess)` is `$true`.
3. **Paste** the full reviewed body from `host-agent/deploy/Bootstrap-V2ProtectedStagingInlineReference.ps1` at the accepted merge commit (printout or immutable commit browser export — not a `-File` invocation).
4. At the prompt, run: `Invoke-LdwV2BootstrapProtectedStagingInlineTransaction`

The inline transaction:

1. Treats Downloads files as byte DATA (`ReadAllBytes` / SHA-256); does not execute any script from Downloads.
2. Verifies independently frozen literal hashes embedded in the paste against each DATA file and issuer cross-check.
3. Validates `ProgramData\LDW` and staging ancestors for reparse / unsafe ancestry; creates `%ProgramData%\LDW\PrivilegedControl\bootstrap-staging\v2-publisher-once` with SYSTEM + Administrators-only DACL only if absent.
4. Exclusive-creates protected copies, re-hashes protected bytes (`PROTECTED_COPY_HASH_MISMATCH` on drift).
5. Launches **only** the protected `Stage-AdminBrokerV2PublisherBootstrap.ps1` via absolute `System32\...\powershell.exe -NoLogo -NoProfile -NonInteractive -File "<protected stage path>"` with zero script arguments.

`Stage-AdminBrokerV2PublisherBootstrap.ps1` refuses `STAGE_DOWNLOAD_PATH_REFUSED` unless `$PSCommandPath` is the exact protected staging copy.

Expected sanitized success line (inline materialization): `OWNER_INLINE_V2_PROTECTED_STAGE=PASS`
Expected sanitized success line (Stage, if Install completed): `STAGE_ADMIN_BROKER_V2_BOOTSTRAP=PASS`

## HOLD criteria

- `PROGRAMDATA_ROOT_BASELINE_HOLD`: OS `ProgramData` root DACL diverges from the stock Windows baseline (protected DACL; SYSTEM/Administrators owner; only the documented **BUILTIN\Users** create/write and read/execute inherit rules plus **InheritOnly** CREATOR_OWNER generic-all). **Do not** change the system-wide `C:\ProgramData` ACL to satisfy bootstrap.
- `LDW_PARENT_ACL_HOLD` or `LDW_PARENT_OWNER_REFUSED`: live `%ProgramData%\LDW` or below (excluding the OS-wide root baseline) has untrusted owner or inherited **BUILTIN\Users** / broad write. **Do not** weaken these checks or mutate production ACLs from this bootstrap lane; open a separate reviewed **LDW-only** ACL remediation, then re-run normal-user verification.
- `PROGRAMDATA_ENV_SPOOFED` / `USERPROFILE_ENV_SPOOFED`: process environment does not match OS known-folder profile paths.
- Any hash mismatch (Downloads DATA, protected copy, issuer vs embedded review pins).
- `STAGING_ALREADY_EXISTS`, `REPARSE_PATH_REFUSED`, or ambiguous `LDW_ROOT` owner/DACL.
- 32-bit host, SysWOW64, or WindowsApps PowerShell.
- Attempt to use `-File` on Downloads, checkout, or the inline reference script path.
- Stage or Install invoked from Downloads or non-ProgramData paths.
- Non-zero child exit or ambiguous Install journal readback.

## Rollback

Before Install mutates tasks: delete only `bootstrap-staging\v2-publisher-once` if Install success is not proven. Otherwise follow Install journal HOLD rules.

## Interrupt / journal caveat (LOW)

If elevation is interrupted after staging copy but before Install journaling completes, follow Install HOLD rules; do not assume partial staging is safe to reuse (`STAGING_ALREADY_EXISTS` applies).

## Post-merge pin refresh

Literal SHA-256 and git blob identities are asserted in `host-agent/deploy/tests/Test-AdminBrokerV2PublisherBootstrapContracts.ps1`. Treat contract test output at merge head as the authoritative pin table for IR.
