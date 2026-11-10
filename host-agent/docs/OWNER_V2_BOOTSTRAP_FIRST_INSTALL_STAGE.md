# V2 publisher bootstrap — first-install Stage issuer (LDW01 owner-admin)

**Status:** source-only specification; **does not authorize installation or execution on LDW01**.

This document freezes the protected first-install Stage issuer path required by [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186) / `ADMIN_BROKER_PROMOTION_TRUST_GATE.md`. The bundle is six files from one immutable `main` commit. Normal-user verification uses literal SHA-256; the only elevated entry is the fixed owner launcher under `Downloads`; **Stage and Install never run from Downloads**.

## Frozen download layout (normal user)

Root: `%USERPROFILE%\Downloads\LDW-V2-Publisher-Bootstrap-Review`

| File | Role |
|------|------|
| `AdminBrokerV2BootstrapIssuerManifest.json` | Lists install bundle + Stage + owner launcher digests (no self-entry). |
| `AdminBrokerV2BootstrapReviewManifest.json` | Install/worker cross-manifest. |
| `Install-AdminBrokerV2PublisherBootstrap.ps1` | Privileged bootstrap (protected staging only). |
| `Invoke-AdminBrokerV2PublisherWorker.ps1` | V2 worker bundle. |
| `Stage-AdminBrokerV2PublisherBootstrap.ps1` | Protected staging orchestrator (ProgramData only). |
| `OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1` | **Only** elevated entry from Downloads. |

Verify each file hash in a **non-elevated** Windows PowerShell 5.1 session before elevation:

```powershell
Get-FileHash -LiteralPath $HOME\Downloads\LDW-V2-Publisher-Bootstrap-Review\*.ps1, `
  $HOME\Downloads\LDW-V2-Publisher-Bootstrap-Review\*.json -Algorithm SHA256
```

Compare output to the literals in the accepted source PR / issuer manifest for that commit. **HOLD** on any mismatch; do not elevate.

## Fixed owner-admin command (elevated, zero parameters)

Resolve native 64-bit host (no PATH, no Bypass):

```text
%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -File "%USERPROFILE%\Downloads\LDW-V2-Publisher-Bootstrap-Review\OwnerAdmin-InvokeV2BootstrapProtectedStage.ps1"
```

The launcher:

1. Refuses non-Administrator, non-64-bit, or non-canonical `System32\...\powershell.exe` hosts.
2. Refuses launch paths outside the fixed Downloads bundle root or with reparse ancestors.
3. Parses `AdminBrokerV2BootstrapIssuerManifest.json` and cross-checks reviewed install-bundle pins.
4. Verifies its own bytes against the issuer manifest owner entry (not a self-embedded digest).
5. Creates `%ProgramData%\LDW\PrivilegedControl\bootstrap-staging\v2-publisher-once` with SYSTEM + Administrators-only ACLs (refuses pre-existing staging / reparse / unsafe ancestry).
6. Copies all six artifacts into staging, re-hashes protected bytes, starts **only** the protected `Stage-...ps1` via the same `System32` PowerShell path (`-NoLogo -NoProfile -NonInteractive -File`, no script arguments).

`Stage-AdminBrokerV2PublisherBootstrap.ps1` refuses `STAGE_DOWNLOAD_PATH_REFUSED` / `STAGE_PROTECTED_PATH_REQUIRED` unless `$PSCommandPath` is the exact staging copy. It validates the issuer manifest against embedded review pins, verifies Stage self-hash from issuer content, then launches Install only from protected staging.

Expected sanitized success line (owner launcher): `OWNER_ADMIN_V2_PROTECTED_STAGE=PASS`  
Expected sanitized success line (Stage, if Install completed): `STAGE_ADMIN_BROKER_V2_BOOTSTRAP=PASS`

## HOLD criteria (do not proceed)

- Any hash mismatch (Downloads, protected copy, issuer vs review cross-check).
- `STAGING_ALREADY_EXISTS` or ambiguous `LDW_ROOT` ACL / owner / reparse.
- 32-bit PowerShell, `SysWOW64`, or `WindowsApps` runtime.
- `OWNER_LAUNCH_PATH_REFUSED` (mutable path substitution).
- Stage or Install invoked from Downloads or any non-ProgramData path.
- Interrupted copy, non-zero child exit, or ambiguous task/journal readback (Install rules apply after Stage invokes Install).

## Rollback

Before Install mutates tasks: delete only `bootstrap-staging\v2-publisher-once` if no Install success was proven. If Install started, follow Install journal / V1 quiescence HOLD rules in the bootstrap source — do not hand-delete workers or task XML.

## Post-merge pin refresh

Literal SHA-256 and git blob identities are asserted in `host-agent/deploy/tests/Test-AdminBrokerV2PublisherBootstrapContracts.ps1` on the merge commit. Treat contract test output on `main` as the authoritative pin table for IR; this document describes behavior, not live hashes.
