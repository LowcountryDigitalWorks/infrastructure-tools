# Host2AssignmentD0 — inert OfficePC-exclusive host assignment DESIGN contract

**Status:** `SOURCE_ONLY / D0 / DEFAULT_DISABLED / NO_RUNTIME_BINDING / NOT_ACCEPTANCE_AUTHORITY`.

This folder is a deliberately isolated, inert schema/data contract for a **future**
profile-to-host ownership decision. It is the smallest source expression of design
pointer [#86 comment 7092892405](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/86#issuecomment-7092892405).
It is **not** a dispatcher, controller, runner, verifier, lease, queue claim, or
admission path, and it grants no runtime authority of any kind.

## Files

| Path | Role |
|---|---|
| `Host2AssignmentD0.contract.json` | Closed allowlist + inert fixture: four known profile IDs, every profile `enabled:false`, `primaryHost:"officepc"` only in the disabled fixture, `fallbackHost:null`, no receipt, no provenance, no wildcard, no address/secret. |
| `Host2AssignmentD0.psm1` | Pure deterministic fail-closed parser/schema/decision evaluator. Strict JSON (duplicate keys, comments, trailing commas rejected); allowlisted keys only; every decision is `DENY`. Only I/O is reading the exact local fixture from this folder. |
| `tests/Test-Host2AssignmentD0.ps1` | Synthetic negative tests. No live provider, GitHub, network, VM, runner, service, privilege, shell or file writes. |

## Fail-closed reason codes (all DENY)

`CONTRACT_SHAPE_INVALID`, `OPERATION_NOT_ALLOWED`, `RUNNER_CLASS_MISMATCH`,
`PROFILE_MISSING`, `PROFILE_UNKNOWN`, `PROFILE_UNASSIGNED`, `LEGACY_HOST_LABEL_SPOOF`,
`CROSS_HOST_CLEANUP_REFUSED`, `DUPLICATE_CONTROLLER`, `CONTROLLER_MISSING`,
`MULTIPLE_ACTIVE_HOSTS`, `WRONG_HOST`, `RECEIPT_MISSING`, `RECEIPT_MALFORMED`,
`RECEIPT_HOST_MISMATCH`, `PROVENANCE_MISSING`, `PROVENANCE_MALFORMED`,
`RECEIPT_PROVENANCE_DRIFT`, `GENERATION_STALE`, `ASSIGNMENT_DISABLED`.

The last code is the **only** outcome for an otherwise fully consistent request,
because every profile is disabled. There is no ALLOW result and no promotion path.

## Explicit risk boundaries

- **No imports into protected runtime.** `ci-dispatch/Dispatch.psm1`, `profiles.json`,
  `ci-runner/**`, accepted controller snapshots, workflows and pinned protected files
  are untouched. No `#269` `ACCEPTED_CONTROLLER_CHANGED` gate is exercised.
- **No Host1 residue interaction.** No `ldw01` receipt, label, root, lock, guest,
  baseline or cleanup is imported or acted on. #264 remains HOLD; LDW01 offline does
  not waive it. Fallback is null and cannot be set automatically.
- **No trust-class downgrade.** Trusted-private persistent runners are recorded only
  as a non-matching runner class; they cannot satisfy an isolated JIT profile.
- **No dual host, no queue claim.** Exactly one host ID (`officepc`) is allowlisted
  and it is disabled; duplicate controller and multiple-active-host inputs refuse.
- **No security theater.** The decision function is a data-returning pure function
  with `claimIssued`, `provisioningAuthorized` and `queueMutated` hard-set to false.
  It is not an authoritative verifier and must not be represented as one.

## Proposed future integration points — documentation only, NOT implemented

1. After accepted #269 issuer/generation and #186 bootstrap, a separately reviewed
   change may bind a host-local signed receipt to a pinned controller generation.
2. A distinct owner/security decision is required for any OfficePC-specific label
   contract; `ldw01` is recorded as a legacy label that must be refused, not reused.
3. #86 representative reserve/CPU/storage/recovery and Secure Boot DISABLED
   disposition remain open. No capacity constant from this folder is a reserve decision.
4. Runtime proof would be a separate, narrowly scoped synthetic JIT with exact-owned
   cleanup — never a migration of protected BO/Royal consumers.

Running the contract tests (PowerShell 7 only, no policy bypass, local fixture only):

```powershell
pwsh -NoProfile -File .\ci-dispatch\host2\tests\Test-Host2AssignmentD0.ps1
```
