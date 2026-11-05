# Gate B promotion: isolated non-authorizing data preflight

**Scope:** infrastructure-tools #186 / parent #52; accepted Gate A revision 2 at #186 comment 6591794708. This is a **small source/test component**, not a complete trusted promotion implementation.

## What is implemented

`PromotionDataPreflight.Check` is an internal pure C# policy in the existing Admin Broker library. It accepts synthetic data records and returns only `BLOCKED` or `DATA_ONLY_CONSISTENT_NOT_AUTHORIZED`; it does not return a privileged-operation success result. It rejects:

- wrong GitHub repo, synthetic ledger issue, immutable comment identity, **Bot** account type, exact 165-W login/user ID, decision schema, or authority type;
- bad source commit/tree/blob SHA-1, package/catalog SHA-256 and package size;
- rollback/skip/stale predecessor or an unreviewed catalog operation ID;
- missing/disabled/corrupt-looking protected state; any change to the protected disable generation, active generation/digest, or promotion-enabled state between pre-provider and immediately pre-swap observations;
- comments edited after creation; future/expired/>10-minute UTC authority; missing/ambiguous data.

The accepted operation registry currently includes **only ELEVATED_IDENTITY_PROOF**. This proof deliberately refuses a caller-selected new privileged operation such as `DRAGONFLY_V2_PUBLISH_REVIEWED`; adding that fixed implementation requires its own exact review and compiled catalog change, not a model-supplied string.

The test suite uses **fictional ledger issue 9001**. This value does not configure or authorize a real ledger. The real accepted ledger issue/immutable anchor has not been selected in this component. A caller of this internal pure method is not authenticated; its input facts are not trustworthy merely because they match in memory.

## What is NOT implemented or authorized

This module **does not** read GitHub, authenticate an API server response, parse an untrusted wire document, validate actual repository/PR/check/review facts, attest installed 165-W App permissions, hash/read immutable Git blob bytes, validate protected Windows ACLs/reparse points, install a package, open/modify a protected file, stage or activate anything, talk to the Admin Broker pipe or task, publish V2, call gh, invoke REDRIX, or change production/runtime. There is no production wire-up, entrypoint, registry change or executable dispatch surface.

**A matching data-only result MUST NOT be interpreted as approved, READY, PASS, installed, promoted, or authority to activate.** A future stable protected launcher must independently obtain and verify the data, pin the eventual ledger issue as an immutable source constant, check exact server-returned comment metadata, execute data-only validation, enforce same-volume admin-protected staging, immutable package digests, negative race/replay tests, explicit disable-before-provider and disable-at-swap, atomic pointer/readback and rollback behavior. It must never execute candidate package code during validation.

Separate accepted Gate A authorization is necessary but not sufficient. Owner approval for expanding the **existing 165-W GitHub App** to the selected `infrastructure-tools` repository is still a consequential **CURRENT → PROPOSED → ROLLBACK/RECOVERY** decision and was **not** requested, performed, or presumed by this source proof.

## Review / integration

Run the existing Host Agent/Admin Broker deterministic tests on Windows/Linux .NET 10, Secret Scan and CodeQL; require independent H0/M0 whole-source review and source-author exclusion on this exact head before any source merge. Review tests for spoofed principal, changed source/operation IDs, missing/corrupt state, mid-operation emergency disable, generation races, replay and TTL boundaries.

Only after this proof is accepted may the owning #186 writer integrate it with a reviewed stable protected launcher and the independently accepted authorizer/165-W ledger path. No service, schedule, new credential, paid provider, customer data or privileged host change occurs in this PR.

**Spend:** $0 incremental. **Owner action:** none for source/review. **Runtime status:** NOT_IMPLEMENTED.
