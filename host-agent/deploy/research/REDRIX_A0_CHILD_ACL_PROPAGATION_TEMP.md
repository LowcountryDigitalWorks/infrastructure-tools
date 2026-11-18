# REDRIX A0 — child ACL propagation TEMP experiment

**Status:** DRAFT synthetic Windows 5.1 test, NOT protected LDW host proof; no physical authorization. Owner gate: [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051), A0 SOURCE_ONLY. This experiment addresses the specific child collateral-effect finding in [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6941521727). Related immutable-issuer and held recovery gates: #269/#264, and REDRIX #139/#96.

## Motivation

The accepted-main synthetic LDW parent DACL target contains inheritable OI/CI ACEs. Windows SetSecurityInfo automatically propagates such ACEs to existing inheriting descendants; a protected child with SE_DACL_PROTECTED should resist inheritance. Importantly, Microsoft also documents a misleading negative case: when a parent is opened exclusively, child propagation may be suppressed. A passing post-image alone cannot establish that the actual protected six children were immune.

Official references:
- [Automatic Propagation of Inheritable ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/automatic-propagation-of-inheritable-aces)
- [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
- [ACE Inheritance Rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules)

## Exact source experiment

A no-arg native Windows PowerShell 5.1 x64 fixture creates a **random GUID-owned tree under process TEMP** with one parent, a DACL-protected child plus grandchild, and a separate inheritance-enabled child plus grandchild. It initially grants only the fixture's current user full control inheritable within the tree. All objects are fixture-created: no external path parameters, protected task, ProgramData, LDW directory, VM, runner, JIT, other host resources, or passwords.

The fixture opens the *synthetic parent* using Win32 CreateFileW with READ_CONTROL + WRITE_DAC + FILE_READ_ATTRIBUTES and share READ + WRITE + DELETE. It deliberately does NOT open with MAXIMUM_ALLOWED, and does not open with exclusive sharing that could suppress inheritance propagation. It then uses SetSecurityInfo on **that still-open TEMP-only parent handle** with DACL_SECURITY_INFORMATION + PROTECTED_DACL_SECURITY_INFORMATION and a fixed source-built surrogate DACL:

- current *fixture user* full-control ACE, OI/CI
- Everyone ReadAttributes ACE, OI/CI
- protected DACL

The surrogate is deliberately **not** the production SYSTEM-owner/Administrators journal SDDL or the accepted LDW parent target. Current user SID is used only to ensure the disposable fixture can be cleaned up. No owner/group change, SeRestore privilege enabling, impersonation, token adjustment, or task elevation.

The source reads parent OWNER/GROUP/DACL on the *same held parent handle* via GetSecurityInfo before and after the TEMP parent DACL mutation, and checks parent owner/group unchanged and protected DACL. It then asserts:

1. protected child's exact SDDL is unchanged;
2. protected child's grandchild exact SDDL is unchanged;
3. unprotected child and grandchild SDDL **change**;
4. both unprotected descendants **inherit** the new Everyone ReadAttributes ACE;
5. both protected descendants do **not** inherit that ACE.

Any unexpected behavior fails the fixture, rather than treating a skipped propagation as security proof. Only the GUID-owned TEMP tree may be deleted, after the handle is closed. Output uses bounded statuses only, no identities or full ACL strings. Unconditionally emits REDRIX_A0_CHILD_PROPAGATION_LDW_PROVEN=FALSE and REDRIX_A0_CHILD_PROPAGATION_PHYSICAL_AUTHORITY=HOLD_SECURITY.

## Validation and boundary

This experiment exercises real Windows TEMP inheritance semantics on GitHub-hosted Windows, not a simulated mock of SetSecurityInfo. It is intentionally nonprivileged and does not mutate LDW01 ProgramData. Green Windows CI and an author-excluded source review show only **source research**. They do not prove the six production LDW children are DACL-protected or safe from collateral propagation under the intended execution token. An exclusive parent open (and MAXIMUM_ALLOWED) can suppress propagation, so real action safety must be analyzed under its *actual* handle rights/shares, not inferred from a TEMP case.

The previous approved source-only PR #323 proves a separate **current-user** NtCreateFile journal, #324 covers synthetic ancestor/rename races, and #325 classifies hosted current process SeRestore privilege. These do not provide the SYSTEM-owned at-create journal, immutable actor, protected D0 source issuer, accepted D1 signer or verified physical root. Existing Test-RedrixLdwParentAclMigrationTransaction.ps1 tests the MOCK interrupted ledger; this fixture does not duplicate it or claim to establish durable real crash recovery.

**Next gate:** retain HOLD_SECURITY until (a) exact six-child protected-state readback and propagation analysis under authorized trust, (b) immutable issuer actor with required enabled token capability, and (c) exact SYSTEM-owned journal at-create + same-handle verification, bounded durable recovery and real parent identity are source reviewed. Physical ACL action requires separate owner approval. CI7 cleanup and REDRIX JIT remain separately blocked.

**Cost:** $0/included hosted Windows only. No package installation, credentials, secrets, new listener, agent, schedule or paid service.
