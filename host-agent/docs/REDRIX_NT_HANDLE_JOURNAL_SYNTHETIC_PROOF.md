# REDRIX / LDW01 — Windows handle-relative journal feasibility proof

**Status: SYNTHETIC RESEARCH ONLY; NO PRODUCTION CODE; NOT A TRUST-CONTRACT FREEZE OR ACL TRANSACTION.**

Authority: [Admin Broker #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), [immutable controller #269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269), and [REDRIX #139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139). The prior author-distinct challenge found a MEDIUM gap in protected journal creation; the fresh architecture re-challenge returned RECOMMEND_FREEZE_SOURCE_ONLY, not authority to change a real host.

## Exact fixture scope

Only host-agent/deploy/tests/Test-RedrixNtHandleRelativeJournalFixture.ps1 executes as new code, on a hosted Windows PowerShell 5.1 x64 runner. The test refuses other runtimes, takes no arguments and creates a uniquely named disposable directory under runner TEMP. It explicitly rejects the machine ProgramData root and cleans up only its newly created TEMP directory.

The test opens its TEMP directory handle with CreateFileW using backup-semantics and open-reparse-point flags, and retains that handle during NtCreateFile. The NtCreateFile call binds OBJECT_ATTRIBUTES.RootDirectory to that directory HANDLE and ObjectName to an exact fixed one-component journal filename, with a self-relative SecurityDescriptor at creation, FILE_CREATE (not OPEN_IF), no sharing, synchronous write-through and reparse-refusal flags.

The test checks managed x64 structure layout sizes; requires STATUS_SUCCESS and FILE_CREATED; writes PREPARED and flushes/read-backs bytes on the same file handle; then invokes Win32 GetSecurityInfo on **that exact still-open journal handle** with OWNER | GROUP | DACL to read a bounded, LocalFree-managed security descriptor. It verifies fixture-user owner and group, a protected DACL with exactly one noninherited allow ACE for the fixture user, and the exact FullControl access mask. It does not reopen the journal by pathname for ACL evidence. A second FILE_CREATE must return exactly STATUS_OBJECT_NAME_COLLISION with no usable handle; a traversal path is rejected before native invocation. The fixture uses the ephemeral runner user's SID, not SYSTEM or Administrators, and requires no elevation.

**Passing proves only these exact Windows TEMP behaviors.** It is not a production security review, physical LDW01 result, first-install trust root or proof of race-free journal creation under the currently writable LDW ancestor. The test does NOT invoke Set-Acl, SetSecurityInfo, Windows Scheduled Tasks, installer, JIT generation, GitHub runners, REDRIX guests, CI7 cleanup, or any privileged operation.

## Remaining acceptance gates

Before production parent-ACL source authoring, owning Product/security Gate A must freeze the full D0 contract: immutable issuer and independent source approval, exact parent object identity and handle lifecycle, secure pinned PrivilegedControl directory, SYSTEM/Administrators journal owner/DACL on **handle-relative atomic create**, durable PREPARED before one parent mutation and COMMITTED only after exact same-handle GetSecurityInfo readback, child/task parity, journal replay and incomplete-commit HOLD, separately reviewed rollback. Hostile tests still need reparse/path-swap, partial writes, access denied, re-open and intermediate ancestor race cases. This isolated fixture is not sufficient on its own.

Before any physical action: independently accepted exact-head H0/M0 transaction source; signed/frozen issuer provenance and host readback; distinct one-time owner approval for the actual LDW parent ACL change. Owner previously approved one fixed V2 verifier/bootstrap; **that consent does not cover this separate parent mutation and should not be requested again**. PR #321 remains design DRAFT; accepted Stage source PR #292/#295 and nonauthorizing ACL rehearsal PR #303 are untouched. Keep #96 guest-visible admission, #139 A4, #269 controller and #264 CI7 recovery HOLD.

## First-party API references

- [Microsoft NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [Microsoft OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes)
- [Microsoft CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Microsoft GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo) and [GetSecurityDescriptorLength](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorlength) for the still-open fixture handle
- [Microsoft SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo) (not used in this research fixture)

No new credential, paid tool, source-promotion authority, ACL, task, JIT, runner, VM or customer data. $0/included only.
