# REDRIX / LDW01 — D0 actor selection and protected initial bootstrap

**STATUS: GATE A DESIGN CANDIDATE, SOURCE ONLY, DRAFT. NO OWNER PHYSICAL APPROVAL.**
**Current classification: D0_TRUST_ROOT_ABSENT / HOLD_SECURITY.**

Owning authority: [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), [owner ACCEPT_A0_SOURCE_ONLY](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051), exact seven constraints in [PR321 §6a frozen head 8877c79c](https://github.com/LowcountryDigitalWorks/infrastructure-tools/blob/8877c79c52ac5bfbe6a9d9cc34594311482d6a69/dragonfly-jit/REDRIX_LDW01_ISSUER_D0_CONTRACT_PROPOSAL.md). Related trust gates: #52, #176, #269; incident #264; REDRIX #139/#96. This is not an installation plan authorizing execution, an executable mutator, a new signed publisher, or a reason to lift the PR320 fail-before-JIT HOLD.

## 1. Frozen technical facts

The accepted installed no-trigger V1 task named LDW-ADMIN-REVIEWED-OPERATION is bound to the owner SID, not LocalSystem. The current accepted Manage-AdminPrivilegedHelper.ps1 validates its principal, logon type and elevated run level. Invoke-AdminPrivilegedOperation.ps1 exposes a closed registry with only the accepted ELEVATED_IDENTITY_PROOF operation. Its prior privileged success demonstrates this ONE operation; it does not install any reviewed publisher or authorize an arbitrary replacement operation. Accepted V2 publisher and Stage source from PR292/295 was last physically observed NOT INSTALLED; new source in a mutable checkout, a GitHub App comment or a bare hash cannot make a protected initial issuer.

SeRestorePrivilege permits setting an arbitrary owner SID; the effective privilege must be enabled, not inferred merely from Administrator-group elevation. PR325 classifies only a hosted process token and does not prove the *future protected V1 or D0 actor token*. Neither impersonation, silently enabling the privilege, nor modifying the existing V1 task principal is approved.

Frozen journal requirement is creation-time owner SYSTEM and group SYSTEM with exactly two protected full-control allow ACEs (SYSTEM, Administrators), SDDL O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA), fixed checksum 217a5b5e3003c8c17a60d7ac4dfe6334c4a4e036ddb4a6431f102f4c1bd8f223, fixed leaf under already trusted PrivilegedControl handle. Create-only, same-handle readback of owner/group/ACE/control flags, PREPARED durable BEFORE any parent ACL mutation, six-child/task/preimage parity, COMMITTED durable after one separately authorized parent-only mutation, and fail-closed replay/partial recovery remain mandatory. Changing SYSTEM ownership AFTER creation, or settling for owner-SID, is noncompliant.

## 2. Alternatives — both HOLD until independent security acceptance

| Route | Preserves existing V1 principal? | Required conditions | Current decision |
| --- | --- | --- | --- |
| A. Owner-SID closed elevated actor | Yes | A separately trusted D0 first-install/promotion with immutable code and exact one-operation registry; proof from the ACTUAL intended execution token of already-enabled SeRestorePrivilege or equivalent explicitly accepted capability to create the frozen SYSTEM-owned journal at creation, without adjusting privilege; stable parent ancestry; exact source pins | HOLD — installed registry cannot mint new source; task-token capability absent |
| B. One owner-attended, fixed-purpose LocalSystem bootstrap | Yes, V1 unchanged | New separately approved first-install verifies fixed independently reviewed source OUTSIDE owner-writable LDW ancestor, seals exactly one zero-input/no-trigger constrained SYSTEM executor, proves task principal/action/code ACL and same-handle journal create/readback, enforces distinct physical parent action approval, deauthorizes one-shot task after protected receipt | PREFERRED DESIGN CANDIDATE for separate owner/security review, NOT authorized or installed |
| C. Owner-supplied code/path, generic SYSTEM updater, hash-only or GitHub App metadata-only proof, new persistent broad service | No credible trust boundary | Rejected by #186 trust model | REJECT |
| D. Change journal owner/group/ACE, alter V1 principal or silently toggle SeRestorePrivilege | Violates frozen A0 | Would require a new explicit contract and owner approval, not implied by this design | NOT AUTHORIZED |

The SYSTEM option is technically possible in Task Scheduler with an Administrator-registered service-account task according to Microsoft, but the Task Scheduler mechanism **does not authenticate source by itself**. A local SYSTEM process also does not automatically prove the frozen journal GROUP/DACL or hostile ancestor identity; creation-time explicit descriptor and SAME-HANDLE verification are still mandatory. No new task may be registered under A0. An attended single installation, if separately authorized, avoids recurring UAC but is not the same as inventing unattended bootstrap power.

## 3. Non-negotiable D0 bootstrap chain

1. Freeze an exact independently accepted source package: repository ID, immutable commit/tree/blob, frozen file SHA256, one reviewed launcher, zero parameters, reviewed task identity/principal/action/executable/arguments, protected install location, rollback/version and expiry. A SHA selected by the same owner-writable caller is NOT authentication. Do not create new signers, GitHub apps, accounts or broad credentials.
2. Establish WHERE an already approved owner-attended verifier authenticates those initial bytes before any privileged execution. Staging in current owner-writable LDW ancestor is NOT an immutable source trust root, even when one child has its own DACL. Verify all relevant ancestor directory identities, handles, final names, reparse/security state and no substitution between check, stage, and launch. If the verifier/launcher is itself owner-writable, HOLD.
3. A future actor/Task Scheduler principal proof is necessary: existing V1 must remain untouched; any B executor is separately authorized, single-use, no trigger/timer/poller, no user-supplied program/args/ref/env/path/URL, no writable executable alias, bounded task ACL, one protected operation, independent action and source digest readback. For A, the ACTUAL trusted actor token must have already-enabled required capability. For B, read back actual SYSTEM principal and exactly created journal owner/group/ACE.
4. Bind OS-known-folder ProgramData/LDW and every hostile ancestor using source-controlled exact expected identities; verify expected parent preimage SDDL SHA and the SIX exact DACL-protected child SDDL SHA pins and V1 Ready/zero-trigger task before and after. The user-mode NtCreateFile function-specific documentation does not expressly establish a cross-version atomic hostile-namespace guarantee for OBJ_DONT_REPARSE plus filesystem RootDirectory. Independent #186 finding 6994028541 says this is an INCOMPLETE FUNCTION-SPECIFIC CONTRACT, not proof the flag is unsupported. If a trusted protected/nonattacker-writable ancestry or explicit narrower accepted threat model is unavailable, HOLD.
5. Under one held verified PrivilegedControl handle, create ONLY the fixed journal, use exact SYSTEM owner/group and protected two-ACE DACL at creation, verify same-open-handle descriptor, check an existing journal collision as HOLD, and persist PREPARED before one parent DACL mutation. No after-the-fact owner fix, alternate filename or fallback privilege elevation. Fail closed if durable PREPARED, parent/root, child, actor, task or publisher readback differs. A keyless SHA256 checksum is NOT authenticity.
6. Require independent exact-head H0/M0 source review and a DISTINCT owner-admin authorization for the exact PHYSICAL LDW parent-only mutation. Source-only A0, prior November 9 fixed V2 bootstrap consent, conditional November 4 one-shot REDRIX canary consent, and existing owner same-account GitHub approval policy are NOT this new physical approval.
7. D1 future approved publisher remains distinct: reuse already merged PR292/295 Stage source only after independently accepted D0; require monotonic signed generation and separately accepted signer/review policy. GitHub Actions, GitHub App attribution, self-reviews, source digest or mutable Git refs alone cannot promote privileged source.

## 4. Strict rejection matrix and execution roadmap

| Fail-closed status | Missing evidence |
| --- | --- |
| HOLD_ACTOR_TOKEN_UNVERIFIED | No readback from the actual fixed protected actor's effective token. Normal-user shell or GitHub-hosted token does not count |
| HOLD_REQUIRED_OWNER_CAPABILITY | Intended actor cannot assign exact SYSTEM owner+group at creation without an unapproved privilege adjustment |
| D0_TRUST_ROOT_ABSENT | No accepted independently authenticated first-install verifier or immutable actor source |
| DOCUMENTED_NAMESPACE_CONTRACT_UNRESOLVED | Real adversarial ancestry and namespace race not handled by an accepted threat model / provenance |
| HOLD_PARENT_OR_CHILD_DRIFT | Preimage root, six protected child pins, or fixed no-trigger V1 task differs |
| HOLD_JOURNAL_CREATE_OR_RECOVERY | Exact at-create owner, group, protected DACL, PREPARED, COMMITTED, collision, replay or partial state ambiguous |
| HOLD_SEPARATE_PHYSICAL_OWNER_APPROVAL | Exact physical parent operation has no separate authorized owner-admin decision |

**Phase A (NOW):** independent security challenge of these route choices. Source docs only, no tasks, host token reads or production source mutator. Resolve if route A is actually admissible; otherwise prefer carefully scoped B *for a future new exact approval* while preserving V1.

**Phase B (only after accepted A):** author ONE fixed zero-argument WinPS5.1 x64 parent-only transaction SOURCE candidate under the seven accepted A0 requirements, deterministic negative tests and hosted CI. Reuse accepted PR323/324/325/328/332 research rather than duplicate the no-privilege test suites. No host operation merely because source tests pass. If the trust root or namespace model is unsatisfiable, return HOLD_SECURITY instead of unsafe executable source.

**Phase C (distinct future owner/security physical decision):** exact privileged D0 first-install and exact LDW parent ACL action with source/actor/ancestor journal readback and deterministic rollback/one-shot deauthorization. V1 task remains unchanged; if no valid first-install provenance, no execution.

**Phase D (downstream):** #269 independently protected CI7 six-file controller/generation and #264 exclusive locks/LOCAL_GUEST_REMOVE still held; #139 A4 root/FD, #96 guest-visible idle MemAvailable >=10,240MiB, and one verified secretless GitHub JIT+teardown remain separate. Do not consume conditional owner canary authorization or change production fail-before-JIT hold early. No duplicate automation.

Primary Microsoft references:
- [Privilege constants / SeRestorePrivilege](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [Privileges must be enabled](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
- [Setting owner restrictions](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
- [Initial security descriptors](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects)
- [Task Scheduler service-account security](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
- [System-account task creation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [NtCreateFile documented attributes](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)

**This PR is a reviewable design artifact only. No token mutation, elevation, installer, privileged task, SYSTEM journal, ACL, CI7, JIT, VM, credential, service, scheduler or money was used. $0/included. Owner action now: NONE.**
