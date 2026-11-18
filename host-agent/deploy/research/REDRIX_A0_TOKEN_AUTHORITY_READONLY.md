# REDRIX / LDW01 A0 — read-only current-token privilege research

**Status: DRAFT SOURCE EXPERIMENT. NOT OWNER/TRUST/PRODUCTION ACCEPTANCE.**

Owning security gate: [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186). Related: [REDRIX #139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), protected snapshot [#269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269), held CI7 guest [#264](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/264), and [A0-only owner consent](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051). The proposed journal descriptor and D0/D1 architecture in **draft** [PR #321](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/321) are not independently installed authority.

## Narrow question

The accepted V1 broker task principal is the **owner**, not SYSTEM. Being elevated Administrators does not prove a token contains an enabled SeRestorePrivilege. Microsoft documents both the privilege's arbitrary-owner semantics and the distinction between absent, present-disabled and present-enabled token privileges:

- [Privilege constants / SeRestorePrivilege](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [Token privileges and changing them](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)

The current A0 source-only experiment tests whether a **hosted Windows PowerShell 5.1 process** can read and strictly classify its own token. It does **not** test LDW01's future protected execution token; no output is reusable as machine-bound authorization.

## Implementation

The test at host-agent/deploy/tests/Test-RedrixLdwA0TokenReadOnly.ps1 accepts no parameters and requires native Windows PowerShell 5.1 x64. It opens **only the current process token** with TOKEN_QUERY (0x0008), obtains TokenPrivileges via GetTokenInformation, identifies only the fixed SeRestorePrivilege LUID, and closes the handle. No impersonation, privilege enabling, token adjustment or TOKEN_ADJUST_PRIVILEGES access is used.

It checks bounded count/byte length, duplicate privilege entries, removed/unknown attribute flags, and all three observed states: ABSENT, PRESENT_DISABLED, PRESENT_ENABLED. Ambiguous states are HOLD_AMBIGUOUS, not silently interpreted as privileges. It also determines **only as a boolean** whether the process principal is SYSTEM, without printing any identity or SID.

Eleven source-fixture assertions exercise normal states and adversarial invalid/ambiguous flags, then issue one hosted read-only live-token query. Only bounded status markers are emitted. Every possible state **unconditionally** emits:

- REDRIX_A0_TOKEN_PHYSICAL_AUTHORITY=HOLD_SECURITY
- REDRIX_A0_TOKEN_JOURNAL_AT_CREATE_PROVEN=FALSE

The existing hosted Windows Host Agent validation receives one additional early test step. Existing hosted CI, secret scan, CodeQL, CI controller snapshot pins and accepted runtime source are not altered. No REDRIX/LDW01 host, ProgramData/LDW, journal, task, ACL, runner, JIT provider, VM, credential, service, schedule, or security setting is touched.

## Acceptance boundaries / roadmap

1. Require actual exact-HEAD hosted Windows test result and all mandatory checks, plus an author-excluded independent H0/M0 source review. A source PR stays **DRAFT/UNMERGED** until review.
2. Independent Product/security must still freeze #186 source/trust requirements. A hosted runner result does not attest current LDW01 protected V1 task identity, enabled privilege, caller/source identity, ancestor handle stability, exact SYSTEM-owned journal at create, PREPARED/COMMITTED recovery, or D0/D1 issuer.
3. A future **separately approved** immutable trusted-token/actor preflight must run inside the actual approved fixed-purpose execution context and verify **its own** token without changing it, before any proposed real journal create or parent ACL transaction. If token authority is absent or disabled, report HOLD_SECURITY; do not compensate by enabling privileges or altering the fixed owner/group/ACE descriptor under this source approval.
4. Separately source-review and approve hostile real ProgramData ancestor integrity, exact journal owner/SDDL same-handle readback, crash recovery, six protected children/V1-task parity and atomic rollback. Only after accepted source and protected D0 issuer may the owner separately authorize an exact physical parent ACL transaction.
5. Retain independent REDRIX A4 process/FD, Crostini 10,240 MiB guest-visible floor, exact GitHub provider job and CI7 snapshot/lock/cleanup gates. Do not consume the previously conditionally approved one-shot canary.

**Cost:** $0 / existing included hosted checks only. No new paid tools, overage, credential, task, standing runner, privilege, or runtime mutation.
