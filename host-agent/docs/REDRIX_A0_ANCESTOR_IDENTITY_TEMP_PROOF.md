# REDRIX A0: ancestor identity TEMP-only proof

**DRAFT RESEARCH ONLY. NO PRODUCTION ACL TRANSACTION OR PRIVILEGED SOURCE.**

The controlling [#186 owner decision](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051) accepts only A0 source development under [PR321 §6a, immutable head 8877c79c](https://github.com/LowcountryDigitalWorks/infrastructure-tools/blob/8877c79c52ac5bfbe6a9d9cc34594311482d6a69/dragonfly-jit/REDRIX_LDW01_ISSUER_D0_CONTRACT_PROPOSAL.md). GM Normal—Codex author request 877975b2-008e-417f-96a5-259df1c56217 returned HOLD_SECURITY without a PR, citing insufficient proof of the hostile real ProgramData ancestor chain and SYSTEM-owned journal creation. This candidate narrows ONLY the first uncertainty, and is not a real ACL mutator.

## Exact TEMP experiment

The only new executable is host-agent/deploy/tests/Test-RedrixLdwAncestorIdentityTemp.ps1 in an ordinary hosted Windows PowerShell 5.1 x64 job. It has NO arguments and writes/deletes only its newly created GUID-named directory under runner TEMP, explicitly refusing the OS ProgramData tree. It never imports or runs production privileged source.

The fixture uses Win32 CreateFileW FILE_FLAG_BACKUP_SEMANTICS + FILE_FLAG_OPEN_REPARSE_POINT, share READ|WRITE but deliberately NOT DELETE, and two **distinguished access classes**. An attribute-only `FILE_READ_ATTRIBUTES` handle on a disposable control sibling is observed with a rename attempt; the outcome is recorded as `A0_TEMP_ATTRIBUTE_ONLY_RENAME=ALLOWED|DENIED`, not treated as a security result. Microsoft documents that access requests for attributes are not affected by normal sharing mode. Separately, it opens the synthetic root/ancestor/child and an **isolated ancestor** with `GENERIC_READ` substantive access and no delete sharing. It then tests the child and isolated ancestor rename outcomes **independently**, before any assertion is allowed to abort the test, outputting `A0_TEMP_GENERIC_READ_CHILD_RENAME` and `A0_TEMP_GENERIC_READ_ANCESTOR_RENAME`. Only explicit denial of BOTH strong-handle moves, stable handle file identities, and unchanged paths may yield `REDRIX_A0_ANCESTOR_IDENTITY_TEMP=PASS`. `GetFileInformationByHandleEx(FileIdInfo)` supplies volume+128-bit object identities; `FileAttributeTagInfo` checks reparse, `GetFinalPathNameByHandleW` checks the synthetic child path, independent opens must match their object, and an unheld control rename must succeed.

**Failure history and independent M1:** Initial PR #324 head `429c79dd31f30403ec5a501efba633e6edcbac32` failed hosted Windows job 132703303225 at `A0_TEMP_IDENTITY_ASSERT_CHILD_RENAME_REFUSED_HELD_HANDLE`. Independent author-excluded IR request `ecd0001e-6de3-4f9d-ace3-b3f8a3327d44` returned `CHANGES_REQUIRED H0/M1/L0`: the old fixture used attribute-only access, assumed that no `FILE_SHARE_DELETE` must block `.NET Directory.Move`, and aborted before testing the ancestor. The revised test does not hide that negative or claim production safety; it isolates attribute-only from GENERIC_READ, and separately observes both move cases. The exact resulting behavior must be verified on hosted Windows before any review or source claim.

## Security limits (HOLD remains)

- Even if **GENERIC_READ** handles deny synthetic TEMP rename, that does NOT prove the real inherited-write ProgramData/LDW directory chain is safe against pre-existing delete-capable handles, ancestor reparse swaps, impersonation or race windows. A future implementation must independently pin each canonical ancestor, verify object/owner/DACL and preserve no-delete-sharing handles across one exact mutation and same-handle readback, with explicit refusal on drift.
- This fixture creates NO journal and does NOT test an Administrator/SYSTEM security token. The exact SYSTEM-owner/group and two protected SYS/BA full-control ACEs frozen in §6a require at-create proof on the actual journal handle under a separately approved execution identity. The current-user journal fixture in [PR323](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/323) is not that authority.
- It does not call Set-Acl, SetSecurityInfo, AdjustTokenPrivileges, task launch, owner-admin bootstrap, GitHub JIT, VM, CI7 or any privileged operation. It does not authorize a real parent-ACL transition.
- Source reviews must separately challenge durable PREPARED/COMMITTED semantics, interrupted journal recovery, child ACL propagation and parent DACL canonicalization.

## Dependency path

1. Independently validate exact-head hosted TEMP Windows tests and security checks; obtain author-excluded source H0/M0; keep this PR **DRAFT/UNMERGED**.
2. Resolve the missing production ancestor-chain and SYSTEM at-create journal owner/token authority **without changing the approved journal SDDL or silently enabling privileges**. If not demonstrable, retain HOLD_SECURITY and do NOT publish an unsafe executable transaction.
3. After a separately reviewed one-action source candidate and distinct owner authorization, migrate only the LDW parent, verify all six child DACLs/task, then reuse the accepted V2 Stage under the existing November 9 one-shot bootstrap consent.
4. Preserve the unrelated D0/D1 issuer, #139 A4, #96 guest memory, #269 immutable controller and #264 CI7 holds.

Official API references: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex), [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info), [GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew).

$0/included only. No production system or account changes, privileged files, V2 install, runner or spend.
