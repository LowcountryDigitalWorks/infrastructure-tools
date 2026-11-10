# REDRIX D1 — read-only LDW parent ACL preflight

**Classification: SOURCE-ONLY / OBSERVE-ONLY / NOT ACL AUTHORITY / NOT INSTALL AUTHORITY**

Owning issues: https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186, #139, #96. This is a bounded readiness observation for the existing LDW01 Windows protected V2 publisher, **not a production ACL migration**.

The owner-approved first-install does not authorize changing unrelated system ACLs. Do **not** modify the OS-wide C:\ProgramData DACL. On LDW01, its standard, protected ACL contains a BUILTIN\Users create/write inheritance ACE. The accepted V2 bootstrap source must recognize that stock OS root while still refusing unsafe control over the fixed LDW subtree.

## Source-only observer

- host-agent/deploy/Test-RedrixLdwParentAclReadiness.ps1 is fixed-path, has no caller arguments, and uses only Windows PowerShell 5.1 read operations (Get-Item, Get-ChildItem, Get-Acl, Get-ScheduledTask, managed-memory SHA-256, JSON output).
- It uses the machine-known CommonApplicationData folder, refuses process/machine-path disagreement, checks absence of reparse points at the fixed roots, and compares the *existing* %ProgramData%\LDW SDDL UTF-8 SHA-256 to a dated observation. **The pinned preimage is an exact drift detection value, not a trusted authority to modify an ACL.**
- It requires exactly six existing child directories. Every child must still be DACL-protected, SYSTEM/Administrators owned, have no broad-user write or generic write/all and match its separately captured SDDL hash. It confirms the existing reviewed operation task is Ready and triggerless; it never starts or edits that task.
- Success explicitly says READ_ONLY_PREIMAGE_MATCH_NOT_AUTHORIZED; any unexpected state, missing API, access failure, extra child, mismatched owner, permission or hash must return sanitized HOLD_READ_ONLY. Both outcomes say ACL and JIT authorization are false.
- It has no Apply, Repair, Commit, Rollback, path, account, or task selection mode. Running source from a user checkout **does not** elevate or authorize a later privileged script.

**Host evidence recorded November 9 ET:** %ProgramData%\LDW inherited BUILTIN\Users Write (ContainerInherit) with its DACL unprotected. All six existing children already had protected DACLs and no broad-user Write ACE. The owner-controlled task was Ready with zero triggers. Snapshot hashes and child inventory are recorded in issue #186 comments 6756451232 and 6756487433. They must be considered historical until freshly rechecked.

## Separate future ACL transaction — NOT implemented or authorized here

Any eventual owner-only protected action requires a new exact independent security review and a frozen source/byte identity. It may touch **only** the existing %ProgramData%\LDW parent. Its transaction design must:

1. Reconcile current live #186, #139, protected V1 task and lock state; stop if concurrent/in-flight operations, mismatched root owner, reparse/rename race, unexpected children or differing exact SDDL preimages.
2. Verify no approved normal-user feature depends on creating new children at the LDW parent. Preserve the fixed existing children and their exact protected DACLs.
3. Capture the original SDDL in a durable, access-controlled owner-only journal under the *existing* verified protected PrivilegedControl directory; fail closed on unavailable or ambiguous journaling.
4. Compute and independently review an exact target LDW-parent DACL before any write. Remove inherited BUILTIN\Users Write from **LDW only**, retain necessary read/execute and SYSTEM/Administrators rights, and prevent new insecure inheritance. Never edit stock C:\ProgramData or child DACLs.
5. If separately authorized, commit one bounded ACL change and re-read the exact new parent owner/DACL plus all six unchanged child SDDL hashes and existing V1 task identity. On any ambiguous result retain the journal and HOLD—no guessed automatic rollback.
6. Permit a separately reviewed fixed rollback to the original SDDL only with exact current-state and child identity guards. Never remove the evidence journal merely because a tool reports success.

After a security-accepted and host-proven ACL transaction, **different** gates still control the immutable V2 publisher first-install, protected receiver transfer, authenticated REDRIX A4 proc/FD evidence, guest-visible 2 GiB + 8 GiB memory policy, exact queued GitHub job admission and destructive cleanup.

## Validation and no-go boundary

Windows PowerShell 5.1 on LDW01 ran the 53-assertion static non-mutation contract and the live, read-only observer against pinned source. The observer reported six matching protected children and READ_ONLY_PREIMAGE_MATCH_NOT_AUTHORIZED. This establishes only the snapshot and script's current behavior, not robustness against every filesystem race or authority for system changes.

**No** Set-Acl, icacls, UAC/bootstrap invocation, SSH/keys, QEMU guest, runner dispatch/registration, task modification, new scheduled polling, credential, production change, new SaaS or paid compute is authorized by this artifact.
