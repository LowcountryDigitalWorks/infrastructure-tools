# REDRIX A0 — flushed TEMP journal interrupted-write and replay HOLD proof

**DRAFT / SOURCE_ONLY / NOT A PROTECTED ISSUER.** Owning authority: [#186 owner ACCEPT_A0_SOURCE_ONLY](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051), exact seven clauses from PR321 §6a. This is not a second production parent ACL implementation, privileged journal publisher or live recovery operation.

## Why this separate experiment exists

Existing accepted-main in-memory migration rehearsal at `host-agent/deploy/RedrixLdwParentAclMigrationTransaction.ps1` already tests typed ledger fields, forged pins, missing children, invalid stages and refuses physical apply. The [PR323 synthetic journal](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/323) creates one relative-handle current-user TEMP journal, validates its at-create ACL on the original handle and flushes PREPARED. Neither proves **what bytes a subsequent process reads from an interrupted on-disk PREPARED/COMMITTED sequence**. This fixture fills that one negative source gap, without implementing real recovery.

Microsoft documents [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers), [flushing system-buffered I/O](https://learn.microsoft.com/en-us/windows/win32/fileio/flushing-system-buffered-i-o-data-to-disk) and [FileStream.Flush](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.flush): file buffers should be explicitly flushed for critical records. This fixture uses FileStream.Flush(true) with WriteThrough, but **does not prove physical power-cut durability, metadata persistence, torn-sector guarantees, filesystem behavior across all hosts or authenticated source provenance**.

## Implementation and test boundaries

`host-agent/deploy/tests/Test-RedrixLdwJournalTornWriteTemp.ps1` accepts **zero arguments** and requires native Windows PowerShell 5.1 x64. It only creates a random GUID-owned disposable TEMP directory and one fixed-leaf `redrix-ldw-parent-acl-once.journal` inside that directory, with CreateNew, exclusive FileShare.None, FileStream WriteThrough and explicit flush-to-disk requests. It never touches the real %ProgramData%/LDW ancestor, protected PrivilegedControl, task, issuer, owner/group, system journal, ACL, credentials, VM, CI7 guest, runner or GitHub provider.

A deliberately **keyless** SHA256 of bounded pipe-delimited records detects accidental byte changes; a hash has **NO cryptographic authority** and cannot authenticate an attacker-controlled journal. A well-formed PREPARED must classify HOLD_PREPARED_UNRESOLVED. Even a fully well-formed COMMITTED record is **HOLD_COMMITTED_UNTRUSTED**, never an apply/rollback/recover command. All other states are HOLD.

The fixture tests source-only:
- a non-existent file, CreateNew collision and strict exclusive creation;
- same-open-handle flushed PREPARED and COMMITTED readbacks;
- closed/reopened file classification (simulates reader turnover, not a reboot);
- physical TEMP journal truncation after a flushed COMMITTED append;
- missing PREPARED, interrupted append, duplicate PREPARED or COMMITTED, CR drift, pinned preimage and child hash drift, foreign journal ID, a recomputed attacker-controlled keyless checksum, and a corrupted checksum;
- bounded ASCII/UTF-8 string shapes, exact sequence and frozen source-identity pins.

Output does not contain any local owner ID, device path, token or receipt. It emits `REDRIX_A0_TORN_JOURNAL_POWER_CUT_PROVEN=FALSE`, `REDRIX_A0_TORN_JOURNAL_SYSTEM_OWNER_PROVEN=FALSE` and `REDRIX_A0_TORN_JOURNAL_PHYSICAL_AUTHORITY=HOLD_SECURITY` regardless of a successful TEMP test.

This does **not** establish that a future protected issuer can create a SYSTEM-owned, exact `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)` journal at creation, nor that a true crash after parent mutation is safe. The production source must still have approved actor identity and privilege, independently trusted D0 initial root, hostile path ancestry binding (including the [user-mode OBJ_DONT_REPARSE documentation gap](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6994028541)), exact owner/group/DACL **on the same at-create handle**, durable transaction intent and before/after parent/child/task pins, a separately reviewed/no-replay recovery policy and exact owner-admin authorization.

## Next gate

Use existing Windows hosted CI and independent author-excluded exact-head security review to accept the **research-only fixture**, not a protected executable mutator. Retain PR in DRAFT/UNMERGED state, avoid source-author native approval, no privilege change, no Task Scheduler trigger or paid service. Proceed on actual #186 D0 trust/token and #269/#264/REDRIX #139/#96 admission as separate decisions.

$0 / included only.
