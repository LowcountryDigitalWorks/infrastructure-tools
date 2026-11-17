# Optional Chat Relay restart journal

Status: SOURCE-ONLY / SYNTHETIC / NOT DEPLOYED.

The default mailbox in `relay.py` stays in memory. This adapter runs only when a trusted local caller opts in with `local-sqlite-synthetic-public`. It is not a service, public listener, plugin, Site connector, or second message bus.

Accepted transport status remains `IN_MAILBOX` and `MANUAL_OR_TOOL_POLL_REQUIRED`. A stored row is not `CHAT_STARTED`, an automatic wake, or `IR_PASS`.

The journal may store synthetic public message text and the trusted role names needed to enforce that text. It does not store the master secret, HMAC tokens, or bearers. The role roster comes only from the trusted constructor argument. Message content cannot add a role.

Restart durability uses a persisted wall-clock high-water mark. A clock that moves backward cannot extend a TTL or restore an expired UUID. SQLite uses a delete journal rather than WAL. On reopen it permits *only* a single correctly owned/typed SQLite rollback `-journal` file for SQLite crash recovery, then requires its removal after recovery and verifies the keyed complete-state commitment. WAL/SHM, unexpected sidecars, symlinks, non-regular files, schema mismatch or failed integrity checks remain refusals. The named rollback candidate must be a regular file with a bounded SQLite journal header shape before the database is opened; after sealed-state readback, the adapter performs one reversible transaction (insert and delete a fixed temporary metadata key), then re-verifies the original HMAC-bound state before commit; SQLite itself retires the cold zero-header journal. A no-op UPDATE is insufficient. This allowance does not authorize a caller-selected sidecar or relax the separate ancestor/reparse-point requirements.

On POSIX the directory must be mode `0700` and the database mode `0600`, both owned by the current user. This proof does not create an account, a scheduled task, or a privileged helper.

Rollback is to stop passing the opt-in and delete the disposable directory. The in-memory relay does not read that directory.

## H1 draft integrity boundary (source-only candidate)

The proposed draft change commits to the *entire* SQLite message row set,
roster, wall-clock high-water value, schema and metadata with a domain-separated
master-secret-derived HMAC-SHA256. It verifies that commitment on reopen and
inside each write transaction before any read/mutation, then commits the new
digest in the same transaction. Unknown or unkeyed legacy journal files fail
closed rather than silently migrating. No bearer or key is stored.

This excludes casual offline SQLite row insertion, change, deletion, clock
metadata rollback and reopen with a different master secret. It cannot detect
rollback of an **entire previously valid database snapshot** without a separate
trusted monotonic source, nor protect against an attacker who also has the
in-process master secret. H1 evidence cannot waive the separate M1-M4/L1-L2
security-review findings or authorize deployment. The persistent adapter
remains opt-in, synthetic/public and UNMERGED until independent acceptance.

## Source proof limitations and operating holds

- **Time/expiry:** messages have a 15-minute TTL. Expiry garbage-collection removes rows and their UUID tombstones; after expiry a duplicate UUID can become a new message. A forward wall-clock jump can permanently expire messages, and the persisted high-water mark prevents clock rollback from extending that lifetime. Replies require an extant compatible prior message; replies after tombstone deletion may be refused.
- **Platform identity:** POSIX mode 0700/0600 checks do **not** establish Windows NTFS DACL ownership or reparse-point protection. This source uses Python pathname-based SQLite open; even a clean symlink inspection does not alone prove an ancestor path or DB object cannot be swapped between check and SQLite open. Windows and POSIX M3 path/identity, junction/symlink race and protected-ACL proof remain **NOT ACCEPTED**. Do not deploy persistent adapter based only on synthetic M1/H1 test success.
- **Delivery semantics:** a journal write reports IN_MAILBOX, not an automatic wake of any other ChatGPT conversation or proof that an authorized receiver executed a task. Manual or tool polling remains required until a separately proven orchestration receiver exists.

## Source-only static path checks (partial M3 mitigation)

The draft checks every directory ancestor for a POSIX symbolic link or a
Windows-reported reparse-point attribute, before creating or opening the
journal. A synthetic reparse-attribute fixture and an actual grandparent-link
negative test cover this *static* screening. Database magic is read with a
16-byte bounded read rather than materializing the entire local file.

**The M3 runtime/security hold remains:** these pathname-based checks are not
atomic with SQLite's later filename-based open; directory/file rename races,
Windows NTFS DACL/owner enforcement, junction substitution and live handle-
identity verification have not been proven. Source-only tests cannot authorize
a persistent host deployment. Valid whole-database snapshot replay also
remains outside the in-database HMAC's rollback protection.
