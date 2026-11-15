# Optional Chat Relay restart journal

Status: SOURCE-ONLY / SYNTHETIC / NOT DEPLOYED.

The default mailbox in `relay.py` stays in memory. This adapter runs only when a trusted local caller opts in with `local-sqlite-synthetic-public`. It is not a service, public listener, plugin, Site connector, or second message bus.

Accepted transport status remains `IN_MAILBOX` and `MANUAL_OR_TOOL_POLL_REQUIRED`. A stored row is not `CHAT_STARTED`, an automatic wake, or `IR_PASS`.

The journal may store synthetic public message text and the trusted role names needed to enforce that text. It does not store the master secret, HMAC tokens, or bearers. The role roster comes only from the trusted constructor argument. Message content cannot add a role.

Restart durability uses a persisted wall-clock high-water mark. A clock that moves backward cannot extend a TTL or restore an expired UUID. SQLite uses a delete journal rather than WAL. On reopen it permits *only* a single correctly owned/typed SQLite rollback `-journal` file for SQLite crash recovery, then requires its removal after recovery and verifies the keyed complete-state commitment. WAL/SHM, unexpected sidecars, symlinks, non-regular files, schema mismatch or failed integrity checks remain refusals. The named rollback candidate must be a regular file with a bounded SQLite journal header shape before the database is opened; after sealed-state readback, the adapter performs one same-value SQLite transaction to retire an otherwise cold zero-header journal and verifies the keyed state again. This allowance does not authorize a caller-selected sidecar or relax the separate ancestor/reparse-point requirements.

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
