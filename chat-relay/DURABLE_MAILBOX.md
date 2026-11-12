# Optional Chat Relay restart journal

Status: SOURCE-ONLY / SYNTHETIC / NOT DEPLOYED.

The default mailbox in `relay.py` stays in memory. This adapter runs only when a trusted local caller opts in with `local-sqlite-synthetic-public`. It is not a service, public listener, plugin, Site connector, or second message bus.

Accepted transport status remains `IN_MAILBOX` and `MANUAL_OR_TOOL_POLL_REQUIRED`. A stored row is not `CHAT_STARTED`, an automatic wake, or `IR_PASS`.

The journal may store synthetic public message text and the trusted role names needed to enforce that text. It does not store the master secret, HMAC tokens, or bearers. The role roster comes only from the trusted constructor argument. Message content cannot add a role.

Restart durability uses a persisted wall-clock high-water mark. A clock that moves backward cannot extend a TTL or restore an expired UUID. SQLite uses a delete journal rather than WAL so `-wal` and `-shm` sidecars are not left beside the database. Any extra file, symlink, non-regular file, schema mismatch, or failed integrity check refuses the journal.

On POSIX the directory must be mode `0700` and the database mode `0600`, both owned by the current user. This proof does not create an account, a scheduled task, or a privileged helper.

Rollback is to stop passing the opt-in and delete the disposable directory. The in-memory relay does not read that directory.
