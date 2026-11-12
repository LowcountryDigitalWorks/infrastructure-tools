"""Optional restart-durable journal for the local Chat Relay mailbox.

The default Mailbox stays in memory. This adapter is used only when a trusted
caller passes OPT_IN. It is not a service, listener, plugin, or deployment.
Status remains IN_MAILBOX / MANUAL_OR_TOOL_POLL_REQUIRED. It never means
CHAT_STARTED, an automatic wake, or IR_PASS.

The journal stores synthetic public message text and role names from the
trusted roster. It does not store the master secret, role tokens, or bearers.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from pathlib import Path
from threading import RLock

from relay import MAX_BODY, MAX_MESSAGES, TTL_SECONDS, Mailbox, RelayError, canonical_id, role_name

OPT_IN = "local-sqlite-synthetic-public"
STATUS_NOTICE = "IN_MAILBOX / MANUAL_OR_TOOL_POLL_REQUIRED"
_SCHEMA = 1
_APP_ID = 0x4C445744
_DB_NAME = "journal.sqlite"
_FORBIDDEN = (
    "bearer ",
    "private key",
    "begin ",
    "ldw_chat_relay_secret",
    "api_key",
    "password=",
)


class DurableRefused(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DurableMailbox:
    def __init__(self, master_secret: bytes, journal_directory: Path, *,
                 opt_in: str, allowed_roles: tuple[str, ...] = (), clock=None):
        if opt_in != OPT_IN:
            raise DurableRefused("DURABLE_OPT_IN_REQUIRED")
        if clock is None:
            import time
            clock = time.time
        if not isinstance(journal_directory, Path):
            raise DurableRefused("DURABLE_PATH_REFUSED")
        self._clock = clock
        self._directory = self._private_directory(journal_directory)
        self._db_path = self._directory / _DB_NAME
        self._auth = Mailbox(master_secret, clock=clock, allowed_roles=allowed_roles)
        self._roles = self._auth._roles
        self._roster = hashlib.sha256(
            ("\n".join(sorted(self._roles))).encode("ascii")
        ).hexdigest()
        self._secret = master_secret
        self._lock = RLock()
        self._conn = self._open_db()

    def close(self) -> None:
        with self._lock:
            conn, self._conn = self._conn, None
            if conn is not None:
                conn.close()

    def token_for_role(self, role: str) -> str:
        return self._auth.token_for_role(role)

    def authenticate(self, role: str, provided: str) -> None:
        self._auth.authenticate(role, provided)

    def send(self, actor: str, data: dict) -> dict:
        if not isinstance(data, dict) or set(data) - {
            "message_id", "sender", "recipient", "body", "reply_to"
        }:
            raise RelayError(400, "INVALID_ENVELOPE")
        if not {"message_id", "sender", "recipient", "body"} <= set(data):
            raise RelayError(400, "INVALID_ENVELOPE")
        msg_id = canonical_id(data["message_id"])
        sender = role_name(data["sender"])
        recipient = role_name(data["recipient"])
        if sender != actor or sender == recipient or sender not in self._roles:
            raise RelayError(403, "ROLE_MISMATCH")
        if recipient not in self._roles:
            raise RelayError(403, "ROLE_NOT_REGISTERED")
        body = self._public_body(data["body"])
        reply_to = data.get("reply_to")
        if reply_to is not None:
            reply_to = canonical_id(reply_to)
        return self._transaction(lambda: self._send_row(
            msg_id, sender, recipient, body, reply_to
        ))

    def receive(self, actor: str, limit: int = 20) -> dict:
        if actor not in self._roles:
            raise RelayError(403, "ROLE_NOT_REGISTERED")
        if not isinstance(limit, int) or not 1 <= limit <= 20:
            raise RelayError(400, "INVALID_LIMIT")
        return self._transaction(lambda: self._receive_rows(actor, limit))

    def acknowledge(self, actor: str, message_id: object) -> dict:
        if actor not in self._roles:
            raise RelayError(403, "ROLE_NOT_REGISTERED")
        mid = canonical_id(message_id)
        return self._transaction(lambda: self._ack_row(actor, mid))

    def _send_row(self, msg_id, sender, recipient, body, reply_to) -> dict:
        self._gc()
        previous = self._row(msg_id)
        if previous:
            if (previous[0], previous[1], previous[2], previous[3]) != (
                sender, recipient, body, reply_to
            ):
                raise RelayError(409, "MESSAGE_ID_CONFLICT")
            return {"message_id": msg_id, "state": "IN_MAILBOX", "duplicate": True}
        if reply_to is not None:
            parent = self._row(reply_to)
            if parent is None or parent[0] != recipient or parent[1] != sender:
                raise RelayError(400, "INVALID_REPLY_TO")
        count = self._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        if count >= MAX_MESSAGES:
            raise RelayError(429, "MAILBOX_FULL")
        now = self._wall_now()
        self._conn.execute(
            "INSERT INTO messages(message_id,sender,recipient,body,reply_to,"
            "created_ms,expires_ms,acknowledged) VALUES(?,?,?,?,?,?,?,0)",
            (msg_id, sender, recipient, body, reply_to, now, now + TTL_SECONDS * 1000),
        )
        return {"message_id": msg_id, "state": "IN_MAILBOX", "duplicate": False}

    def _receive_rows(self, actor: str, limit: int) -> dict:
        self._gc()
        rows = self._conn.execute(
            "SELECT message_id,sender,recipient,body,reply_to,created_ms "
            "FROM messages WHERE recipient=? AND acknowledged=0 "
            "AND sender IN (%s) ORDER BY expires_ms, message_id LIMIT ?"
            % ",".join("?" for _ in self._roles),
            (actor, *sorted(self._roles), limit),
        ).fetchall()
        messages = []
        for row in rows:
            self._public_body(row[3])
            messages.append({
                "message_id": row[0],
                "sender": row[1],
                "recipient": row[2],
                "body": row[3],
                "reply_to": row[4],
                "created_at": row[5] / 1000,
            })
        return {"messages": messages, "state": "MAILBOX_READ"}

    def _ack_row(self, actor: str, mid: str) -> dict:
        self._gc()
        row = self._row(mid)
        if row is None:
            raise RelayError(404, "NOT_FOUND")
        if row[1] != actor:
            raise RelayError(403, "ROLE_MISMATCH")
        self._conn.execute(
            "UPDATE messages SET acknowledged=1 WHERE message_id=?", (mid,)
        )
        return {"message_id": mid, "state": "ACKNOWLEDGED"}

    def _row(self, mid: str):
        found = self._conn.execute(
            "SELECT sender,recipient,body,reply_to FROM messages WHERE message_id=?",
            (mid,),
        ).fetchone()
        if found and (found[0] not in self._roles or found[1] not in self._roles):
            raise DurableRefused("DURABLE_TAMPER")
        return found

    def _gc(self) -> None:
        now = self._wall_now()
        self._conn.execute("DELETE FROM messages WHERE expires_ms<=?", (now,))

    def _wall_now(self) -> int:
        observed = self._clock()
        if isinstance(observed, bool) or not isinstance(observed, (int, float)):
            raise DurableRefused("DURABLE_CLOCK")
        if observed != observed or observed in (float("inf"), float("-inf")) or observed < 0:
            raise DurableRefused("DURABLE_CLOCK")
        observed_ms = int(observed * 1000)
        stored = self._conn.execute(
            "SELECT value FROM meta WHERE key='wall_high_ms'"
        ).fetchone()
        high = int(stored[0]) if stored else 0
        if high < 0:
            raise DurableRefused("DURABLE_TAMPER")
        effective = max(high, observed_ms)
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES('wall_high_ms',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(effective),),
        )
        return effective

    def _transaction(self, fn):
        with self._lock:
            if self._conn is None:
                raise DurableRefused("DURABLE_CLOSED")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                result = fn()
                self._conn.execute("COMMIT")
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            self._refuse_sidecars()
            return result

    def _public_body(self, body: object) -> str:
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_BODY:
            raise RelayError(400, "INVALID_BODY")
        folded = body.casefold()
        if any(marker in folded for marker in _FORBIDDEN):
            raise RelayError(400, "INVALID_BODY")
        try:
            secret_text = self._secret.decode("utf-8")
        except UnicodeDecodeError:
            secret_text = ""
        if secret_text and secret_text in body:
            raise RelayError(400, "INVALID_BODY")
        return body

    def _private_directory(self, directory: Path) -> Path:
        if not directory.is_absolute():
            raise DurableRefused("DURABLE_PATH_REFUSED")
        parent = directory.parent
        self._refuse_link(parent)
        if not parent.is_dir():
            raise DurableRefused("DURABLE_PATH_REFUSED")
        if directory.exists() or directory.is_symlink():
            self._refuse_link(directory)
            if not directory.is_dir():
                raise DurableRefused("DURABLE_PATH_REFUSED")
            self._refuse_widened(directory, 0o700)
        else:
            os.mkdir(directory, 0o700)
            os.chmod(directory, 0o700)
        self._require_private(directory, 0o700)
        return directory

    def _open_db(self) -> sqlite3.Connection:
        self._refuse_sidecars()
        if self._db_path.exists() or self._db_path.is_symlink():
            self._refuse_link(self._db_path)
            if not stat.S_ISREG(os.lstat(self._db_path).st_mode):
                raise DurableRefused("DURABLE_PATH_REFUSED")
            self._refuse_widened(self._db_path, 0o600)
        else:
            fd = os.open(self._db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            os.chmod(self._db_path, 0o600)
        self._require_private(self._db_path, 0o600)
        header = self._db_path.read_bytes()[:16]
        if header and not header.startswith(b"SQLite format 3\x00"):
            raise DurableRefused("DURABLE_CORRUPT")
        try:
            conn = sqlite3.connect(
                self._db_path, isolation_level=None, check_same_thread=False
            )
        except sqlite3.Error:
            raise DurableRefused("DURABLE_CORRUPT") from None
        try:
            mode = conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).lower() != "delete":
                raise DurableRefused("DURABLE_SIDECAR")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA foreign_keys=ON")
            check = conn.execute("PRAGMA integrity_check").fetchone()
            if not header:
                conn.execute(f"PRAGMA application_id={_APP_ID}")
                conn.execute(f"PRAGMA user_version={_SCHEMA}")
                conn.execute(
                    "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                conn.execute(
                    "CREATE TABLE messages("
                    "message_id TEXT PRIMARY KEY,"
                    "sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL,"
                    "reply_to TEXT, created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,"
                    "acknowledged INTEGER NOT NULL)"
                )
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('roster',?)", (self._roster,)
                )
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('wall_high_ms','0')"
                )
                created = conn.execute("PRAGMA integrity_check").fetchone()
                if created is None or created[0] != "ok":
                    raise DurableRefused("DURABLE_CORRUPT")
            else:
                if check is None or check[0] != "ok":
                    raise DurableRefused("DURABLE_CORRUPT")
                if conn.execute("PRAGMA application_id").fetchone()[0] != _APP_ID:
                    raise DurableRefused("DURABLE_TAMPER")
                if conn.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA:
                    raise DurableRefused("DURABLE_SCHEMA")
                roster = conn.execute(
                    "SELECT value FROM meta WHERE key='roster'"
                ).fetchone()
                if roster is None or roster[0] != self._roster:
                    raise DurableRefused("DURABLE_ROSTER_MISMATCH")
            self._refuse_sidecars()
            return conn
        except DurableRefused:
            conn.close()
            raise
        except sqlite3.Error:
            conn.close()
            raise DurableRefused("DURABLE_CORRUPT") from None
        except Exception:
            conn.close()
            raise

    def _refuse_sidecars(self) -> None:
        if not self._directory.exists():
            return
        for child in self._directory.iterdir():
            if child.name != _DB_NAME or child.is_symlink():
                raise DurableRefused("DURABLE_SIDECAR")

    def _refuse_link(self, path: Path) -> None:
        try:
            info = os.lstat(path)
        except OSError:
            raise DurableRefused("DURABLE_PATH_REFUSED") from None
        if stat.S_ISLNK(info.st_mode):
            raise DurableRefused("DURABLE_PATH_REFUSED")

    def _refuse_widened(self, path: Path, expected: int) -> None:
        if os.name != "posix":
            return
        if stat.S_IMODE(os.lstat(path).st_mode) != expected:
            raise DurableRefused("DURABLE_PERMISSIONS")

    def _require_private(self, path: Path, expected: int) -> None:
        if os.name != "posix":
            return
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != expected:
            raise DurableRefused("DURABLE_PERMISSIONS")
        if info.st_uid != os.getuid():
            raise DurableRefused("DURABLE_PERMISSIONS")
