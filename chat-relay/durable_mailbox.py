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
import hmac
import json
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
_MAC_KEY_DOMAIN = b"LDW/chat-relay/durable/v1/state-key"
_MAC_STATE_DOMAIN = "LDW/chat-relay/durable/v1/state"
_MAC_FIELD = "state_mac"
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
        self._role_token_markers = tuple(
            self._auth.token_for_role(role).casefold()
            for role in sorted(self._roles)
        )
        self._roster = hashlib.sha256(
            ("\n".join(sorted(self._roles))).encode("ascii")
        ).hexdigest()
        self._secret = master_secret
        self._mac_key = hmac.new(master_secret, _MAC_KEY_DOMAIN, hashlib.sha256).digest()
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
        if type(limit) is not int or not 1 <= limit <= 20:
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

    @staticmethod
    def _sqlite_refusal(error: sqlite3.Error) -> DurableRefused:
        detail = str(error).casefold()
        if "locked" in detail or "busy" in detail:
            return DurableRefused("DURABLE_BUSY")
        return DurableRefused("DURABLE_CORRUPT")

    def _transaction(self, fn):
        with self._lock:
            if self._conn is None:
                raise DurableRefused("DURABLE_CLOSED")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as error:
                raise self._sqlite_refusal(error) from None
            try:
                self._verify_mac(self._conn)
                result = fn()
                self._store_mac(self._conn)
                self._conn.execute("COMMIT")
            except Exception as error:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if isinstance(error, sqlite3.Error):
                    raise self._sqlite_refusal(error) from None
                raise
            self._refuse_sidecars()
            return result

    def _state_mac(self, conn: sqlite3.Connection) -> str:
        """Authenticate the *complete* local SQLite snapshot, not individual rows.

        A row-only MAC cannot detect message deletion, replay or meta rollback.
        This does not detect replay of an entire previously valid DB snapshot:
        that would require an independent, durable monotonic trust anchor.
        """
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            app_id = conn.execute("PRAGMA application_id").fetchone()[0]
            if type(version) is not int or version != _SCHEMA or app_id != _APP_ID:
                raise DurableRefused("DURABLE_TAMPER")
            schema = conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema "
                "ORDER BY type,name"
            ).fetchall()
            if {(row[0], row[1]) for row in schema if row[0] == "table"} != {
                ("table", "meta"), ("table", "messages")
            } or any(row[0] not in ("table", "index") for row in schema):
                raise DurableRefused("DURABLE_TAMPER")
            meta_rows = conn.execute(
                "SELECT key,value FROM meta ORDER BY key"
            ).fetchall()
            meta = dict(meta_rows)
            if len(meta_rows) != 3 or set(meta) != {
                "roster", "wall_high_ms", _MAC_FIELD
            } or any(type(k) is not str or type(v) is not str
                     for k, v in meta_rows):
                raise DurableRefused("DURABLE_TAMPER")
            if meta["roster"] != self._roster:
                raise DurableRefused("DURABLE_ROSTER_MISMATCH")
            high = meta["wall_high_ms"]
            if not high or not high.isascii() or not high.isdecimal() or (
                len(high) > 1 and high.startswith("0")
            ) or len(high) > 20:
                raise DurableRefused("DURABLE_TAMPER")
            rows = conn.execute(
                "SELECT message_id,sender,recipient,body,reply_to,"
                "created_ms,expires_ms,acknowledged FROM messages "
                "ORDER BY message_id"
            ).fetchall()
            if len(rows) > MAX_MESSAGES:
                raise DurableRefused("DURABLE_TAMPER")
            for row in rows:
                mid, sender, recipient, body, reply_to, created, expires, ack = row
                if (type(mid) is not str or canonical_id(mid) != mid
                    or type(sender) is not str or sender not in self._roles
                    or type(recipient) is not str or recipient not in self._roles
                    or sender == recipient or type(body) is not str
                    or type(created) is not int or type(expires) is not int
                    or created < 0 or expires != created + TTL_SECONDS * 1000
                    or type(ack) is not int or ack not in (0, 1)):
                    raise DurableRefused("DURABLE_TAMPER")
                if reply_to is not None and (
                    type(reply_to) is not str or canonical_id(reply_to) != reply_to
                ):
                    raise DurableRefused("DURABLE_TAMPER")
                self._public_body(body)
            payload = json.dumps({
                "domain": _MAC_STATE_DOMAIN,
                "application_id": app_id,
                "user_version": version,
                "schema": schema,
                "meta": [(key, value) for key, value in meta_rows
                         if key != _MAC_FIELD],
                "messages": rows,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            return hmac.new(
                self._mac_key, payload.encode("ascii"), hashlib.sha256
            ).hexdigest()
        except DurableRefused:
            raise
        except (sqlite3.Error, RelayError, TypeError, ValueError,
                OverflowError, UnicodeError):
            raise DurableRefused("DURABLE_TAMPER") from None

    def _verify_mac(self, conn: sqlite3.Connection) -> None:
        try:
            stored = conn.execute(
                "SELECT value FROM meta WHERE key=?", (_MAC_FIELD,)
            ).fetchone()
            if (stored is None or type(stored[0]) is not str
                or not hmac.compare_digest(stored[0], self._state_mac(conn))):
                raise DurableRefused("DURABLE_TAMPER")
        except sqlite3.Error:
            raise DurableRefused("DURABLE_TAMPER") from None

    def _store_mac(self, conn: sqlite3.Connection) -> None:
        mac = self._state_mac(conn)
        result = conn.execute(
            "UPDATE meta SET value=? WHERE key=?", (mac, _MAC_FIELD)
        )
        if result.rowcount != 1:
            raise DurableRefused("DURABLE_TAMPER")

    def _public_body(self, body: object) -> str:
        if not isinstance(body, str) or not body:
            raise RelayError(400, "INVALID_BODY")
        try:
            encoded_body = body.encode("utf-8")
        except UnicodeError:
            raise RelayError(400, "INVALID_BODY") from None
        if len(encoded_body) > MAX_BODY:
            raise RelayError(400, "INVALID_BODY")
        folded = body.casefold()
        if any(marker in folded for marker in _FORBIDDEN):
            raise RelayError(400, "INVALID_BODY")
        try:
            secret_text = self._secret.decode("utf-8")
        except UnicodeDecodeError:
            secret_text = ""
        if secret_text and secret_text.casefold() in folded:
            raise RelayError(400, "INVALID_BODY")
        if any(token and token in folded for token in self._role_token_markers):
            raise RelayError(400, "INVALID_BODY")
        return body

    def _private_directory(self, directory: Path) -> Path:
        if not directory.is_absolute():
            raise DurableRefused("DURABLE_PATH_REFUSED")
        parent = directory.parent
        # A direct-parent check misses a link or junction one or more
        # components above it. Inspect every ancestor (including the root).
        # This is static fail-closed screening, NOT an atomic path-to-open
        # identity guarantee for SQLite's pathname-based VFS.
        for ancestor in (parent, *parent.parents):
            self._refuse_link(ancestor)
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
        self._refuse_sidecars(allow_rollback_journal=True)
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
        try:
            with self._db_path.open("rb") as db_header:
                header = db_header.read(16)
        except OSError:
            raise DurableRefused("DURABLE_PATH_REFUSED") from None
        if header and not header.startswith(b"SQLite format 3\x00"):
            raise DurableRefused("DURABLE_CORRUPT")
        try:
            conn = sqlite3.connect(
                self._db_path, isolation_level=None,
                check_same_thread=False, timeout=0.5,
            )
        except sqlite3.Error as error:
            raise self._sqlite_refusal(error) from None
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
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES(?, '')", (_MAC_FIELD,)
                )
                self._store_mac(conn)
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
                self._verify_mac(conn)
                # A crash may leave an inactive DELETE-mode rollback journal with
                # a zeroed header. SQLite read-only open does not erase it; after
                # verifying the sealed state, complete a bounded, same-value
                # SQLite write so its own pager retires the cold journal.
                cold_journal = self._directory / (_DB_NAME + "-journal")
                if cold_journal.exists():
                    self._refuse_sidecars(allow_rollback_journal=True)
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        self._verify_mac(conn)
                        # A no-op UPDATE is optimized away by SQLite's
                        # pager and leaves a cold journal behind. Force one
                        # real reversible SQLite write instead; the keyed
                        # state and schema must be identical at COMMIT.
                        cleanup_key = "__ldw_cold_journal_cleanup__"
                        conn.execute(
                            "INSERT INTO meta(key,value) VALUES (?,?)",
                            (cleanup_key, "1"),
                        )
                        deleted = conn.execute(
                            "DELETE FROM meta WHERE key=?", (cleanup_key,)
                        )
                        if deleted.rowcount != 1:
                            raise DurableRefused("DURABLE_TAMPER")
                        self._verify_mac(conn)
                        conn.execute("COMMIT")
                    except Exception:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise
                    self._verify_mac(conn)
            self._refuse_sidecars()
            return conn
        except DurableRefused:
            conn.close()
            raise
        except sqlite3.Error as error:
            conn.close()
            raise self._sqlite_refusal(error) from None
        except Exception:
            conn.close()
            raise

    def _refuse_sidecars(self, *, allow_rollback_journal: bool = False) -> None:
        if not self._directory.exists():
            return
        for child in self._directory.iterdir():
            if child.name == _DB_NAME and not child.is_symlink():
                continue
            if (allow_rollback_journal
                and child.name == _DB_NAME + "-journal"
                and not child.is_symlink()):
                try:
                    info = os.lstat(child)
                except OSError:
                    raise DurableRefused("DURABLE_SIDECAR") from None
                if not stat.S_ISREG(info.st_mode) or info.st_size < 512:
                    raise DurableRefused("DURABLE_SIDECAR")
                try:
                    with child.open("rb") as rollback:
                        prefix = rollback.read(8)
                except OSError:
                    raise DurableRefused("DURABLE_SIDECAR") from None
                if prefix not in (
                    b"\x00" * 8,
                    b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7",
                ):
                    raise DurableRefused("DURABLE_SIDECAR")
                if os.name == "posix":
                    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
                        raise DurableRefused("DURABLE_SIDECAR")
                continue
            raise DurableRefused("DURABLE_SIDECAR")

    def _refuse_link(self, path: Path) -> None:
        try:
            info = os.lstat(path)
        except OSError:
            raise DurableRefused("DURABLE_PATH_REFUSED") from None
        if (stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) &
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )):
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
