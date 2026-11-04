"""SYNTHETIC ONLY: host-local single-use command-intent journal.

A command ID is reserved atomically BEFORE a permitted fixed canary starts.
A crash or uncertain result remains RESERVED_UNVERIFIED and blocks new work.
Successful OS process drain is separate from verified host-session close.

This does NOT implement a protected/rollback-resistant privileged ledger,
network isolation, or model-facing command execution.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

STATES = frozenset({
    "RESERVED_UNVERIFIED", "PROCESS_DRAIN_VERIFIED", "HOST_CLOSE_VERIFIED"
})


class CommandJournalError(ValueError):
    def __init__(self, code: str = "COMMAND_JOURNAL_UNAVAILABLE"):
        super().__init__(code)
        self.code = code


def _canonical_uuid(value: str) -> str:
    if type(value) is not str or len(value) != 36:
        raise CommandJournalError("COMMAND_ID_INVALID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError, TypeError):
        raise CommandJournalError("COMMAND_ID_INVALID") from None
    return value


def canonical_intent_digest(*, session_id: str, token: str,
                            host: str, operation: str, workload: str,
                            operation_id: str) -> str:
    sid, cid = _canonical_uuid(session_id), _canonical_uuid(operation_id)
    if (type(token) is not str or not token or len(token) > 4096 or
        any(type(x) is not str or not x or len(x) > 128
            for x in (host, operation, workload))):
        raise CommandJournalError("COMMAND_INTENT_INVALID")
    record = {
        "session_id": sid, "operation_id": cid,
        "host": host, "operation": operation, "workload": workload,
        "signed_grant_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _canonical_digest(value: str) -> str:
    if type(value) is not str or len(value) != 64:
        raise CommandJournalError("COMMAND_INTENT_INVALID")
    try:
        if int(value, 16) < 0 or value != value.lower():
            raise ValueError()
    except ValueError:
        raise CommandJournalError("COMMAND_INTENT_INVALID") from None
    return value


class CommandIntentJournal:
    """Disposable SQLite journal, initialised only by a separate test bootstrap."""

    def __init__(self, filename: str | Path, *, initialize: bool = False):
        if not isinstance(filename, (str, Path)):
            raise CommandJournalError()
        self._path = Path(filename)
        if not self._path.is_absolute() or len(str(self._path)) > 1024:
            raise CommandJournalError()
        parent = self._path.parent
        if not parent.is_dir() or parent.is_symlink() or self._path.is_symlink():
            raise CommandJournalError()
        if os.name == "posix" and parent.stat().st_mode & 0o077:
            raise CommandJournalError()
        if initialize:
            try:
                handle = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(handle)
            except OSError:
                raise CommandJournalError() from None
        try:
            with closing(self._connect()) as db:
                if initialize:
                    db.execute(
                        "CREATE TABLE attempts ("
                        " command_id TEXT PRIMARY KEY NOT NULL,"
                        " session_id TEXT NOT NULL,"
                        " intent_sha256 TEXT NOT NULL,"
                        " state TEXT NOT NULL CHECK (state IN "
                        " ('RESERVED_UNVERIFIED','PROCESS_DRAIN_VERIFIED','HOST_CLOSE_VERIFIED')))"
                    )
                    db.execute("PRAGMA user_version=1")
                else:
                    version = db.execute("PRAGMA user_version").fetchone()[0]
                    if version != 1:
                        raise CommandJournalError()
                    db.execute("SELECT command_id FROM attempts LIMIT 1").fetchall()
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def _verify(self) -> None:
        try:
            item = self._path.lstat()
            if not stat.S_ISREG(item.st_mode) or self._path.is_symlink():
                raise CommandJournalError()
            if os.name == "posix" and item.st_mode & 0o077:
                raise CommandJournalError()
        except OSError:
            raise CommandJournalError() from None

    def _connect(self):
        self._verify()
        try:
            db = sqlite3.connect(
                self._path.as_uri() + "?mode=rw",
                uri=True, isolation_level=None, timeout=3.0,
            )
            try:
                db.execute("PRAGMA busy_timeout=3000")
                db.execute("PRAGMA synchronous=FULL")
                return db
            except BaseException:
                db.close()
                raise
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def summary(self) -> dict:
        """Sanitized readback; no token, host address, args or stdout."""
        try:
            with closing(self._connect()) as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM attempts WHERE state != 'HOST_CLOSE_VERIFIED'"
                ).fetchone()[0]
                return {
                    "state": "COMMAND_JOURNAL_QUARANTINED" if count
                             else "NO_UNVERIFIED_COMMANDS",
                    "unverified_count": count,
                }
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def lookup(self, command_id: str) -> dict:
        cid = _canonical_uuid(command_id)
        try:
            with closing(self._connect()) as db:
                item = db.execute(
                    "SELECT state FROM attempts WHERE command_id=?", (cid,)
                ).fetchone()
                return {"known": bool(item), "state": item[0] if item else None}
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def reserve(self, *, command_id: str, session_id: str,
                intent_sha256: str) -> None:
        cid, sid = _canonical_uuid(command_id), _canonical_uuid(session_id)
        digest = _canonical_digest(intent_sha256)
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                item = db.execute(
                    "SELECT session_id,intent_sha256 FROM attempts WHERE command_id=?",
                    (cid,)
                ).fetchone()
                if item:
                    db.rollback()
                    if item == (sid, digest):
                        raise CommandJournalError("COMMAND_ALREADY_RESERVED")
                    raise CommandJournalError("COMMAND_ID_CONFLICT")
                pending = db.execute(
                    "SELECT COUNT(*) FROM attempts WHERE state != 'HOST_CLOSE_VERIFIED'"
                ).fetchone()[0]
                if pending:
                    db.rollback()
                    raise CommandJournalError("COMMAND_JOURNAL_QUARANTINED")
                db.execute(
                    "INSERT INTO attempts(command_id,session_id,intent_sha256,state)"
                    " VALUES(?,?,?,'RESERVED_UNVERIFIED')",
                    (cid, sid, digest),
                )
                db.commit()
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def _transition(self, *, command_id: str, session_id: str,
                    intent_sha256: str, source: str, target: str):
        cid, sid = _canonical_uuid(command_id), _canonical_uuid(session_id)
        digest = _canonical_digest(intent_sha256)
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                updated = db.execute(
                    "UPDATE attempts SET state=?"
                    " WHERE command_id=? AND session_id=? AND intent_sha256=? AND state=?",
                    (target, cid, sid, digest, source),
                ).rowcount
                if updated != 1:
                    db.rollback()
                    raise CommandJournalError("COMMAND_TRANSITION_REFUSED")
                db.commit()
        except (sqlite3.Error, OSError):
            raise CommandJournalError() from None

    def mark_process_drained(self, *, command_id: str, session_id: str,
                             intent_sha256: str):
        """Caller MUST positively verify actual OS drain before invoking."""
        self._transition(
            command_id=command_id, session_id=session_id,
            intent_sha256=intent_sha256,
            source="RESERVED_UNVERIFIED", target="PROCESS_DRAIN_VERIFIED",
        )

    def mark_host_closed(self, *, command_id: str, session_id: str,
                         intent_sha256: str):
        """Caller MUST independently verify host journal closure before invoking."""
        self._transition(
            command_id=command_id, session_id=session_id,
            intent_sha256=intent_sha256,
            source="PROCESS_DRAIN_VERIFIED", target="HOST_CLOSE_VERIFIED",
        )
