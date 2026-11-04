"""LDW Commander disposable host-session journal (synthetic-only Gate B).

A host-side, separately maintained SQLite tombstone store. It fails closed on
restarts with an OPEN session, instead of silently restoring an old grant.
This is NOT an OS-protected ledger, protected Windows service, TPM store,
rollback-resistant record, process containment or real privileged executor.

The only valid bootstrap creates an owner-private disposable fixture. No
model-facing create/recovery/clear operation or live host enrollment exists.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from session import SessionRefused, SyntheticAgent, uid

STATES = ("OPEN", "REVOKED_VERIFIED")
SCHEMA_VERSION = 1


class HostJournalError(ValueError):
    pass


class HostSessionJournal:
    """Local test journal with single-owner, transactionally recorded sessions."""

    def __init__(self, filename: str | Path, *, initialize: bool = False):
        if not isinstance(filename, (str, Path)):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        self._path = Path(filename)
        if not self._path.is_absolute() or len(str(self._path)) > 1024:
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        parent = self._path.parent
        if not parent.is_dir() or parent.is_symlink() or self._path.is_symlink():
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        if os.name == "posix" and parent.stat().st_mode & 0o077:
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        if initialize:
            try:
                fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except OSError:
                raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None
        try:
            with closing(self._connect()) as db:
                if initialize:
                    db.execute(
                        "CREATE TABLE sessions ("
                        " session_id TEXT PRIMARY KEY NOT NULL,"
                        " grant_digest TEXT NOT NULL,"
                        " state TEXT NOT NULL CHECK (state IN ('OPEN','REVOKED_VERIFIED')))"
                    )
                    db.execute("PRAGMA user_version=1")
                else:
                    version = db.execute("PRAGMA user_version").fetchone()[0]
                    if version != SCHEMA_VERSION:
                        raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
                    db.execute("SELECT session_id FROM sessions LIMIT 1").fetchall()
        except (OSError, sqlite3.Error):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None

    def _verify(self):
        try:
            st = self._path.lstat()
            if not stat.S_ISREG(st.st_mode) or self._path.is_symlink():
                raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
            if os.name == "posix" and st.st_mode & 0o077:
                raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        except OSError:
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None

    def _connect(self):
        self._verify()
        try:
            db = sqlite3.connect(self._path.as_uri() + "?mode=rw",
                                 uri=True, isolation_level=None, timeout=3)
            try:
                db.execute("PRAGMA busy_timeout=3000")
                db.execute("PRAGMA synchronous=FULL")
                return db
            except BaseException:
                db.close()
                raise
        except (OSError, sqlite3.Error):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None

    def status(self, session_id: str | None = None) -> dict:
        """Only sanitized summary. Unknown/open residue is NOT Healthy."""
        try:
            with closing(self._connect()) as db:
                if session_id is not None:
                    sid = uid(session_id)
                    state = db.execute(
                        "SELECT state FROM sessions WHERE session_id=?", (sid,)
                    ).fetchone()
                    return {"known": bool(state), "state": state[0] if state else None}
                count = db.execute(
                    "SELECT COUNT(*) FROM sessions WHERE state='OPEN'"
                ).fetchone()[0]
                return {
                    "state": "HOST_QUARANTINED" if count else "NO_UNVERIFIED_SESSIONS",
                    "unverified_count": count,
                }
        except (OSError, sqlite3.Error, SessionRefused):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None

    def reserve(self, session_id: str, token: str) -> None:
        sid = uid(session_id)
        if not isinstance(token, str) or not token:
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                previous = db.execute(
                    "SELECT state FROM sessions WHERE session_id=?", (sid,)
                ).fetchone()
                if previous:
                    db.rollback()
                    raise SessionRefused("HOST_SESSION_REPLAY")
                pending = db.execute(
                    "SELECT COUNT(*) FROM sessions WHERE state='OPEN'"
                ).fetchone()[0]
                if pending:
                    db.rollback()
                    raise SessionRefused("HOST_QUARANTINED")
                db.execute(
                    "INSERT INTO sessions(session_id,grant_digest,state)"
                    " VALUES(?, ?, 'OPEN')", (sid, digest)
                )
                db.commit()
        except (OSError, sqlite3.Error):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None

    def synthetic_revoke_verified(self, session_id: str, token: str) -> None:
        """NO running child/process exists in this synthetic-only agent."""
        sid = uid(session_id)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT grant_digest,state FROM sessions WHERE session_id=?", (sid,)
                ).fetchone()
                if row != (digest, "OPEN"):
                    db.rollback()
                    raise HostJournalError("HOST_JOURNAL_UNAVAILABLE")
                db.execute(
                    "UPDATE sessions SET state='REVOKED_VERIFIED' WHERE session_id=?",
                    (sid,)
                )
                db.commit()
        except (OSError, sqlite3.Error):
            raise HostJournalError("HOST_JOURNAL_UNAVAILABLE") from None


class JournalBoundSyntheticAgent(SyntheticAgent):
    """A host-side replay gate for the NO-OS-EXECUTION agent only."""

    def __init__(self, public_key, policy, host, *, host_journal: HostSessionJournal,
                 **kwargs):
        if not isinstance(host_journal, HostSessionJournal):
            raise ValueError("HOST_JOURNAL_REQUIRED")
        super().__init__(public_key, policy, host, **kwargs)
        self._host_journal = host_journal

    def open(self, token: str, operator: str) -> dict:
        with self._lock:
            grant = self._decode(token)
            sid = self._check(grant, operator)
            if sid in self._active:
                return super().open(token, operator)
            # Persist a one-use tombstone BEFORE any session is presented as
            # OPEN. An unexpected failure leaves residue, not a reusable token.
            try:
                self._host_journal.reserve(sid, token)
            except HostJournalError:
                raise SessionRefused("HOST_JOURNAL_UNAVAILABLE") from None
            return super().open(token, operator)

    def revoke(self, session_id: str) -> dict:
        with self._lock:
            sid = uid(session_id)
            state = self._active.get(sid)
            if state is None:
                raise SessionRefused("SESSION_NOT_OPEN")
            token = state.get("token")
            # Parent stores only parsed grant, not the original signed token.
            # This synthetic proof tracks the original at open after source
            # admission and ensures its exact digest at revoke.
            if not token:
                raise SessionRefused("HOST_JOURNAL_UNAVAILABLE")
            result = super().revoke(sid)
            try:
                self._host_journal.synthetic_revoke_verified(sid, token)
            except HostJournalError:
                raise SessionRefused("HOST_QUARANTINED") from None
            return result
