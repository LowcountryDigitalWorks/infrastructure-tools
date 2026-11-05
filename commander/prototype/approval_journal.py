"""Disposable, fail-closed issuer approval replay journal.

NOT protected production owner state, OS-backed consent, or a host-agent state
journal. The trusted test bootstrap creates the file exactly once; the issuer
only reopens an existing journal and refuses missing/corrupt/unsafe state.

SQLite BEGIN IMMEDIATE + unique decision UUID gives atomic cross-thread and
cross-process single-use consumption for synthetic FULL_ADMIN issuance.
"""
from __future__ import annotations

import os
from contextlib import closing
from pathlib import Path
import sqlite3
import stat
import uuid

MAX_DB_PATH = 1024


class ApprovalJournalError(ValueError):
    pass


class ApprovalJournal:
    def __init__(self, location: str | Path, *, initialize: bool = False):
        if not isinstance(location, (str, Path)):
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
        path = Path(location)
        if not path.is_absolute() or len(str(path)) > MAX_DB_PATH:
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink() or path.is_symlink():
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
        if os.name == "posix" and (parent.stat().st_mode & 0o077):
            # A per-owner private directory is mandatory for the test fixture.
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
        if initialize:
            # Only a separate trusted test/bootstrap step may initialize. An
            # issuer restart must NEVER silently recreate a missing ledger.
            try:
                handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError:
                raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE") from None
            os.close(handle)
        try:
            self.path = path
            self._verify_file()
            with closing(self._connect()) as db:
                if initialize:
                    db.execute(
                        "CREATE TABLE consumed ("
                        " decision_id TEXT NOT NULL PRIMARY KEY,"
                        " grant_sha256 TEXT NOT NULL)"
                    )
                    db.execute("PRAGMA user_version=1")
                else:
                    version = db.execute("PRAGMA user_version").fetchone()[0]
                    if version != 1:
                        raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
                    db.execute("SELECT decision_id FROM consumed LIMIT 1").fetchall()
        except (OSError, sqlite3.Error):
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE") from None

    def _verify_file(self):
        try:
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
                raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
            if os.name == "posix" and (metadata.st_mode & 0o077):
                raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE")
        except OSError:
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE") from None

    def _connect(self):
        self._verify_file()
        # mode=rw must never create missing state; fail closed after deletion.
        uri = self.path.as_uri() + "?mode=rw"
        db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=3.0)
        try:
            db.execute("PRAGMA busy_timeout=3000")
            db.execute("PRAGMA synchronous=FULL")
            return db
        except BaseException:
            # Crucial on Windows: an exception during PRAGMA on a corrupt DB
            # must release the OS file handle before fixture cleanup/recovery.
            db.close()
            raise

    def consume(self, decision_id: str, grant_sha256: str) -> bool:
        """Atomically consume once. Returns False only on confirmed replay."""
        try:
            if str(uuid.UUID(decision_id)) != decision_id:
                raise ValueError()
            if not isinstance(grant_sha256, str) or len(grant_sha256) != 64:
                raise ValueError()
            int(grant_sha256, 16)
        except (ValueError, TypeError, AttributeError):
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE") from None

        try:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute(
                        "INSERT INTO consumed (decision_id, grant_sha256) VALUES (?, ?)",
                        (decision_id, grant_sha256),
                    )
                except sqlite3.IntegrityError:
                    db.rollback()
                    return False
                db.commit()
                return True
            finally:
                db.close()
        except (OSError, sqlite3.Error):
            raise ApprovalJournalError("APPROVAL_JOURNAL_UNAVAILABLE") from None
