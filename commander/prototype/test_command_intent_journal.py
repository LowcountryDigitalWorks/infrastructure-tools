"""SYNTHETIC SQLite intent-journal tests; never spawn a process or shell."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from command_intent_journal import (
    CommandIntentJournal, CommandJournalError, canonical_intent_digest,
)


class CommandIntentJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ldw-command-journal-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "attempts.db"
        self.journal = CommandIntentJournal(self.path, initialize=True)
        self.sid = str(uuid.uuid4())
        self.cid = str(uuid.uuid4())
        self.intent = self.digest(self.sid, self.cid)

    def digest(self, sid, cid, *, token="fixed-synthetic-signed-grant"):
        return canonical_intent_digest(
            session_id=sid, operation_id=cid, token=token,
            host="synthetic-host", operation="RUN_DISPOSABLE_CHILD_CANARY",
            workload="LOCAL_FIXED_NO_NETWORK_NO_SECRETS",
        )

    def reserve(self, journal=None, *, command_id=None,
                session_id=None, intent_sha256=None):
        (journal or self.journal).reserve(
            command_id=command_id or self.cid,
            session_id=session_id or self.sid,
            intent_sha256=intent_sha256 or self.intent,
        )

    def reject(self, code, func):
        with self.assertRaises(CommandJournalError) as got:
            func()
        self.assertEqual(got.exception.code, code)

    def test_atomic_reserve_then_process_drain_then_host_close(self):
        self.reserve()
        self.assertEqual(self.journal.summary(),
                         {"state": "COMMAND_JOURNAL_QUARANTINED", "unverified_count": 1})
        self.assertEqual(self.journal.lookup(self.cid)["state"], "RESERVED_UNVERIFIED")
        self.journal.mark_process_drained(
            command_id=self.cid, session_id=self.sid, intent_sha256=self.intent)
        self.assertEqual(self.journal.lookup(self.cid)["state"], "PROCESS_DRAIN_VERIFIED")
        self.assertEqual(self.journal.summary()["state"], "COMMAND_JOURNAL_QUARANTINED")
        self.journal.mark_host_closed(
            command_id=self.cid, session_id=self.sid, intent_sha256=self.intent)
        self.assertEqual(self.journal.lookup(self.cid)["state"], "HOST_CLOSE_VERIFIED")
        self.assertEqual(self.journal.summary()["state"], "NO_UNVERIFIED_COMMANDS")
        self.reject("COMMAND_ALREADY_RESERVED", self.reserve)

    def test_cannot_promote_host_close_before_drain(self):
        self.reserve()
        self.reject("COMMAND_TRANSITION_REFUSED",
                    lambda: self.journal.mark_host_closed(
                        command_id=self.cid, session_id=self.sid,
                        intent_sha256=self.intent))
        self.assertEqual(self.journal.summary()["unverified_count"], 1)

    def test_invalid_result_or_wrong_session_cannot_complete(self):
        self.reserve()
        bad_sid = str(uuid.uuid4())
        for session_id, intent_sha256 in (
            (bad_sid, self.intent),
            (self.sid, "0"*64),
        ):
            self.reject("COMMAND_TRANSITION_REFUSED",
                        lambda session_id=session_id, intent_sha256=intent_sha256:
                        self.journal.mark_process_drained(
                            command_id=self.cid, session_id=session_id,
                            intent_sha256=intent_sha256))
        self.assertEqual(self.journal.lookup(self.cid)["state"], "RESERVED_UNVERIFIED")

    def test_restart_does_not_reexecute_or_clear_unknown(self):
        self.reserve()
        after_restart = CommandIntentJournal(self.path)
        self.reject("COMMAND_ALREADY_RESERVED",
                    lambda: self.reserve(after_restart))
        self.reject("COMMAND_JOURNAL_QUARANTINED",
                    lambda: self.reserve(after_restart,
                                        command_id=str(uuid.uuid4()),
                                        intent_sha256=self.digest(self.sid, str(uuid.uuid4()))))
        self.assertEqual(after_restart.summary()["unverified_count"], 1)

    def test_reused_command_id_with_different_session_or_intent_conflicts(self):
        self.reserve()
        second_sid = str(uuid.uuid4())
        self.reject("COMMAND_ID_CONFLICT",
                    lambda: self.reserve(command_id=self.cid,
                                         session_id=second_sid,
                                         intent_sha256=self.digest(second_sid, self.cid)))
        self.reject("COMMAND_ID_CONFLICT",
                    lambda: self.reserve(intent_sha256=self.digest(
                        self.sid, self.cid, token="different-grant")))

    def test_parallel_same_command_one_reservation(self):
        barrier = threading.Barrier(8)
        def attempt(_):
            db = CommandIntentJournal(self.path)
            barrier.wait(timeout=8)
            try:
                self.reserve(db)
                return "RESERVED"
            except CommandJournalError as err:
                return err.code
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(outcomes.count("RESERVED"), 1, outcomes)
        self.assertEqual(outcomes.count("COMMAND_ALREADY_RESERVED"), 7, outcomes)

    def test_parallel_different_commands_only_one_unfinished(self):
        barrier = threading.Barrier(2)
        ids = [str(uuid.uuid4()) for _ in range(2)]
        def attempt(cid):
            db = CommandIntentJournal(self.path)
            barrier.wait(timeout=8)
            try:
                db.reserve(command_id=cid, session_id=self.sid,
                           intent_sha256=self.digest(self.sid, cid))
                return "RESERVED"
            except CommandJournalError as err:
                return err.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ids))
        self.assertEqual(outcomes.count("RESERVED"), 1, outcomes)
        self.assertEqual(outcomes.count("COMMAND_JOURNAL_QUARANTINED"), 1, outcomes)

    def test_corrupt_missing_or_reinit_state_fail_closed(self):
        self.reject("COMMAND_JOURNAL_UNAVAILABLE",
                    lambda: CommandIntentJournal(self.path, initialize=True))
        self.path.write_bytes(b"not a valid sqlite database")
        self.reject("COMMAND_JOURNAL_UNAVAILABLE",
                    lambda: CommandIntentJournal(self.path))
        self.reject("COMMAND_JOURNAL_UNAVAILABLE", self.journal.summary)
        self.path.unlink()
        self.reject("COMMAND_JOURNAL_UNAVAILABLE", self.journal.summary)
        self.assertFalse(self.path.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX file-mode proof")
    def test_world_readable_ledger_rejected(self):
        self.path.chmod(0o644)
        self.reject("COMMAND_JOURNAL_UNAVAILABLE",
                    lambda: CommandIntentJournal(self.path))

    def test_canonical_request_binds_host_operation_and_signed_grant_digest(self):
        self.assertNotEqual(self.intent, self.digest(self.sid, self.cid, token="other"))
        other_host = canonical_intent_digest(
            session_id=self.sid, operation_id=self.cid,
            token="fixed-synthetic-signed-grant",
            host="other-host", operation="RUN_DISPOSABLE_CHILD_CANARY",
            workload="LOCAL_FIXED_NO_NETWORK_NO_SECRETS",
        )
        self.assertNotEqual(self.intent, other_host)

    def test_bad_ids_and_digests_refused(self):
        for cid in ("", "not-an-id", self.cid.upper(), self.cid + " ", 8, None):
            self.reject("COMMAND_ID_INVALID",
                        lambda cid=cid: self.journal.reserve(
                            command_id=cid, session_id=self.sid,
                            intent_sha256=self.intent))
        self.reject("COMMAND_INTENT_INVALID",
                    lambda: self.journal.reserve(
                        command_id=self.cid, session_id=self.sid,
                        intent_sha256="not-a-digest"))
        self.assertEqual(self.journal.summary()["unverified_count"], 0)

    def test_no_executor_signer_or_clear_api(self):
        for name in ("shell", "execute", "send", "clear",
                     "reset", "recover", "issue_grant", "spawn"):
            self.assertFalse(hasattr(self.journal, name))


if __name__ == "__main__":
    unittest.main()
