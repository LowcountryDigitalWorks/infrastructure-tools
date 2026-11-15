import os
import sqlite3
import subprocess
import sys
import stat
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from durable_mailbox import (
    OPT_IN, STATUS_NOTICE, DurableMailbox, DurableRefused,
)
from relay import MAX_MESSAGES, Mailbox, RelayError

SECRET = b"synthetic-test-key-only-NOT-FOR-PRODUCTION-00000"
ROLES = ("gm17", "ir02")


class DurableMailboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = [1_000.0]
        self.boxes = []

    def tearDown(self):
        for box in self.boxes:
            box.close()

    def directory(self, name="journal"):
        return Path(self.tmp.name) / name

    def open(self, *, roles=ROLES, clock=None, directory=None):
        box = DurableMailbox(
            SECRET, directory or self.directory(), opt_in=OPT_IN,
            allowed_roles=roles, clock=clock or (lambda: self.now[0]),
        )
        self.boxes.append(box)
        return box

    def send(self, box, **kw):
        payload = dict(
            message_id=kw.pop("message_id", str(uuid.uuid4())),
            sender=kw.pop("sender", "gm17"),
            recipient=kw.pop("recipient", "ir02"),
            body=kw.pop("body", "review synthetic candidate"),
        )
        payload.update(kw)
        actor = payload["sender"]
        return payload["message_id"], box.send(actor, payload)

    def assert_code(self, error, code, fn):
        with self.assertRaises(error) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_opt_in_required_and_default_mailbox_unchanged(self):
        self.assertIn("MANUAL_OR_TOOL_POLL_REQUIRED", STATUS_NOTICE)
        self.assert_code(
            DurableRefused, "DURABLE_OPT_IN_REQUIRED",
            lambda: DurableMailbox(SECRET, self.directory(), opt_in="yes", allowed_roles=ROLES),
        )
        memory = Mailbox(SECRET, allowed_roles=ROLES)
        sent = memory.send("gm17", {
            "message_id": str(uuid.uuid4()), "sender": "gm17",
            "recipient": "ir02", "body": "review synthetic candidate",
        })
        self.assertEqual(sent["state"], "IN_MAILBOX")
        self.assertFalse((Path(self.tmp.name) / "journal.sqlite").exists())

    def test_restart_keeps_pending_then_ack_tombstone(self):
        box = self.open()
        mid, receipt = self.send(box)
        self.assertEqual(receipt, {"message_id": mid, "state": "IN_MAILBOX", "duplicate": False})
        box.close()
        restored = self.open(directory=self.directory())
        self.assertEqual(restored.receive("ir02")["messages"][0]["message_id"], mid)
        self.assertEqual(restored.acknowledge("ir02", mid)["state"], "ACKNOWLEDGED")
        restored.close()
        again = self.open(directory=self.directory())
        self.assertEqual(again.receive("ir02")["messages"], [])
        self.assertTrue(self.send(again, message_id=mid)[1]["duplicate"])

    def test_changed_uuid_conflicts_after_restart(self):
        box = self.open()
        mid, _ = self.send(box)
        box.close()
        restored = self.open(directory=self.directory())
        self.assert_code(
            RelayError, "MESSAGE_ID_CONFLICT",
            lambda: self.send(restored, message_id=mid, body="changed synthetic text"),
        )

    def test_role_spoof_and_unknown_role_refused(self):
        box = self.open()
        self.assert_code(
            RelayError, "ROLE_MISMATCH",
            lambda: box.send("gm17", {
                "message_id": str(uuid.uuid4()), "sender": "ir02",
                "recipient": "gm17", "body": "review synthetic candidate",
            }),
        )
        self.assert_code(
            RelayError, "ROLE_NOT_REGISTERED",
            lambda: self.send(box, recipient="unknown"),
        )
        self.assert_code(RelayError, "ROLE_NOT_REGISTERED", lambda: box.receive("unknown"))

    def test_wrong_role_cannot_ack(self):
        box = self.open()
        mid, _ = self.send(box)
        self.assert_code(RelayError, "ROLE_MISMATCH", lambda: box.acknowledge("gm17", mid))
        self.assertEqual(len(box.receive("ir02")["messages"]), 1)

    def test_corruption_and_schema_tamper_fail_closed(self):
        box = self.open()
        self.send(box)
        box.close()
        path = self.directory() / "journal.sqlite"
        blob = bytearray(path.read_bytes())
        blob[0:4] = b"XXXX"
        path.write_bytes(blob)
        self.assert_code(DurableRefused, "DURABLE_CORRUPT", lambda: self.open(directory=self.directory()))
        path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
        self.assert_code(DurableRefused, "DURABLE_CORRUPT", lambda: self.open(directory=self.directory()))

    def test_close_reopen_and_roster_mismatch(self):
        box = self.open()
        mid, _ = self.send(box)
        box.close()
        self.assert_code(
            DurableRefused, "DURABLE_ROSTER_MISMATCH",
            lambda: self.open(directory=self.directory(), roles=("gm17", "ir03")),
        )
        restored = self.open(directory=self.directory())
        self.assertEqual(restored.receive("ir02")["messages"][0]["message_id"], mid)

    def test_concurrent_send_and_ack_are_isolated(self):
        box = self.open()
        ids = [str(uuid.uuid4()) for _ in range(2)]
        barrier = threading.Barrier(2)
        errors = []

        def worker(index):
            try:
                barrier.wait()
                if index == 0:
                    self.send(box, message_id=ids[0])
                else:
                    self.send(box, message_id=ids[1], sender="ir02", recipient="gm17",
                              body="synthetic reply candidate")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(
            {row["message_id"] for row in box.receive("ir02")["messages"]}, {ids[0]}
        )
        self.assertEqual(
            {row["message_id"] for row in box.receive("gm17")["messages"]}, {ids[1]}
        )

    def test_expiry_tombstone_and_wall_clock_rollback(self):
        box = self.open()
        mid, _ = self.send(box)
        self.now[0] = 500.0
        self.assertEqual(box.receive("ir02")["messages"][0]["message_id"], mid)
        box.close()
        restored = self.open(directory=self.directory())
        self.assertEqual(restored.receive("ir02")["messages"][0]["message_id"], mid)
        self.now[0] = 1_000.0 + 901
        self.assertEqual(restored.receive("ir02")["messages"], [])
        self.assert_code(RelayError, "NOT_FOUND", lambda: restored.acknowledge("ir02", mid))
        self.now[0] = 100.0
        again, receipt = self.send(restored, message_id=mid)
        self.assertEqual(again, mid)
        self.assertFalse(receipt["duplicate"])

    def test_forward_jump_expires_without_resurrecting_on_reopen(self):
        box = self.open()
        mid, _ = self.send(box)
        self.now[0] += 901
        self.assertEqual(box.receive("ir02")["messages"], [])
        box.close()
        self.now[0] = 100.0
        restored = self.open(directory=self.directory())
        self.assertEqual(restored.receive("ir02")["messages"], [])
        self.assert_code(RelayError, "NOT_FOUND", lambda: restored.acknowledge("ir02", mid))

    def test_path_symlink_and_sidecar_refused(self):
        file_path = Path(self.tmp.name) / "not-a-directory"
        file_path.write_text("synthetic", encoding="utf-8")
        self.assert_code(
            DurableRefused, "DURABLE_PATH_REFUSED",
            lambda: self.open(directory=file_path),
        )
        occupied = self.directory("occupied")
        occupied.mkdir()
        if os.name == "posix":
            os.chmod(occupied, 0o700)
        (occupied / "journal.sqlite-wal").write_bytes(b"")
        self.assert_code(
            DurableRefused, "DURABLE_SIDECAR",
            lambda: self.open(directory=occupied),
        )
        link_parent = Path(self.tmp.name) / "links"
        link_parent.mkdir()
        target = Path(self.tmp.name) / "target"
        target.mkdir()
        link = link_parent / "alias"
        try:
            os.symlink(target, link, target_is_directory=True)
        except OSError:
            return
        self.assert_code(
            DurableRefused, "DURABLE_PATH_REFUSED",
            lambda: self.open(directory=link),
        )

    def test_permissions_fail_closed_on_posix(self):
        if os.name != "posix":
            box = self.open()
            self.assertTrue((self.directory() / "journal.sqlite").is_file())
            box.close()
            return
        box = self.open()
        db_path = self.directory() / "journal.sqlite"
        self.assertEqual(stat.S_IMODE(os.lstat(self.directory()).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(db_path).st_mode), 0o600)
        box.close()
        os.chmod(db_path, 0o644)
        self.assert_code(
            DurableRefused, "DURABLE_PERMISSIONS",
            lambda: self.open(directory=self.directory()),
        )

    def test_crash_before_commit_discards_the_row(self):
        box = self.open()
        self.send(box)
        calls = {"crash": False}

        def crashing_clock():
            if calls["crash"]:
                raise RuntimeError("simulated crash")
            return self.now[0]

        box._clock = crashing_clock
        calls["crash"] = True
        with self.assertRaises(RuntimeError):
            self.send(box)
        box.close()
        restored = self.open(directory=self.directory())
        self.assertEqual(len(restored.receive("ir02")["messages"]), 1)

    def test_secret_and_token_are_not_stored(self):
        box = self.open()
        token = box.token_for_role("gm17")
        self.send(box)
        blob = (self.directory() / "journal.sqlite").read_bytes()
        self.assertNotIn(SECRET, blob)
        self.assertNotIn(token.encode("ascii"), blob)
        self.assert_code(
            RelayError, "INVALID_BODY",
            lambda: self.send(box, body="prefix " + SECRET.decode("ascii")),
        )

    def test_bounded_capacity(self):
        box = self.open()
        for _ in range(MAX_MESSAGES):
            self.send(box, message_id=str(uuid.uuid4()))
        self.assert_code(RelayError, "MAILBOX_FULL", lambda: self.send(box))

    def test_synthetic_send_receive_ack_restart_reply(self):
        box = self.open()
        mid, receipt = self.send(box)
        self.assertEqual(receipt["state"], "IN_MAILBOX")
        self.assertNotIn("CHAT_STARTED", receipt["state"])
        pending = box.receive("ir02")
        self.assertEqual(pending["state"], "MAILBOX_READ")
        self.assertEqual(pending["messages"][0]["body"], "review synthetic candidate")
        self.assertEqual(box.acknowledge("ir02", mid)["state"], "ACKNOWLEDGED")
        box.close()
        restored = self.open(directory=self.directory())
        reply = str(uuid.uuid4())
        sent = restored.send("ir02", {
            "message_id": reply, "sender": "ir02", "recipient": "gm17",
            "body": "synthetic reply", "reply_to": mid,
        })
        self.assertEqual(sent["state"], "IN_MAILBOX")
        self.assertFalse(sent["duplicate"])
        restored.close()
        final = self.open(directory=self.directory())
        row = final.receive("gm17")["messages"][0]
        self.assertEqual(row["reply_to"], mid)
        self.assertEqual(row["sender"], "ir02")
        self.assertEqual(final.receive("ir02")["messages"], [])

    def test_h1_complete_state_mac_refuses_offline_forgery(self):
        # These five probes were independently reproduced as accepted
        # against the unkeyed PR307 baseline. No real credentials/data.
        for attack in ("body", "insert", "delete", "secret", "high_water"):
            with self.subTest(attack=attack):
                directory = self.directory("h1_" + attack)
                box = self.open(directory=directory)
                mid, _ = self.send(box)
                box.close()
                path = directory / "journal.sqlite"
                if attack != "secret":
                    conn = sqlite3.connect(path)
                    try:
                        if attack == "body":
                            conn.execute(
                                "UPDATE messages SET body=? WHERE message_id=?",
                                ("forged public message", mid),
                            )
                        elif attack == "insert":
                            conn.execute(
                                "INSERT INTO messages VALUES(?,?,?,?,?,?,?,?)",
                                (str(uuid.uuid4()), "gm17", "ir02",
                                 "forged public message", None,
                                 1000000, 1900000, 0),
                            )
                        elif attack == "delete":
                            conn.execute(
                                "DELETE FROM messages WHERE message_id=?", (mid,)
                            )
                        elif attack == "high_water":
                            conn.execute(
                                "UPDATE meta SET value='0' WHERE key='wall_high_ms'"
                            )
                        conn.commit()
                    finally:
                        conn.close()
                def reopen():
                    return DurableMailbox(
                        b"synthetic-alternate-master-key-NEVER-REAL-000000"
                        if attack == "secret" else SECRET,
                        directory, opt_in=OPT_IN, allowed_roles=ROLES,
                        clock=lambda: self.now[0],
                    )
                self.assert_code(DurableRefused, "DURABLE_TAMPER", reopen)

    def test_h1_live_sqlite_mutation_detected_before_receive(self):
        box = self.open(directory=self.directory("h1_live"))
        mid, _ = self.send(box)
        path = self.directory("h1_live") / "journal.sqlite"
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                "UPDATE messages SET body='forged public message' WHERE message_id=?",
                (mid,),
            )
            conn.commit()
        finally:
            conn.close()
        self.assert_code(
            DurableRefused, "DURABLE_TAMPER",
            lambda: box.receive("ir02"),
        )

    def test_h1_integrity_commits_valid_ack_and_reopen(self):
        box = self.open(directory=self.directory("h1_roundtrip"))
        mid, _ = self.send(box)
        self.assertEqual(len(box.receive("ir02")["messages"]), 1)
        self.assertEqual(box.acknowledge("ir02", mid)["state"], "ACKNOWLEDGED")
        box.close()
        reopened = self.open(directory=self.directory("h1_roundtrip"))
        self.assertEqual(reopened.receive("ir02")["messages"], [])
        self.assertTrue(self.send(reopened, message_id=mid)[1]["duplicate"])

    def test_m4_surrogate_and_casefold_sensitive_content_refused(self):
        box = self.open(directory=self.directory("m4_inputs"))
        self.assert_code(
            RelayError, "INVALID_BODY",
            lambda: self.send(box, body="bad\ud800surrogate"),
        )
        self.assert_code(
            RelayError, "INVALID_BODY",
            lambda: self.send(
                box, body="synthetic " + SECRET.decode("ascii").swapcase()
            ),
        )
        self.assert_code(
            RelayError, "INVALID_BODY",
            lambda: self.send(
                box, body="synthetic " + box.token_for_role("ir02").upper()
            ),
        )
        self.assert_code(
            RelayError, "INVALID_LIMIT",
            lambda: box.receive("ir02", limit=True),
        )
        self.assertEqual(self.send(box)[1]["state"], "IN_MAILBOX")

    def test_m1_hot_rollback_journal_recovery_keeps_sealed_state(self):
        directory = self.directory("m1_hot")
        box = self.open(directory=directory)
        mid, _ = self.send(box)
        box.close()
        path = directory / "journal.sqlite"
        script = (
            "import sqlite3,os,sys\n"
            "c=sqlite3.connect(sys.argv[1],isolation_level=None)\n"
            "c.execute('BEGIN IMMEDIATE')\n"
            "c.execute(\"UPDATE messages SET body='interrupted synthetic text'\")\n"
            "os._exit(9)\n"
        )
        child = subprocess.run([sys.executable, "-c", script, str(path)],
                               check=False, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 9, child.stderr.decode(errors="replace"))
        journal = directory / "journal.sqlite-journal"
        self.assertTrue(journal.is_file(), "no hot SQLite rollback journal reproduced")
        recovered = self.open(directory=directory)
        self.assertEqual(
            recovered.receive("ir02")["messages"][0]["message_id"], mid
        )
        self.assertFalse(journal.exists())

    def test_m1_concurrent_sqlite_lock_returns_closed_busy_code(self):
        directory = self.directory("m1_busy")
        box = self.open(directory=directory)
        path = directory / "journal.sqlite"
        locker = sqlite3.connect(path, isolation_level=None)
        try:
            locker.execute("BEGIN EXCLUSIVE")
            self.assert_code(
                DurableRefused, "DURABLE_BUSY",
                lambda: box.receive("ir02"),
            )
        finally:
            locker.execute("ROLLBACK")
            locker.close()
        self.assertEqual(box.receive("ir02")["messages"], [])

    def test_m2_dropped_schema_or_malformed_values_refuse(self):
        for attack in ("drop_table", "bad_high", "bad_timestamp"):
            with self.subTest(attack=attack):
                directory = self.directory("m2_" + attack)
                box = self.open(directory=directory)
                self.send(box)
                box.close()
                conn = sqlite3.connect(directory / "journal.sqlite")
                try:
                    if attack == "drop_table":
                        conn.execute("DROP TABLE messages")
                    elif attack == "bad_high":
                        conn.execute(
                            "UPDATE meta SET value='not-an-integer' "
                            "WHERE key='wall_high_ms'"
                        )
                    else:
                        conn.execute(
                            "UPDATE messages SET created_ms='invalid'"
                        )
                    conn.commit()
                finally:
                    conn.close()
                self.assert_code(
                    DurableRefused, "DURABLE_TAMPER",
                    lambda: self.open(directory=directory),
                )

    def test_schema_version_mismatch_fails_closed(self):
        box = self.open(directory=self.directory("schema"))
        box.close()
        conn = sqlite3.connect(self.directory("schema") / "journal.sqlite")
        conn.execute("PRAGMA user_version=2")
        conn.commit()
        conn.close()
        self.assert_code(
            DurableRefused, "DURABLE_SCHEMA",
            lambda: self.open(directory=self.directory("schema")),
        )


if __name__ == "__main__":
    unittest.main()
