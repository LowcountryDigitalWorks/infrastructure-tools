import http.client
import json
import socket
import threading
import time
import unittest
import uuid

from relay import Mailbox, LocalRelay, RelayError, MAX_MESSAGES, MAX_CLIENT_THREADS

SECRET = b"synthetic-test-key-only-NOT-FOR-PRODUCTION-00000"
ROLES = ("gm17", "ir02")


class MailboxTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.ticks = [100.0]
        self.box = Mailbox(SECRET, clock=lambda: self.now[0],
                           allowed_roles=ROLES, expiry_clock=lambda: self.ticks[0])
        self.id = str(uuid.uuid4())

    def send(self, **kw):
        p = dict(message_id=self.id, sender="gm17", recipient="ir02", body="review synthetic candidate")
        p.update(kw)
        return self.box.send("gm17", p)

    def assertCode(self, code, fn):
        with self.assertRaises(RelayError) as exc:
            fn()
        self.assertEqual(code, exc.exception.code)

    def test_roundtrip_and_ack(self):
        self.assertFalse(self.send()["duplicate"])
        self.assertEqual(self.box.receive("ir02")["messages"][0]["body"], "review synthetic candidate")
        self.assertEqual(self.box.acknowledge("ir02", self.id)["state"], "ACKNOWLEDGED")
        self.assertEqual(self.box.receive("ir02")["messages"], [])

    def test_ack_replay_keeps_tombstone_until_expiry(self):
        self.send()
        self.box.acknowledge("ir02", self.id)
        self.assertTrue(self.send()["duplicate"])
        self.assertEqual(self.box.receive("ir02")["messages"], [])
        self.assertCode("MESSAGE_ID_CONFLICT", lambda: self.send(body="changed-after-ack"))

    def test_reply_in_other_direction(self):
        self.send()
        reply_id = str(uuid.uuid4())
        self.box.send("ir02", dict(message_id=reply_id, sender="ir02", recipient="gm17", body="PASS", reply_to=self.id))
        self.assertEqual(self.box.receive("gm17")["messages"][0]["reply_to"], self.id)

    def test_auth_is_role_scoped(self):
        token = self.box.token_for_role("gm17")
        self.box.authenticate("gm17", token)
        self.assertCode("UNAUTHORIZED", lambda: self.box.authenticate("ir02", token))
        self.assertCode("UNAUTHORIZED", lambda: self.box.authenticate("gm17", "wrong"))

    def test_sender_cannot_impersonate(self):
        self.assertCode("ROLE_MISMATCH", lambda: self.send(sender="ir02"))
        self.assertCode("ROLE_MISMATCH", lambda: self.send(recipient="gm17"))
        self.send()
        self.assertCode("ROLE_MISMATCH", lambda: self.box.acknowledge("gm17", self.id))

    def test_duplicate_and_conflict(self):
        self.send()
        self.assertTrue(self.send()["duplicate"])
        self.assertCode("MESSAGE_ID_CONFLICT", lambda: self.send(body="different"))

    def test_expiry(self):
        self.send()
        self.now[0] += 901
        self.ticks[0] += 901
        self.assertEqual(self.box.receive("ir02")["messages"], [])
        self.assertCode("NOT_FOUND", lambda: self.box.acknowledge("ir02", self.id))

    def test_wall_clock_rollback_does_not_extend_direct_ttl_or_replay_window(self):
        self.send()
        self.box.acknowledge("ir02", self.id)
        self.now[0] -= 86400  # wall clock moves back one day
        self.ticks[0] += 899
        self.assertTrue(self.send()["duplicate"])
        self.ticks[0] += 2
        self.assertCode("NOT_FOUND", lambda: self.box.acknowledge("ir02", self.id))
        self.assertFalse(self.send()["duplicate"])

    def test_expired_direct_message_never_resurrects_after_tick_regression(self):
        self.send()
        self.ticks[0] += 901
        self.assertEqual(self.box.receive("ir02")["messages"], [])
        self.ticks[0] -= 901
        self.assertCode("NOT_FOUND", lambda: self.box.acknowledge("ir02", self.id))

    def test_highwater_clamp_preserves_new_direct_ttl_after_tick_rollback(self):
        # Unlike a post-GC resurrection test, this keeps a live message
        # across a rollback and then sends a NEW message while time is low.
        # Removing the high-water return guard expires that new message early.
        self.send()
        self.ticks[0] = 800.0
        self.assertIn(self.id, [
            msg["message_id"] for msg in self.box.receive("ir02")["messages"]
        ])
        self.ticks[0] = 200.0
        newer = str(uuid.uuid4())
        self.assertFalse(self.send(message_id=newer)["duplicate"])
        self.ticks[0] = 1200.0
        pending = [
            msg["message_id"] for msg in self.box.receive("ir02")["messages"]
        ]
        self.assertNotIn(self.id, pending)  # first message expired at tick 1000
        self.assertIn(newer, pending)       # second retained until tick 1700

    def test_reject_unbounded_payload(self):
        self.assertCode("INVALID_BODY", lambda: self.send(body="x" * 8193))
        self.assertCode("INVALID_MESSAGE_ID", lambda: self.send(message_id="not-a-uuid"))
        self.assertCode("INVALID_ENVELOPE", lambda: self.send(extra="surprise"))

    def test_full_mailbox_rejects_and_releases_after_expiry(self):
        for _ in range(MAX_MESSAGES):
            self.send(message_id=str(uuid.uuid4()))
        self.assertCode("MAILBOX_FULL", lambda: self.send())
        self.now[0] += 901
        self.ticks[0] += 901
        self.assertFalse(self.send()["duplicate"])

    def test_no_nonlocal_bind(self):
        self.assertRaises(ValueError, LocalRelay, ("0.0.0.0", 0), self.box)

    def test_unknown_role_never_receives_token_or_messages(self):
        self.assertCode("ROLE_NOT_REGISTERED", lambda: self.box.token_for_role("unknown"))
        self.assertCode("ROLE_NOT_REGISTERED", lambda: self.send(recipient="unknown"))
        self.assertCode("UNAUTHORIZED", lambda: self.box.authenticate("unknown", "x" * 64))

    def test_invalid_role_roster_refused(self):
        for roles in ((), ("gm17",), ("gm17", "gm17"), ("gm17", "BAD")):
            with self.assertRaises(ValueError):
                Mailbox(SECRET, allowed_roles=roles)

    def test_reply_must_reference_reverse_direction_existing_message(self):
        self.assertCode("INVALID_REPLY_TO", lambda: self.send(reply_to=str(uuid.uuid4())))
        self.send()
        self.assertCode("INVALID_REPLY_TO", lambda: self.send(
            message_id=str(uuid.uuid4()), reply_to=self.id))
        reverse = dict(message_id=str(uuid.uuid4()), sender="ir02", recipient="gm17",
                       body="terminal response", reply_to=self.id)
        self.assertFalse(self.box.send("ir02", reverse)["duplicate"])
        self.assertEqual(self.box.receive("gm17")["messages"][0]["reply_to"], self.id)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box = Mailbox(SECRET, allowed_roles=ROLES)
        cls.srv = LocalRelay(("127.0.0.1", 0), cls.box)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.thread.join(timeout=2)

    def req(self, method, path, role=None, data=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=2)
        headers = {}
        if role:
            headers.update({"X-LDW-Role": role, "Authorization": "Bearer " + (token or self.box.token_for_role(role))})
        body = json.dumps(data).encode() if data is not None else None
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        rsp = conn.getresponse()
        ret = rsp.status, json.loads(rsp.read())
        conn.close()
        return ret

    def test_http_two_actors(self):
        mid = str(uuid.uuid4())
        status, response = self.req("POST", "/v1/send", role="gm17", data={
            "message_id": mid, "sender": "gm17", "recipient": "ir02", "body": "Review packet R1"})
        self.assertEqual((status, response["state"]), (200, "IN_MAILBOX"))
        status, inbox = self.req("GET", "/v1/receive", role="ir02")
        self.assertEqual(status, 200)
        self.assertIn(mid, [m["message_id"] for m in inbox["messages"]])
        status, ack = self.req("POST", "/v1/ack", role="ir02", data={"message_id": mid})
        self.assertEqual((status, ack["state"]), (200, "ACKNOWLEDGED"))

    def test_http_denies_wrong_token(self):
        status, body = self.req("GET", "/v1/receive", role="gm17", token="incorrect")
        self.assertEqual((status, body["error"]), (401, "UNAUTHORIZED"))

    def test_http_no_sensitive_health(self):
        status, body = self.req("GET", "/health")
        self.assertEqual((status, body["scope"]), (200, "LOCAL_ONLY"))
        self.assertNotIn("secret", json.dumps(body))

    def test_partial_header_connections_have_bounded_admission(self):
        holders = []
        try:
            for _ in range(MAX_CLIENT_THREADS):
                sock = socket.create_connection(("127.0.0.1", self.srv.server_port), timeout=2)
                sock.sendall(b"POST /v1/send HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n")
                holders.append(sock)
            # Give the server's accept thread a bounded turn to admit socket workers.
            time.sleep(0.25)
            self.assertFalse(self.srv._slots.acquire(blocking=False))
        finally:
            for sock in holders:
                sock.close()
        # Allow the accepted workers to observe peer closure and restore slots.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status, reply = self.req("GET", "/health")
            if status == 200:
                return
            time.sleep(0.05)
        self.fail("relay did not recover from incomplete requests")


if __name__ == "__main__":
    unittest.main()
