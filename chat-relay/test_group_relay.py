"""Pure synthetic proof: group transport is not ChatGPT recipient wake."""
import http.client
import json
import socket
import threading
import time
import unittest
import uuid

from group_relay import GroupMailbox, GroupLocalRelay, MAX_PER_SENDER, MAX_PER_GROUP, parse_room_config
from relay import RelayError, LocalRelay, MAX_MESSAGES, MAX_CLIENT_THREADS

SECRET = b"synthetic-only-LDW-group-mailbox-test-secret-1234567890"
ROOMS = {"ldw-ir": ["gm17", "ir02", "ops04"], "ldw-ops": ["gm17", "ops04"]}


def uid():
    return str(uuid.uuid4())


class GroupMailboxTests(unittest.TestCase):
    def setUp(self):
        self.clock = [300.0]
        self.ticks = [100.0]
        self.box = GroupMailbox(SECRET, ROOMS, clock=lambda: self.clock[0],
                                expiry_clock=lambda: self.ticks[0])
        self.id = uid()

    def send(self, actor="gm17", **changes):
        data = {
            "message_id": self.id, "group_id": "ldw-ir",
            "sender": actor, "body": "Review harmless artifact"
        }
        data.update(changes)
        return self.box.group_send(actor, data)

    def expect(self, code, func):
        with self.assertRaises(RelayError) as e:
            func()
        self.assertEqual(code, e.exception.code)

    def test_three_chat_broadcast_no_sender_echo(self):
        receipt = self.send()
        self.assertEqual((receipt["recipient_count"], receipt["state"]), (2, "GROUP_IN_MAILBOX"))
        self.assertEqual(self.box.group_receive("gm17", "ldw-ir")["messages"], [])
        for receiver in ("ir02", "ops04"):
            self.assertEqual(self.box.group_receive(receiver, "ldw-ir")["messages"][0]["message_id"], self.id)

    def test_each_member_ack_is_independent(self):
        self.send()
        self.assertEqual(self.box.group_acknowledge("ir02", "ldw-ir", self.id)["state"], "ACKNOWLEDGED")
        self.assertEqual(self.box.group_receive("ir02", "ldw-ir")["messages"], [])
        self.assertEqual(len(self.box.group_receive("ops04", "ldw-ir")["messages"]), 1)
        self.assertTrue(self.send()["duplicate"])
        self.assertEqual(self.box.group_receive("ir02", "ldw-ir")["messages"], [])
        self.expect("MESSAGE_ID_CONFLICT", lambda: self.send(body="altered"))

    def test_group_reply_visible_to_other_members(self):
        self.send()
        reply = uid()
        self.box.group_send("ir02", {
            "message_id": reply, "group_id": "ldw-ir", "sender": "ir02",
            "body": "ACCEPT synthetic", "reply_to": self.id
        })
        self.assertEqual(self.box.group_receive("gm17", "ldw-ir")["messages"][0]["reply_to"], self.id)
        self.assertEqual(len(self.box.group_receive("ops04", "ldw-ir")["messages"]), 2)

    def test_cannot_reply_across_groups(self):
        self.send()
        self.expect("INVALID_GROUP_REPLY", lambda: self.send(
            message_id=uid(), group_id="ldw-ops", reply_to=self.id
        ))

    def test_nonmember_cannot_access_or_send(self):
        self.send()
        self.expect("GROUP_NOT_FOUND", lambda: self.box.group_receive("ir02", "ldw-ops"))
        self.expect("GROUP_NOT_FOUND", lambda: self.box.group_send("ir02", {
            "message_id": uid(), "group_id": "ldw-ops", "sender": "ir02", "body": "intrusion"
        }))
        self.expect("GROUP_NOT_FOUND", lambda: self.box.group_acknowledge("ir02", "ldw-ops", self.id))

    def test_wall_clock_rollback_does_not_extend_group_ttl(self):
        self.send()
        self.box.group_acknowledge("ir02", "ldw-ir", self.id)
        self.clock[0] -= 86400
        self.ticks[0] += 899
        self.assertTrue(self.send()["duplicate"])
        self.ticks[0] += 2
        self.expect("NOT_FOUND", lambda: self.box.group_acknowledge("ir02", "ldw-ir", self.id))
        self.assertFalse(self.send()["duplicate"])

    def test_expired_group_message_never_resurrects_after_tick_regression(self):
        self.send()
        self.ticks[0] += 901
        self.assertEqual(self.box.group_receive("ir02", "ldw-ir")["messages"], [])
        self.ticks[0] -= 901
        self.expect("NOT_FOUND", lambda: self.box.group_acknowledge("ir02", "ldw-ir", self.id))

    def test_highwater_clamp_preserves_new_group_ttl_after_tick_rollback(self):
        # Keep the first group envelope live when time advances, then
        # send another after a clock regression. Without returning the
        # high-water tick, the second envelope prematurely expires.
        self.send()
        self.ticks[0] = 800.0
        self.assertIn(self.id, [
            msg["message_id"]
            for msg in self.box.group_receive("ir02", "ldw-ir")["messages"]
        ])
        self.ticks[0] = 200.0
        newer = uid()
        self.assertFalse(self.send(message_id=newer)["duplicate"])
        self.ticks[0] = 1200.0
        pending = [
            msg["message_id"]
            for msg in self.box.group_receive("ir02", "ldw-ir")["messages"]
        ]
        self.assertNotIn(self.id, pending)  # first message expired at tick 1000
        self.assertIn(newer, pending)       # second retained until tick 1700

    def test_role_impersonation_and_sender_ack_refused(self):
        self.expect("ROLE_MISMATCH", lambda: self.send(sender="ops04"))
        self.send()
        self.expect("ROLE_MISMATCH", lambda: self.box.group_acknowledge("gm17", "ldw-ir", self.id))

    def test_expiry_and_ack_tombstone(self):
        self.send()
        self.box.group_acknowledge("ir02", "ldw-ir", self.id)
        self.assertTrue(self.send()["duplicate"])
        self.assertEqual(self.box.group_receive("ir02", "ldw-ir")["messages"], [])
        self.clock[0] += 901
        self.ticks[0] += 901
        self.assertEqual(self.box.group_receive("ops04", "ldw-ir")["messages"], [])
        self.expect("NOT_FOUND", lambda: self.box.group_acknowledge("ops04", "ldw-ir", self.id))

    def test_uuid_namespace_shared_across_direct_and_group(self):
        self.send()
        self.expect("MESSAGE_ID_CONFLICT", lambda: self.box.send("gm17", {
            "message_id": self.id, "sender": "gm17", "recipient": "ir02", "body": "direct"
        }))
        direct_id = uid()
        self.box.send("gm17", {
            "message_id": direct_id, "sender": "gm17", "recipient": "ir02", "body": "direct"
        })
        self.expect("MESSAGE_ID_CONFLICT", lambda: self.send(message_id=direct_id))

    def test_group_directory_only_member_rooms(self):
        only_ir = self.box.groups_for("ir02")["groups"]
        self.assertEqual([x["group_id"] for x in only_ir], ["ldw-ir"])
        self.assertEqual(self.box.groups_for("unbound")["groups"], [])

    def test_invalid_group_and_input_bounds(self):
        self.expect("INVALID_GROUP_ID", lambda: self.send(group_id="BAD"))
        self.expect("INVALID_BODY", lambda: self.send(body="x" * 8193))
        self.expect("INVALID_ENVELOPE", lambda: self.send(admin=True))
        self.expect("INVALID_LIMIT", lambda: self.box.group_receive("gm17", "ldw-ir", 100))
        self.expect("GROUP_NOT_FOUND", lambda: self.send(group_id="unknown-room"))

    def test_sender_quota_cannot_starve_unrelated_group_or_direct(self):
        first = uid()
        self.send(message_id=first)
        for _ in range(MAX_PER_SENDER - 1):
            self.send(message_id=uid())
        self.expect("SENDER_QUOTA_EXCEEDED", lambda: self.send(message_id=uid()))
        self.assertTrue(self.send(message_id=first)["duplicate"])
        # Another sender in another room still has capacity even though
        # gm17 reached its sender limit.
        self.assertEqual(self.box.group_send("ops04", {
            "message_id": uid(), "sender": "ops04",
            "group_id": "ldw-ops", "body": "unrelated group"
        })["state"], "GROUP_IN_MAILBOX")
        self.assertEqual(self.box.send("ir02", {
            "message_id": uid(), "sender": "ir02",
            "recipient": "gm17", "body": "direct still usable"
        })["state"], "IN_MAILBOX")
        self.expect("SENDER_QUOTA_EXCEEDED", lambda: self.box.send("gm17", {
            "message_id": uid(), "sender": "gm17",
            "recipient": "ir02", "body": "quota applied across modes"
        }))

    def test_direct_sender_cannot_starve_group_mailboxes(self):
        for _ in range(MAX_PER_SENDER):
            self.box.send("gm17", {
                "message_id": uid(), "sender": "gm17",
                "recipient": "ir02", "body": "bounded direct message"
            })
        self.expect("SENDER_QUOTA_EXCEEDED", lambda: self.send(message_id=uid()))
        self.assertEqual(self.box.group_send("ir02", {
            "message_id": uid(), "sender": "ir02",
            "group_id": "ldw-ir", "body": "other member can still send"
        })["state"], "GROUP_IN_MAILBOX")

    def test_room_quota_preserves_other_room_capacity(self):
        for sender in ("gm17", "ir02"):
            for _ in range(MAX_PER_SENDER):
                self.send(actor=sender, message_id=uid())
        self.assertEqual(MAX_PER_GROUP, 2 * MAX_PER_SENDER)
        self.expect("GROUP_QUOTA_EXCEEDED", lambda: self.send(
            actor="ops04", message_id=uid()))
        self.assertEqual(self.box.group_send("ops04", {
            "message_id": uid(), "sender": "ops04",
            "group_id": "ldw-ops", "body": "other room not starved"
        })["state"], "GROUP_IN_MAILBOX")

    def test_member_cannot_read_or_ack_other_room_message(self):
        ir_id, ops_id = uid(), uid()
        self.send(message_id=ir_id)
        self.send(message_id=ops_id, group_id="ldw-ops")
        ir_view = self.box.group_receive("ops04", "ldw-ir")["messages"]
        ops_view = self.box.group_receive("ops04", "ldw-ops")["messages"]
        self.assertEqual([x["message_id"] for x in ir_view], [ir_id])
        self.assertEqual([x["message_id"] for x in ops_view], [ops_id])
        self.expect("NOT_FOUND", lambda: self.box.group_acknowledge(
            "ops04", "ldw-ops", ir_id))
        self.assertEqual(len(self.box.group_receive("ops04", "ldw-ir")["messages"]), 1)

    def test_reject_bad_membership_config(self):
        for groups in ({"ldw-ir": ["gm17", "gm17"]},
                       {"ldw-ir": ["gm17"]}, {"BAD": ["gm17", "ir02"]},
                       {"ldw-ir": ["gm17", "BAD"]},
                       {"ldw-ir": "gm17,ir02"}):
            with self.assertRaises(ValueError):
                GroupMailbox(SECRET, groups)

    def test_room_config_rejects_duplicate_names(self):
        self.assertRaises(ValueError, parse_room_config,
            '{"ldw-ir":["gm17","ir02"],"ldw-ir":["gm17","ops04"]}')
        parsed = parse_room_config(
            '{"ldw-ir":["gm17","ir02"],"ldw-ops":["gm17","ops04"]}')
        self.assertEqual(len(parsed), 2)

    def test_nonmember_room_exists_and_absent_are_indistinguishable(self):
        for group_id in ("ldw-ops", "not-a-room"):
            self.expect("GROUP_NOT_FOUND", lambda group_id=group_id:
                        self.box.group_receive("ir02", group_id))

    def test_refuse_public_binding(self):
        with self.assertRaises(ValueError):
            GroupLocalRelay(("0.0.0.0", 0), self.box)


class GroupHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box = GroupMailbox(SECRET, ROOMS)
        cls.server = GroupLocalRelay(("127.0.0.1", 0), cls.box)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=2)

    def request(self, method, path, role=None, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {}
        if role:
            headers["X-LDW-Role"] = role
            headers["Authorization"] = "Bearer " + (token or self.box.token_for_role(role))
        payload = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        result = (resp.status, json.loads(resp.read()))
        conn.close()
        return result

    def test_http_group_send_receive_reply_ack(self):
        message_id = uid()
        status, receipt = self.request("POST", "/v1/groups/send", "gm17", {
            "message_id": message_id, "group_id": "ldw-ir",
            "sender": "gm17", "body": "Independent synthetic review request"
        })
        self.assertEqual((status, receipt["state"]), (200, "GROUP_IN_MAILBOX"))
        _, inbox_ir = self.request("GET", "/v1/groups/receive?group_id=ldw-ir", "ir02")
        _, inbox_ops = self.request("GET", "/v1/groups/receive?group_id=ldw-ir", "ops04")
        for inbox in (inbox_ir, inbox_ops):
            self.assertTrue(any(m["message_id"] == message_id for m in inbox["messages"]))
        status, receipt = self.request("POST", "/v1/groups/ack", "ir02", {
            "group_id": "ldw-ir", "message_id": message_id
        })
        self.assertEqual((status, receipt["state"]), (200, "ACKNOWLEDGED"))
        _, inbox_ir = self.request("GET", "/v1/groups/receive?group_id=ldw-ir", "ir02")
        self.assertFalse(any(m["message_id"] == message_id for m in inbox_ir["messages"]))
        _, inbox_ops = self.request("GET", "/v1/groups/receive?group_id=ldw-ir", "ops04")
        self.assertTrue(any(m["message_id"] == message_id for m in inbox_ops["messages"]))
        reply_id = uid()
        status, reply_receipt = self.request("POST", "/v1/groups/send", "ir02", {
            "message_id": reply_id, "group_id": "ldw-ir", "sender": "ir02",
            "body": "Independent synthetic review received", "reply_to": message_id
        })
        self.assertEqual((status, reply_receipt["state"]), (200, "GROUP_IN_MAILBOX"))
        _, gm_inbox = self.request("GET", "/v1/groups/receive?group_id=ldw-ir", "gm17")
        self.assertTrue(any(m["message_id"] == reply_id and m["reply_to"] == message_id for m in gm_inbox["messages"]))

    def test_http_private_directory_and_invalid_auth(self):
        status, member_list = self.request("GET", "/v1/groups", "ir02")
        self.assertEqual(status, 200)
        self.assertEqual([g["group_id"] for g in member_list["groups"]], ["ldw-ir"])
        status, failure = self.request("GET", "/v1/groups", "gm17", token="wrong")
        self.assertEqual((status, failure["error"]), (401, "UNAUTHORIZED"))
        status, failure = self.request("GET", "/v1/groups/receive?group_id=ldw-ops", "ir02")
        self.assertEqual((status, failure["error"]), (404, "GROUP_NOT_FOUND"))

    def test_http_query_and_scope_fail_closed(self):
        status, error = self.request("GET", "/v1/groups/receive?group_id=ldw-ir&group_id=ldw-ops", "gm17")
        self.assertEqual((status, error["error"]), (400, "INVALID_QUERY"))
        status, error = self.request("GET", "/v1/groups/receive?group_id=ldw-ir&limit=21", "gm17")
        self.assertEqual((status, error["error"]), (400, "INVALID_LIMIT"))
        status, error = self.request("POST", "/v1/groups/ack", "gm17", {"message_id": uid()})
        self.assertEqual((status, error["error"]), (400, "INVALID_ENVELOPE"))

    def test_direct_receive_rejects_blank_or_duplicate_limits(self):
        for path in ("/v1/receive?limit=", "/v1/receive?limit=1&limit=2",
                     "/v1/receive?limit=1&extra=2"):
            status, error = self.request("GET", path, "ir02")
            self.assertEqual((status, error["error"]), (400, "INVALID_QUERY"))

    def test_legacy_direct_missing_required_field_is_bounded_error(self):
        status, error = self.request("POST", "/v1/send", "gm17", {
            "message_id": uid(), "sender": "gm17", "body": "fixture",
            "reply_to": uid()
        })
        self.assertEqual((status, error["error"]), (400, "INVALID_ENVELOPE"))

    def test_recursive_json_and_oversized_integer_return_json_error(self):
        # The client inputs are deliberately invalid and never executed.
        for payload in (
            b"[" * 1100 + b"0" + b"]" * 1100,
            b'{"number":' + b"9" * 5000 + b"}",
        ):
            for path in ("/v1/send", "/v1/groups/send"):
                with self.subTest(path=path, length=len(payload)):
                    conn = http.client.HTTPConnection(
                        "127.0.0.1", self.server.server_port, timeout=3)
                    try:
                        conn.request("POST", path, body=payload,
                                     headers={
                                        "X-LDW-Role": "gm17",
                                        "Authorization": "Bearer " + self.box.token_for_role("gm17"),
                                        "Content-Type": "application/json",
                                     })
                        response = conn.getresponse()
                        status = response.status
                        reply = json.loads(response.read())
                        self.assertEqual(status, 400)
                        if payload.startswith(b"["):
                            # A deeply nested but parseable JSON list is a
                            # bad envelope; parser-dependent recursion refusal
                            # is likewise a bounded JSON error.
                            self.assertIn(reply["error"], ("INVALID_JSON", "INVALID_ENVELOPE"))
                        else:
                            self.assertEqual(reply["error"], "INVALID_JSON")
                    finally:
                        conn.close()

    def test_group_http_bounded_connection_admission(self):
        self.assertTrue(issubclass(GroupLocalRelay, LocalRelay))
        holders = []
        try:
            for _ in range(MAX_CLIENT_THREADS):
                sock = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
                sock.sendall(b"GET /v1/groups HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                holders.append(sock)
            time.sleep(0.3)
            self.assertFalse(self.server._slots.acquire(blocking=False))
        finally:
            for sock in holders:
                sock.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.server._slots.acquire(blocking=False):
                self.server._slots.release()
                return
            time.sleep(0.05)
        self.fail("group relay worker slots did not recover")

    def test_http_direct_legacy_works(self):
        direct_id = uid()
        status, receipt = self.request("POST", "/v1/send", "gm17", {
            "message_id": direct_id, "sender": "gm17",
            "recipient": "ir02", "body": "direct remains available"
        })
        self.assertEqual((status, receipt["state"]), (200, "IN_MAILBOX"))
        _, direct = self.request("GET", "/v1/receive", "ir02")
        self.assertTrue(any(m["message_id"] == direct_id for m in direct["messages"]))


if __name__ == "__main__":
    unittest.main()
