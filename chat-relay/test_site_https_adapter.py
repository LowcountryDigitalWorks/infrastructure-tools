"""Synthetic Gate B Site HTTPS adapter tests — mock transport only, no live gateway."""
from __future__ import annotations

import json
import threading
import unittest
import uuid

from relay import LocalRelay, Mailbox
from site_https_adapter import (
    FORBIDDEN_PROMOTION,
    SITE_PROTOCOL,
    SiteHttpsMessageAdapter,
    SiteTransportError,
    SyntheticLoopbackGatewayTransport,
)

KEY = b"synthetic-site-gate-b-https-adapter-test-key-000000"
ROLES = ("gm22", "ir07")


def mid():
    return str(uuid.uuid4())


class SiteGatewayTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box = Mailbox(KEY, allowed_roles=ROLES)
        cls.server = LocalRelay(("127.0.0.1", 0), cls.box)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        # Shared listener, isolated mailbox per test to avoid cross-test inbox leakage.
        self.box = Mailbox(KEY, allowed_roles=ROLES)
        self.server.mailbox = self.box

    def adapter(self, role: str) -> SiteHttpsMessageAdapter:
        transport = SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port)
        return SiteHttpsMessageAdapter(role, self.box.token_for_role(role), transport)

    def test_send_receive_ack_and_https_framing(self):
        message_id = mid()
        gm = self.adapter("gm22")
        transport = gm._transport
        receipt = gm.invoke("send_message", {
            "message_id": message_id,
            "recipient": "ir07",
            "body": "Synthetic Gate B packet",
        })
        self.assertEqual(receipt["state"], "IN_MAILBOX")
        self.assertEqual(receipt["delivery_notice"], "IN_MAILBOX / NOT_AUTO_WOKEN")
        self.assertNotIn("CHAT_STARTED", json.dumps(receipt))
        self.assertEqual(transport.calls[0]["scheme"], "https")
        self.assertEqual(transport.calls[0]["method"], "POST")
        self.assertEqual(transport.calls[0]["path"], "/v1/send")

        ir = self.adapter("ir07")
        inbox = ir.invoke("receive_messages", {})
        self.assertEqual(inbox["state"], "MAILBOX_READ")
        self.assertEqual(inbox["delivery_notice"], "IN_MAILBOX / NOT_AUTO_WOKEN")
        ids = [m["message_id"] for m in inbox["messages"]]
        self.assertIn(message_id, ids)
        ack = ir.invoke("ack_message", {"message_id": message_id})
        self.assertEqual(ack["state"], "ACKNOWLEDGED")
        self.assertEqual(ir.invoke("receive_messages", {})["messages"], [])

    def test_tool_catalog_is_fixed_and_minimal(self):
        names = [t["name"] for t in SiteHttpsMessageAdapter.tool_catalog()]
        self.assertEqual(names, ["send_message", "receive_messages", "ack_message"])
        for tool in SiteHttpsMessageAdapter.tool_catalog():
            self.assertFalse(tool["inputSchema"].get("additionalProperties", True))

    def test_forbidden_model_identity_fields(self):
        gm = self.adapter("gm22")
        for bad in (
            {"message_id": mid(), "recipient": "ir07", "body": "x", "sender": "ir07"},
            {"message_id": mid(), "recipient": "ir07", "body": "x", "token": "abc"},
            {"message_id": mid(), "recipient": "ir07", "body": "x", "bearer": "abc"},
            {"message_id": mid(), "recipient": "ir07", "body": "x", "wake": True},
            {"message_id": mid(), "recipient": "ir07", "body": "x", "chat_started": True},
        ):
            with self.subTest(bad=sorted(bad)):
                with self.assertRaises(SiteTransportError):
                    gm.invoke("send_message", bad)

    def test_impersonation_and_reply_mismatch_fail_closed(self):
        gm = self.adapter("gm22")
        parent = mid()
        gm.invoke("send_message", {
            "message_id": parent, "recipient": "ir07", "body": "parent",
        })
        with self.assertRaises(SiteTransportError) as err:
            gm.invoke("ack_message", {"message_id": parent})
        self.assertEqual(err.exception.code, "ROLE_MISMATCH")
        reply = mid()
        with self.assertRaises(SiteTransportError):
            gm.invoke("send_message", {
                "message_id": reply,
                "recipient": "ir07",
                "body": "bad reply",
                "reply_to": mid(),
            })

    def test_uuid_replay_and_changed_body_conflict(self):
        gm = self.adapter("gm22")
        ir = self.adapter("ir07")
        message_id = mid()
        self.assertFalse(gm.invoke("send_message", {
            "message_id": message_id, "recipient": "ir07", "body": "one",
        })["duplicate"])
        self.assertTrue(gm.invoke("send_message", {
            "message_id": message_id, "recipient": "ir07", "body": "one",
        })["duplicate"])
        with self.assertRaises(SiteTransportError) as err:
            gm.invoke("send_message", {
                "message_id": message_id, "recipient": "ir07", "body": "two",
            })
        self.assertEqual(err.exception.code, "MESSAGE_ID_CONFLICT")
        ir.invoke("ack_message", {"message_id": message_id})
        self.assertTrue(gm.invoke("send_message", {
            "message_id": message_id, "recipient": "ir07", "body": "one",
        })["duplicate"])

    def test_unknown_tool_and_oversized_body(self):
        gm = self.adapter("gm22")
        with self.assertRaises(SiteTransportError):
            gm.invoke("list_groups", {})
        with self.assertRaises(SiteTransportError):
            gm.invoke("send_message", {
                "message_id": mid(),
                "recipient": "ir07",
                "body": "x" * 9000,
            })

    def test_forbidden_promotion_states_rejected_if_injected(self):
        class PoisonTransport:
            def request(self, method, path, *, role, bearer, body):
                return 200, {"message_id": mid(), "state": "CHAT_STARTED"}

        poison = SiteHttpsMessageAdapter("gm22", self.box.token_for_role("gm22"), PoisonTransport())
        with self.assertRaises(SiteTransportError) as err:
            poison.invoke("send_message", {
                "message_id": mid(), "recipient": "ir07", "body": "x",
            })
        self.assertEqual(err.exception.code, "FORBIDDEN_PROMOTION_STATE")
        self.assertIn("CHAT_STARTED", FORBIDDEN_PROMOTION)
        self.assertIn("IR_PASS", FORBIDDEN_PROMOTION)

    def test_gateway_host_binding_refuses_public_listener_pattern(self):
        with self.assertRaises(ValueError):
            SyntheticLoopbackGatewayTransport(host="0.0.0.0", port=self.port)

    def test_site_protocol_constant_documented(self):
        self.assertEqual(SITE_PROTOCOL, "ldw.chat-relay.site-gate-b.v1")
