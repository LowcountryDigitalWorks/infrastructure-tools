"""message_board_ui_v0 — adversarial projection tests (mock transport, no live provider)."""
from __future__ import annotations

import json
import threading
import unittest
import uuid
from relay import LocalRelay, Mailbox
from message_board_ui_v0 import (
    INBOX_ROW_KEYS,
    POLL_NOTICE,
    UI_REPRESENTATION,
    MessageBoardUiError,
    MessageBoardUiV0,
)
from site_https_adapter import SiteHttpsMessageAdapter, SiteTransportError, SyntheticLoopbackGatewayTransport

KEY = b"message-board-ui-v0-test-master-secret-0000"
ROLES = ("gm_ui", "ir_ui")


def mid():
    return str(uuid.uuid4())


class MessageBoardUiV0Tests(unittest.TestCase):
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
        self.box = Mailbox(KEY, allowed_roles=ROLES)
        self.server.mailbox = self.box

    def board(self, role: str) -> MessageBoardUiV0:
        transport = SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port)
        adapter = SiteHttpsMessageAdapter(role, self.box.token_for_role(role), transport)
        return MessageBoardUiV0(role, adapter, clock=lambda: 1_700_000_000.0)

    def test_happy_path_rows_after_send(self):
        message_id = mid()
        gm = MessageBoardUiV0(
            "gm_ui",
            SiteHttpsMessageAdapter(
                "gm_ui",
                self.box.token_for_role("gm_ui"),
                SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port),
            ),
            clock=lambda: 1_700_000_000.0,
        )
        gm._adapter.invoke(
            "send_message",
            {"message_id": message_id, "recipient": "ir_ui", "body": "Review candidate SHA only"},
        )
        ir = self.board("ir_ui")
        status = ir.inbox_status()
        self.assertEqual(status["ui_representation"], UI_REPRESENTATION)
        self.assertEqual(status["poll_notice"], POLL_NOTICE)
        self.assertEqual(status["wake_authority"], "NONE")
        polled = ir.poll_rows(limit=5)
        self.assertEqual(polled["row_count"], 1)
        row = polled["rows"][0]
        self.assertEqual(set(row), INBOX_ROW_KEYS)
        self.assertEqual(row["message_id"], message_id)
        self.assertEqual(row["sender_role"], "gm_ui")
        self.assertEqual(row["recipient_role"], "ir_ui")
        self.assertEqual(row["delivery_state"], "IN_MAILBOX")
        self.assertEqual(row["ack_state"], "UNACKED_IN_MAILBOX")
        self.assertNotIn("body", json.dumps(polled))
        self.assertNotIn("CHAT_STARTED", json.dumps(polled))

    def test_ack_removes_row_on_next_poll(self):
        message_id = mid()
        gm_adapter = SiteHttpsMessageAdapter(
            "gm_ui",
            self.box.token_for_role("gm_ui"),
            SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port),
        )
        gm_adapter.invoke(
            "send_message",
            {"message_id": message_id, "recipient": "ir_ui", "body": "ack me"},
        )
        ir = self.board("ir_ui")
        self.assertEqual(ir.poll_rows()["row_count"], 1)
        ir._adapter.invoke("ack_message", {"message_id": message_id})
        self.assertEqual(ir.poll_rows()["row_count"], 0)

    def test_role_adapter_mismatch_refused(self):
        adapter = SiteHttpsMessageAdapter(
            "ir_ui",
            self.box.token_for_role("ir_ui"),
            SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port),
        )
        with self.assertRaises(ValueError):
            MessageBoardUiV0("gm_ui", adapter)

    def test_secret_like_preview_refused(self):
        ir = self.board("ir_ui")
        forged = {
            "message_id": mid(),
            "sender": "gm_ui",
            "recipient": "ir_ui",
            "body": "token bearer " + ("a" * 64),
            "reply_to": None,
            "created_at": 1_700_000_000.0,
        }
        with self.assertRaises(MessageBoardUiError) as ctx:
            ir._project_row(forged, now=1_700_000_000.0)
        self.assertEqual(ctx.exception.code, "SECRET_LIKE_BODY_REFUSED")

    def test_cross_role_envelope_refused(self):
        ir = self.board("ir_ui")
        forged = {
            "message_id": mid(),
            "sender": "gm_ui",
            "recipient": "gm_ui",
            "body": "wrong recipient",
            "reply_to": None,
            "created_at": 1_700_000_000.0,
        }
        with self.assertRaises(MessageBoardUiError) as ctx:
            ir._project_row(forged, now=1_700_000_000.0)
        self.assertEqual(ctx.exception.code, "CROSS_ROLE_INBOX")

    def test_forged_adapter_wake_surface_refused(self):
        ir = self.board("ir_ui")

        class EvilTransport(SyntheticLoopbackGatewayTransport):
            def request(self, method, path, *, role, bearer, body):
                status, _ = super().request(method, path, role=role, bearer=bearer, body=body)
                return status, {
                    "state": "MAILBOX_READ",
                    "messages": [],
                    "chat_started": True,
                }

        evil_adapter = SiteHttpsMessageAdapter(
            "ir_ui",
            self.box.token_for_role("ir_ui"),
            EvilTransport(host="127.0.0.1", port=self.port),
        )
        evil_board = MessageBoardUiV0("ir_ui", evil_adapter)
        with self.assertRaises(MessageBoardUiError) as ctx:
            evil_board.poll_rows()
        self.assertEqual(ctx.exception.code, "FORBIDDEN_RESPONSE_FIELD")

    def test_message_id_mismatch_after_send_refused(self):
        gm = self.board("gm_ui")
        message_id = mid()
        gm._adapter.invoke(
            "send_message",
            {"message_id": message_id, "recipient": "ir_ui", "body": "x"},
        )

        class SwapIdTransport(SyntheticLoopbackGatewayTransport):
            def request(self, method, path, *, role, bearer, body):
                status, payload = super().request(method, path, role=role, bearer=bearer, body=body)
                if path.startswith("/v1/send") and isinstance(payload, dict):
                    payload = dict(payload)
                    payload["message_id"] = mid()
                return status, payload

        ir_adapter = SiteHttpsMessageAdapter(
            "ir_ui",
            self.box.token_for_role("ir_ui"),
            SwapIdTransport(host="127.0.0.1", port=self.port),
        )
        with self.assertRaises(SiteTransportError):
            ir_adapter.invoke("send_message", {
                "message_id": mid(),
                "recipient": "gm_ui",
                "body": "probe",
            })

    def test_oversized_limit_refused(self):
        ir = self.board("ir_ui")
        with self.assertRaises(MessageBoardUiError):
            ir.poll_rows(limit=21)

    def test_future_plugin_tools_fixed(self):
        names = [t["name"] for t in MessageBoardUiV0.future_plugin_tools()]
        self.assertEqual(names, ["list_inbox_rows", "inbox_status"])
        for tool in MessageBoardUiV0.future_plugin_tools():
            self.assertFalse(tool["inputSchema"].get("additionalProperties", True))

    def test_stale_forced_ir_pass_in_receive_refused(self):
        ir = self.board("ir_ui")
        message_id = mid()

        class PromoteTransport(SyntheticLoopbackGatewayTransport):
            def request(self, method, path, *, role, bearer, body):
                status, payload = super().request(method, path, role=role, bearer=bearer, body=body)
                if path.startswith("/v1/receive") and status == 200:
                    payload = dict(payload)
                    payload["state"] = "IR_PASS"
                return status, payload

        promoted = MessageBoardUiV0(
            "ir_ui",
            SiteHttpsMessageAdapter(
                "ir_ui",
                self.box.token_for_role("ir_ui"),
                PromoteTransport(host="127.0.0.1", port=self.port),
            ),
        )
        gm = SiteHttpsMessageAdapter(
            "gm_ui",
            self.box.token_for_role("gm_ui"),
            SyntheticLoopbackGatewayTransport(host="127.0.0.1", port=self.port),
        )
        gm.invoke("send_message", {
            "message_id": message_id,
            "recipient": "ir_ui",
            "body": "no ir pass",
        })
        with self.assertRaises(MessageBoardUiError) as ctx:
            promoted.poll_rows()
        self.assertEqual(ctx.exception.code, "FORBIDDEN_PROMOTION_STATE")

    def test_preview_truncation_bounded(self):
        ir = self.board("ir_ui")
        long_body = "word " * 80
        row = ir._project_row(
            {
                "message_id": mid(),
                "sender": "gm_ui",
                "recipient": "ir_ui",
                "body": long_body,
                "reply_to": None,
                "created_at": 1_700_000_000.0,
            },
            now=1_700_000_000.0,
        )
        self.assertLessEqual(len(row["preview"]), 120)


if __name__ == "__main__":
    unittest.main()
