"""Bounded MCP stdio adapter tests with a shared loopback group relay and three role clients.

These are three local tool clients, NOT three real native ChatGPT conversations.
"""
from __future__ import annotations

import io
import json
import threading
import unittest
import uuid

from group_relay import GroupLocalRelay, GroupMailbox
from mcp_local import GroupTransportClient, StdioMcpBridge, PROTOCOL

KEY = b"synthetic-only-local-mcp-bridge-test-secret-00000000"
ROOMS = {"ldw-ir": ["gm17", "ir02", "ops04"]}


def unique_id():
    return str(uuid.uuid4())


class LocalMcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box = GroupMailbox(KEY, ROOMS)
        cls.server = GroupLocalRelay(("127.0.0.1", 0), cls.box)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.clients = {}
        for role in ROOMS["ldw-ir"]:
            local = GroupTransportClient(role, cls.box.token_for_role(role), cls.server.server_port)
            bridge = StdioMcpBridge(local)
            init = bridge.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": PROTOCOL,
                                             "clientInfo": {"name": "synthetic", "version": "1"},
                                             "capabilities": {}}})
            if init["result"]["protocolVersion"] != PROTOCOL:
                raise AssertionError("MCP negotiation not accepted")
            cls.clients[role] = bridge

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def call(self, role, name, **args):
        res = self.clients[role].handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })
        self.assertEqual(res["result"]["isError"], False, res)
        return json.loads(res["result"]["content"][0]["text"])

    def test_one_sender_two_distinct_receivers_and_ack(self):
        mid = unique_id()
        receipt = self.call("gm17", "send_group_message",
                            group_id="ldw-ir", message_id=mid, body="Review harmless synthetic packet")
        self.assertEqual((receipt["state"], receipt["recipient_count"]), ("GROUP_IN_MAILBOX", 2))
        ir = self.call("ir02", "receive_group_messages", group_id="ldw-ir")
        ops = self.call("ops04", "receive_group_messages", group_id="ldw-ir")
        self.assertIn(mid, [item["message_id"] for item in ir["messages"]])
        self.assertIn(mid, [item["message_id"] for item in ops["messages"]])
        ack = self.call("ir02", "ack_group_message", group_id="ldw-ir", message_id=mid)
        self.assertEqual(ack["state"], "ACKNOWLEDGED")
        ir_after = self.call("ir02", "receive_group_messages", group_id="ldw-ir")
        ops_after = self.call("ops04", "receive_group_messages", group_id="ldw-ir")
        self.assertNotIn(mid, [item["message_id"] for item in ir_after["messages"]])
        self.assertIn(mid, [item["message_id"] for item in ops_after["messages"]])

    def test_group_reply_uses_original_uuid_and_trusted_sender(self):
        parent = unique_id()
        self.call("gm17", "send_group_message", group_id="ldw-ir", message_id=parent, body="Initial")
        reply_id = unique_id()
        reply = self.call("ir02", "send_group_message", group_id="ldw-ir",
                          message_id=reply_id, body="Review queued", reply_to=parent)
        self.assertEqual(reply["message_id"], reply_id)
        inbox = self.call("gm17", "receive_group_messages", group_id="ldw-ir")
        found = [item for item in inbox["messages"] if item["message_id"] == reply_id]
        self.assertEqual([(msg["sender"], msg["reply_to"]) for msg in found], [("ir02", parent)])

    def test_identity_cannot_be_overridden_by_tool_arguments(self):
        failure = self.clients["gm17"].handle({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "send_group_message", "arguments": {
                "group_id": "ldw-ir", "message_id": unique_id(), "body": "test",
                "sender": "ir02", "token": "do-not-accept"}},
        })
        self.assertTrue(failure["result"]["isError"])
        self.assertIn("INVALID_ARGUMENTS", failure["result"]["content"][0]["text"])

    def test_tool_directory_exposes_only_group_operations(self):
        r = self.clients["gm17"].handle({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
        names = [x["name"] for x in r["result"]["tools"]]
        self.assertEqual(names, ["list_groups", "receive_group_messages",
                                 "send_group_message", "ack_group_message"])
        self.assertNotIn("execute_shell", names)
        self.assertNotIn("wake_chat", names)

    def test_wrong_role_token_cannot_read(self):
        bogus = StdioMcpBridge(GroupTransportClient(
            "ir02", self.box.token_for_role("gm17"), self.server.server_port))
        bogus.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        reply = bogus.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "receive_group_messages",
                                        "arguments": {"group_id": "ldw-ir"}}})
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("UNAUTHORIZED", reply["result"]["content"][0]["text"])

    def test_unknown_mcp_tool_rejected_without_local_execution(self):
        result = self.clients["gm17"].handle({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": {"name": ["not-a-string"], "arguments": {}}})
        self.assertTrue(result["result"]["isError"])
        self.assertIn("UNKNOWN_TOOL", result["result"]["content"][0]["text"])

    def test_stdio_handshake_and_tool_listing_no_token_leak(self):
        raw = io.StringIO("\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": PROTOCOL}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ]) + "\n")
        sink = io.StringIO()
        bridge = StdioMcpBridge(GroupTransportClient(
            "gm17", self.box.token_for_role("gm17"), self.server.server_port))
        bridge.serve(raw, sink)
        messages = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["result"]["protocolVersion"], PROTOCOL)
        self.assertEqual(len(messages[1]["result"]["tools"]), 4)
        self.assertNotIn(self.box.token_for_role("gm17"), sink.getvalue())

    def test_invalid_json_returns_parse_error_without_secrets(self):
        raw = io.StringIO("bad-json\n")
        sink = io.StringIO()
        self.clients["gm17"].serve(raw, sink)
        msg = json.loads(sink.getvalue())
        self.assertEqual(msg["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
