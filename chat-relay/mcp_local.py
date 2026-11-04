"""Source-only LDW Chat Relay legacy-MCP stdio adapter (2025-11-25).

This is a local tool interface, NOT a native ChatGPT plugin installation,
conversation identity assertion, remote API, or autonomous ChatGPT wake.
One trusted local process identity is provisioned outside model-controlled tools.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import sys

from relay import canonical_id, role_name, RelayError

PROTOCOL = "2025-11-25"
MAX_FRAME = 16384
MAX_RESPONSE = 32768
GROUP_ID = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")
TOOLS = (
    ("list_groups", "List only groups of the trusted local role", {}, []),
    ("receive_group_messages", "Fetch group inbox; this does not wake a ChatGPT conversation",
     {"group_id": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 20}}, ["group_id"]),
    ("send_group_message", "Send one group message; mailbox receipt does not mean another chat started",
     {"group_id": {"type": "string"}, "message_id": {"type": "string"},
      "body": {"type": "string", "maxLength": 8192}, "reply_to": {"type": "string"}},
     ["group_id", "message_id", "body"]),
    ("ack_group_message", "Acknowledge only the calling role's group message",
     {"group_id": {"type": "string"}, "message_id": {"type": "string"}},
     ["group_id", "message_id"]),
)


class BridgeError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class GroupTransportClient:
    def __init__(self, role: str, token: str, port: int):
        try:
            self.role = role_name(role)
        except RelayError:
            raise ValueError("INVALID_LOCAL_ROLE") from None
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("INVALID_LOCAL_BEARER")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("INVALID_LOCAL_PORT")
        self._token = token
        self._port = port

    @staticmethod
    def _validate_tool(tool: str, args: object) -> None:
        definitions = {name: (props, required) for name, _, props, required in TOOLS}
        if not isinstance(tool, str) or tool not in definitions:
            raise BridgeError("UNKNOWN_TOOL")
        if not isinstance(args, dict):
            raise BridgeError("INVALID_ARGUMENTS")
        props, required = definitions[tool]
        if set(args) - set(props) or not set(required) <= set(args):
            raise BridgeError("INVALID_ARGUMENTS")
        if "group_id" in args and (not isinstance(args["group_id"], str)
                                  or not GROUP_ID.fullmatch(args["group_id"])):
            raise BridgeError("INVALID_GROUP_ID")
        if "message_id" in args:
            try:
                canonical_id(args["message_id"])
            except RelayError:
                raise BridgeError("INVALID_MESSAGE_ID") from None
        if "reply_to" in args:
            try:
                canonical_id(args["reply_to"])
            except RelayError:
                raise BridgeError("INVALID_REPLY_TO") from None
        if "body" in args and (
            not isinstance(args["body"], str) or not args["body"]
            or len(args["body"].encode("utf-8")) > 8192
        ):
            raise BridgeError("INVALID_BODY")
        if "limit" in args and (
            isinstance(args["limit"], bool) or not isinstance(args["limit"], int)
            or not 1 <= args["limit"] <= 20
        ):
            raise BridgeError("INVALID_LIMIT")

    def invoke(self, tool: str, args: object) -> dict:
        self._validate_tool(tool, args)
        if tool == "list_groups":
            method, path, body = "GET", "/v1/groups", None
        elif tool == "receive_group_messages":
            method = "GET"
            path = "/v1/groups/receive?group_id=" + args["group_id"]
            if "limit" in args:
                path += "&limit=" + str(args["limit"])
            body = None
        elif tool == "send_group_message":
            method, path = "POST", "/v1/groups/send"
            body = {
                "message_id": args["message_id"], "group_id": args["group_id"],
                "sender": self.role, "body": args["body"],
            }
            if "reply_to" in args:
                body["reply_to"] = args["reply_to"]
        else:
            method, path = "POST", "/v1/groups/ack"
            body = {"group_id": args["group_id"], "message_id": args["message_id"]}
        conn = http.client.HTTPConnection("127.0.0.1", self._port, timeout=3)
        try:
            payload = json.dumps(body, separators=(",", ":")).encode() if body else None
            conn.request(
                method, path, body=payload,
                headers={"X-LDW-Role": self.role,
                         "Authorization": "Bearer " + self._token,
                         "Content-Type": "application/json"},
            )
            response = conn.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise BridgeError("RESPONSE_TOO_LARGE")
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise BridgeError("INVALID_RELAY_RESULT")
            if response.status != 200:
                # Error payload codes only; never forward a token or traceback.
                code = obj.get("error", "RELAY_REFUSED")
                if not isinstance(code, str) or len(code) > 80:
                    code = "RELAY_REFUSED"
                raise BridgeError(code)
            return obj
        except (OSError, TimeoutError, json.JSONDecodeError, http.client.HTTPException):
            raise BridgeError("RELAY_UNAVAILABLE_OR_AMBIGUOUS") from None
        finally:
            conn.close()


class StdioMcpBridge:
    def __init__(self, client: GroupTransportClient):
        self._client = client
        self._ready = False

    @staticmethod
    def _response(request_id: object, result: object = None, error: dict | None = None) -> dict:
        obj = {"jsonrpc": "2.0", "id": request_id}
        if error is None:
            obj["result"] = result
        else:
            obj["error"] = error
        return obj

    def handle(self, request: object) -> dict | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return self._response(None, error={"code": -32600, "message": "INVALID_REQUEST"})
        method = request.get("method")
        if not isinstance(method, str):
            return self._response(request.get("id"), error={"code": -32600, "message": "INVALID_REQUEST"})
        if "id" not in request:  # notifications must not produce JSON-RPC responses
            if method == "notifications/initialized" and self._ready:
                return None
            return None
        rid = request["id"]
        if not isinstance(rid, (str, int)) or isinstance(rid, bool):
            return self._response(None, error={"code": -32600, "message": "INVALID_REQUEST"})
        if method == "initialize":
            params = request.get("params")
            if not isinstance(params, dict):
                return self._response(rid, error={"code": -32602, "message": "INVALID_PARAMS"})
            self._ready = True
            return self._response(rid, {
                "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "ldw-chat-relay-local-proof", "version": "0.1.0"},
                "instructions": "Source-only local messages; no autonomous native ChatGPT chat wake or IR guarantee.",
            })
        if not self._ready:
            return self._response(rid, error={"code": -32002, "message": "NOT_INITIALIZED"})
        if method == "ping":
            return self._response(rid, {})
        if method == "tools/list":
            return self._response(rid, {"tools": [
                {"name": name, "description": desc,
                 "inputSchema": {"type": "object", "properties": props,
                                 "required": required, "additionalProperties": False}}
                for name, desc, props, required in TOOLS
            ]})
        if method == "tools/call":
            params = request.get("params", {})
            if not isinstance(params, dict) or set(params) - {"name", "arguments"}:
                return self._response(rid, error={"code": -32602, "message": "INVALID_PARAMS"})
            name = params.get("name")
            try:
                result = self._client.invoke(name, params.get("arguments", {}))
                return self._response(rid, {"content": [
                    {"type": "text", "text": json.dumps(result, separators=(",", ":"))}
                ], "isError": False})
            except BridgeError as ex:
                return self._response(rid, {"content": [
                    {"type": "text", "text": json.dumps({"error": ex.code})}
                ], "isError": True})
        return self._response(rid, error={"code": -32601, "message": "METHOD_NOT_FOUND"})

    def serve(self, source, sink):
        # A strict bound on untrusted stdio frames. Never echo requests or tokens.
        while True:
            # readline with a hard character cap prevents an untrusted stdio
            # peer from causing unbounded buffering before newline/frame check.
            line = source.readline(MAX_FRAME + 1)
            if not line:
                break
            if not line.endswith("\n") or len(line.encode("utf-8")) > MAX_FRAME:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                result = self._response(None, error={"code": -32700, "message": "PARSE_ERROR"})
            else:
                result = self.handle(message)
            if result is not None:
                sink.write(json.dumps(result, separators=(",", ":")) + "\n")
                sink.flush()


def main() -> None:
    role = os.environ.get("LDW_CHAT_RELAY_MCP_ROLE", "")
    bearer = os.environ.get("LDW_CHAT_RELAY_MCP_BEARER", "")
    try:
        port = int(os.environ.get("LDW_CHAT_RELAY_PORT", "8767"))
        client = GroupTransportClient(role, bearer, port)
    except (TypeError, ValueError):
        raise SystemExit("LOCAL_MCP_PROVISIONING_REQUIRED") from None
    StdioMcpBridge(client).serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    main()
