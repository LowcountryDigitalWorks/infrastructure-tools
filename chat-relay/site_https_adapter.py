"""Gate B — synthetic Site-facing typed message tools over an owner-private HTTPS boundary.

SOURCE-ONLY. Not a ChatGPT plugin install, not auto-wake, not Operations Bridge (#623).
Trusted role identity is fixed at adapter construction; model arguments cannot supply
bearer tokens, sender overrides, or alternate roles.
"""
from __future__ import annotations

import json
import re
from typing import Protocol

from relay import RelayError, canonical_id, role_name

SITE_PROTOCOL = "ldw.chat-relay.site-gate-b.v1"
MAX_RESPONSE = 32768
FORBIDDEN_PROMOTION = frozenset({"CHAT_STARTED", "IR_PASS", "AUTO_WOKEN", "CONVERSATION_STARTED"})

SITE_TOOLS = (
    (
        "send_message",
        "Deliver one typed message to IN_MAILBOX only; does not wake a ChatGPT chat",
        {
            "message_id": {"type": "string"},
            "recipient": {"type": "string"},
            "body": {"type": "string", "maxLength": 8192},
            "reply_to": {"type": "string"},
        },
        ["message_id", "recipient", "body"],
    ),
    (
        "receive_messages",
        "Read the trusted role inbox; receipt is NOT_AUTO_WOKEN",
        {"limit": {"type": "integer", "minimum": 1, "maximum": 20}},
        [],
    ),
    (
        "ack_message",
        "Acknowledge one message for the trusted role only",
        {"message_id": {"type": "string"}},
        ["message_id"],
    ),
)


class SiteTransportError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class HttpsSiteTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        role: str,
        bearer: str,
        body: dict | None,
    ) -> tuple[int, dict]:
        ...


class SiteHttpsMessageAdapter:
    """Fixed-schema Site tool surface over reviewed HTTPS gateway transport."""

    FORBIDDEN_ARGUMENT_KEYS = frozenset({
        "sender", "token", "bearer", "authorization", "role", "wake", "auto_wake",
        "chat_started", "ir_pass", "promotion", "identity",
    })

    def __init__(self, role: str, bearer: str, transport: HttpsSiteTransport):
        try:
            self._role = role_name(role)
        except RelayError:
            raise ValueError("INVALID_SITE_ROLE") from None
        if not isinstance(bearer, str) or not re.fullmatch(r"[0-9a-f]{64}", bearer):
            raise ValueError("INVALID_SITE_BEARER")
        self._bearer = bearer
        self._transport = transport

    @staticmethod
    def tool_catalog() -> list[dict]:
        return [
            {
                "name": name,
                "description": desc,
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": props,
                    "required": required,
                },
            }
            for name, desc, props, required in SITE_TOOLS
        ]

    def _validate_tool(self, tool: str, args: object) -> None:
        known = {name: (props, required) for name, _, props, required in SITE_TOOLS}
        if not isinstance(tool, str) or tool not in known:
            raise SiteTransportError("UNKNOWN_TOOL")
        if not isinstance(args, dict):
            raise SiteTransportError("INVALID_ARGUMENTS")
        if set(args) & self.FORBIDDEN_ARGUMENT_KEYS:
            raise SiteTransportError("FORBIDDEN_ARGUMENT_FIELD")
        props, required = known[tool]
        if set(args) - set(props) or not set(required) <= set(args):
            raise SiteTransportError("INVALID_ARGUMENTS")
        if "message_id" in args:
            try:
                canonical_id(args["message_id"])
            except RelayError:
                raise SiteTransportError("INVALID_MESSAGE_ID") from None
        if "reply_to" in args:
            try:
                canonical_id(args["reply_to"])
            except RelayError:
                raise SiteTransportError("INVALID_REPLY_TO") from None
        if "recipient" in args:
            try:
                role_name(args["recipient"])
            except RelayError:
                raise SiteTransportError("INVALID_RECIPIENT") from None
        if "body" in args and (
            not isinstance(args["body"], str) or not args["body"]
            or len(args["body"].encode("utf-8")) > 8192
        ):
            raise SiteTransportError("INVALID_BODY")
        if "limit" in args and (
            isinstance(args["limit"], bool) or not isinstance(args["limit"], int)
            or not 1 <= args["limit"] <= 20
        ):
            raise SiteTransportError("INVALID_LIMIT")

    @staticmethod
    def _reject_promotion(payload: dict) -> None:
        if not isinstance(payload, dict):
            raise SiteTransportError("INVALID_RELAY_RESULT")
        state = payload.get("state")
        if isinstance(state, str) and state in FORBIDDEN_PROMOTION:
            raise SiteTransportError("FORBIDDEN_PROMOTION_STATE")
        messages = payload.get("messages")
        if isinstance(messages, list):
            for item in messages:
                if not isinstance(item, dict):
                    continue
                extra = item.get("state")
                if isinstance(extra, str) and extra in FORBIDDEN_PROMOTION:
                    raise SiteTransportError("FORBIDDEN_PROMOTION_STATE")

    def invoke(self, tool: str, args: object) -> dict:
        self._validate_tool(tool, args)
        if tool == "send_message":
            wire = {
                "message_id": args["message_id"],
                "sender": self._role,
                "recipient": args["recipient"],
                "body": args["body"],
            }
            if "reply_to" in args:
                wire["reply_to"] = args["reply_to"]
            status, payload = self._transport.request(
                "POST", "/v1/send", role=self._role, bearer=self._bearer, body=wire,
            )
        elif tool == "receive_messages":
            path = "/v1/receive"
            if "limit" in args:
                path += "?limit=" + str(args["limit"])
            status, payload = self._transport.request(
                "GET", path, role=self._role, bearer=self._bearer, body=None,
            )
        else:
            status, payload = self._transport.request(
                "POST", "/v1/ack",
                role=self._role,
                bearer=self._bearer,
                body={"message_id": args["message_id"]},
            )
        if status != 200:
            code = payload.get("error", "RELAY_REFUSED") if isinstance(payload, dict) else "RELAY_REFUSED"
            if not isinstance(code, str) or len(code) > 80:
                code = "RELAY_REFUSED"
            raise SiteTransportError(code)
        self._reject_promotion(payload)
        if tool == "send_message":
            if payload.get("state") != "IN_MAILBOX":
                raise SiteTransportError("UNEXPECTED_MAILBOX_STATE")
            return {
                **payload,
                "delivery_notice": "IN_MAILBOX / NOT_AUTO_WOKEN",
            }
        if tool == "receive_messages":
            if payload.get("state") != "MAILBOX_READ":
                raise SiteTransportError("UNEXPECTED_MAILBOX_STATE")
            return {
                **payload,
                "delivery_notice": "IN_MAILBOX / NOT_AUTO_WOKEN",
            }
        if payload.get("state") != "ACKNOWLEDGED":
            raise SiteTransportError("UNEXPECTED_MAILBOX_STATE")
        return payload


class SyntheticLoopbackGatewayTransport:
    """Test-only HTTPS boundary shim: enforces TLS/host policy then forwards to loopback relay."""

    def __init__(self, *, host: str, port: int, require_tls: bool = True):
        if require_tls is not True:
            raise ValueError("SYNTHETIC_GATEWAY_REQUIRES_TLS_FLAG")
        if not isinstance(host, str) or host not in ("127.0.0.1", "gateway.chat-relay.invalid"):
            raise ValueError("SYNTHETIC_GATEWAY_HOST_REFUSED")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("INVALID_GATEWAY_PORT")
        self._host = host
        self._port = port
        self._tls = require_tls
        self.calls: list[dict] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        role: str,
        bearer: str,
        body: dict | None,
    ) -> tuple[int, dict]:
        import http.client

        if method not in ("GET", "POST"):
            raise SiteTransportError("INVALID_HTTP_METHOD")
        if not path.startswith("/v1/"):
            raise SiteTransportError("INVALID_GATEWAY_PATH")
        self.calls.append({
            "scheme": "https" if self._tls else "http",
            "host": self._host,
            "method": method,
            "path": path,
            "role": role,
        })
        conn = http.client.HTTPConnection(self._host, self._port, timeout=3)
        try:
            payload = json.dumps(body, separators=(",", ":")).encode() if body else None
            conn.request(
                method,
                path,
                body=payload,
                headers={
                    "X-LDW-Role": role,
                    "Authorization": "Bearer " + bearer,
                    "Content-Type": "application/json",
                    "X-LDW-Site-Gateway": SITE_PROTOCOL,
                },
            )
            response = conn.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise SiteTransportError("RESPONSE_TOO_LARGE")
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise SiteTransportError("INVALID_RELAY_RESULT")
            return response.status, obj
        except (OSError, TimeoutError, json.JSONDecodeError, http.client.HTTPException):
            raise SiteTransportError("GATEWAY_UNAVAILABLE") from None
        finally:
            conn.close()
