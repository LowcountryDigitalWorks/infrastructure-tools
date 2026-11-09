"""message_board_ui_v0 — read-model projection for per-role inbox rows (SOURCE-ONLY).

Uses the accepted Gate B SiteHttpsMessageAdapter receive path; does not add a queue,
database, broker, or ChatGPT wake capability. UI truth: IN_MAILBOX with
MANUAL_OR_TOOL_POLL_REQUIRED.
"""
from __future__ import annotations

import math
import re
import time
from typing import Protocol

from relay import RelayError, canonical_id, role_name
from site_https_adapter import (
    DELIVERY_NOTICE,
    MESSAGE_VIEW_KEYS,
    SiteHttpsMessageAdapter,
    SiteTransportError,
)

UI_PROTOCOL = "ldw.chat-relay.message-board-ui.v0"
UI_REPRESENTATION = "IN_MAILBOX"
POLL_NOTICE = "MANUAL_OR_TOOL_POLL_REQUIRED"
MAX_PREVIEW_CHARS = 120
MAX_ROWS = 20

INBOX_ROW_KEYS = frozenset({
    "message_id",
    "sender_role",
    "recipient_role",
    "reply_to",
    "preview",
    "age_seconds",
    "ttl_seconds_remaining",
    "delivery_state",
    "ack_state",
    "correlation_id",
    "ui_representation",
    "poll_notice",
})

# Synthetic test-fixture guard only; not universal credential or customer-data redaction.
BEARER_LIKE = re.compile(r"(?i)(bearer\s+[0-9a-f]{16,}|[0-9a-f]{64}|sk-[A-Za-z0-9]{20,})")
FORBIDDEN_SURPRISE_KEYS = frozenset({
    "raw", "token", "bearer", "wake", "auto_woken", "chat_started", "ir_pass", "state",
})


class MessageBoardUiError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class InboxPollAdapter(Protocol):
    def invoke(self, tool: str, args: object) -> dict:
        ...


class MessageBoardUiV0:
    """Truthful per-role inbox projection over verified receive_messages results."""

    def __init__(self, role: str, adapter: SiteHttpsMessageAdapter, *, clock=time.time):
        try:
            self._role = role_name(role)
        except RelayError:
            raise ValueError("INVALID_BOARD_ROLE") from None
        if not isinstance(adapter, SiteHttpsMessageAdapter):
            raise ValueError("ADAPTER_REQUIRED")
        if adapter._role != self._role:
            raise ValueError("ROLE_ADAPTER_MISMATCH")
        self._adapter = adapter
        self._clock = clock

    @staticmethod
    def future_plugin_tools() -> list[dict]:
        """Exact future sidebar/panel tool contract (not deployed)."""
        return [
            {
                "name": "list_inbox_rows",
                "description": (
                    "Read bounded inbox rows for the construction-bound role only; "
                    "does not wake another ChatGPT chat"
                ),
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
                    },
                },
            },
            {
                "name": "inbox_status",
                "description": "Return inbox poll mode and delivery notice without message bodies",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                },
            },
        ]

    @staticmethod
    def _sanitize_preview(body: str) -> str:
        if not isinstance(body, str) or not body:
            raise MessageBoardUiError("INVALID_BODY")
        if BEARER_LIKE.search(body):
            raise MessageBoardUiError("SECRET_LIKE_BODY_REFUSED")
        compact = re.sub(r"\s+", " ", body.strip())
        if len(compact) > MAX_PREVIEW_CHARS:
            compact = compact[: MAX_PREVIEW_CHARS - 1] + "…"
        return compact

    @staticmethod
    def _finite_numeric(value: object) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            numeric = float(value)
        except (OverflowError, ValueError):
            return None
        if not math.isfinite(numeric):
            return None
        return numeric

    @staticmethod
    def _age_seconds(created_at: object, *, now: float) -> int | str:
        created = MessageBoardUiV0._finite_numeric(created_at)
        clock = MessageBoardUiV0._finite_numeric(now)
        if created is None or clock is None:
            return "UNKNOWN"
        try:
            delta = int(clock - created)
        except (OverflowError, ValueError):
            return "UNKNOWN"
        if delta < 0:
            return 0
        return delta

    @staticmethod
    def _ttl_seconds_remaining() -> str:
        # Relay expiry is monotonic server-side; accepted envelopes expose created_at only.
        return "UNKNOWN"

    def _project_row(self, envelope: dict, *, now: float) -> dict:
        if not isinstance(envelope, dict):
            raise MessageBoardUiError("INVALID_ENVELOPE")
        if set(envelope) - MESSAGE_VIEW_KEYS:
            raise MessageBoardUiError("UNEXPECTED_ENVELOPE_FIELD")
        if set(envelope) & FORBIDDEN_SURPRISE_KEYS:
            raise MessageBoardUiError("FORBIDDEN_ENVELOPE_FIELD")
        try:
            mid = canonical_id(envelope["message_id"])
            sender = role_name(envelope["sender"])
            recipient = role_name(envelope["recipient"])
        except RelayError:
            raise MessageBoardUiError("INVALID_ENVELOPE") from None
        if recipient != self._role:
            raise MessageBoardUiError("CROSS_ROLE_INBOX")
        if sender == self._role:
            raise MessageBoardUiError("SELF_SENDER_INBOX")
        reply_to = envelope.get("reply_to")
        if reply_to is not None:
            try:
                reply_to = canonical_id(reply_to)
            except RelayError:
                raise MessageBoardUiError("INVALID_REPLY_TO") from None
        preview = self._sanitize_preview(envelope["body"])
        age = self._age_seconds(envelope.get("created_at"), now=now)
        row = {
            "message_id": mid,
            "sender_role": sender,
            "recipient_role": recipient,
            "reply_to": reply_to,
            "preview": preview,
            "age_seconds": age,
            "ttl_seconds_remaining": self._ttl_seconds_remaining(),
            "delivery_state": "IN_MAILBOX",
            "ack_state": "UNACKED_IN_MAILBOX",
            "correlation_id": mid,
            "ui_representation": UI_REPRESENTATION,
            "poll_notice": POLL_NOTICE,
        }
        if set(row) != INBOX_ROW_KEYS:
            raise MessageBoardUiError("ROW_SHAPE_DRIFT")
        return row

    def inbox_status(self) -> dict:
        return {
            "protocol": UI_PROTOCOL,
            "role": self._role,
            "ui_representation": UI_REPRESENTATION,
            "poll_notice": POLL_NOTICE,
            "delivery_notice": DELIVERY_NOTICE,
            "wake_authority": "NONE",
        }

    def poll_rows(self, *, limit: int = 10) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ROWS:
            raise MessageBoardUiError("INVALID_LIMIT")
        try:
            received = self._adapter.invoke("receive_messages", {"limit": limit})
        except SiteTransportError as exc:
            raise MessageBoardUiError(exc.code) from None
        if received.get("state") != "MAILBOX_READ":
            raise MessageBoardUiError("UNEXPECTED_MAILBOX_STATE")
        now = self._clock()
        rows = []
        for item in received.get("messages", []):
            rows.append(self._project_row(item, now=now))
        return {
            "protocol": UI_PROTOCOL,
            "role": self._role,
            "ui_representation": UI_REPRESENTATION,
            "poll_notice": POLL_NOTICE,
            "delivery_notice": DELIVERY_NOTICE,
            "row_count": len(rows),
            "rows": rows,
        }
