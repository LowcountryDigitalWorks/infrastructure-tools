"""LDW group message extension to the standalone local chat relay.

A transport mailbox is NOT a native ChatGPT chat, model invocation or wake API.
Membership is provisioned in trusted local startup config only.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from relay import (Handler, LocalRelay, Mailbox, RelayError, canonical_id, role_name,
                   MAX_BODY, MAX_MESSAGES, TTL_SECONDS)

GROUP = re.compile(r"^[a-z][a-z0-9_-]{1,47}$")
MAX_GROUPS = 16
MAX_MEMBERS = 12
MAX_PER_SENDER = 16
MAX_PER_GROUP = 32


@dataclass
class GroupMessage:
    message_id: str
    group_id: str
    sender: str
    body: str
    reply_to: str | None
    created_at: float
    expires_at: float
    acknowledged_by: set[str] = field(default_factory=set)

    def view(self) -> dict:
        return {
            "message_id": self.message_id, "group_id": self.group_id,
            "sender": self.sender, "body": self.body,
            "reply_to": self.reply_to, "created_at": self.created_at,
        }


class GroupMailbox(Mailbox):
    def __init__(self, master_secret: bytes, groups: dict, clock=time.time):
        validated_groups = self._validate_groups(groups)
        registered_roles = tuple(sorted({role for members in validated_groups.values() for role in members}))
        super().__init__(master_secret, clock=clock, allowed_roles=registered_roles)
        self._groups = validated_groups
        self._group_messages: dict[str, GroupMessage] = {}

    @staticmethod
    def _validate_groups(groups: dict) -> dict[str, tuple[str, ...]]:
        if not isinstance(groups, dict) or len(groups) > MAX_GROUPS:
            raise ValueError("INVALID_GROUP_CONFIG")
        validated = {}
        for group_id, members in groups.items():
            if not isinstance(group_id, str) or not GROUP.fullmatch(group_id):
                raise ValueError("INVALID_GROUP_ID")
            if not isinstance(members, (tuple, list)) or not 2 <= len(members) <= MAX_MEMBERS:
                raise ValueError("INVALID_GROUP_MEMBERS")
            if any(not isinstance(m, str) for m in members):
                raise ValueError("INVALID_GROUP_MEMBERS")
            try:
                for member in members:
                    role_name(member)
            except RelayError:
                raise ValueError("INVALID_GROUP_MEMBERS") from None
            if len(set(members)) != len(members):
                raise ValueError("DUPLICATE_GROUP_MEMBER")
            validated[group_id] = tuple(members)
        return validated

    def _group_members(self, actor: str, group_id: object) -> tuple[str, ...]:
        if not isinstance(group_id, str) or not GROUP.fullmatch(group_id):
            raise RelayError(400, "INVALID_GROUP_ID")
        members = self._groups.get(group_id)
        if members is None:
            raise RelayError(404, "GROUP_NOT_FOUND")
        if actor not in members:
            raise RelayError(403, "NOT_GROUP_MEMBER")
        return members

    def _gc(self) -> None:
        super()._gc()
        now = self._clock()
        for key, message in list(self._group_messages.items()):
            if message.expires_at <= now:
                del self._group_messages[key]

    def send(self, actor: str, data: dict) -> dict:
        # One UUID namespace across direct and group envelopes.
        with self._lock:
            self._gc()
            if isinstance(data, dict) and "message_id" in data:
                message_id = canonical_id(data["message_id"])
                if message_id in self._group_messages:
                    raise RelayError(409, "MESSAGE_ID_CONFLICT")
                if message_id not in self._messages:
                    self._check_sender_quota(actor)
                    if len(self._messages) + len(self._group_messages) >= MAX_MESSAGES:
                        raise RelayError(429, "MAILBOX_FULL")
            return super().send(actor, data)

    def _check_sender_quota(self, actor: str) -> None:
        # A sender's DMs and group messages share ONE fixed allowance. Retained
        # ACK tombstones still count, preserving single-use UUID semantics.
        sender_count = sum(msg.sender == actor for msg in self._messages.values())
        sender_count += sum(msg.sender == actor for msg in self._group_messages.values())
        if sender_count >= MAX_PER_SENDER:
            raise RelayError(429, "SENDER_QUOTA_EXCEEDED")

    def groups_for(self, actor: str) -> dict:
        with self._lock:
            return {
                "state": "GROUP_DIRECTORY_READ",
                "groups": [
                    {"group_id": group_id, "members": list(members)}
                    for group_id, members in sorted(self._groups.items())
                    if actor in members
                ],
            }

    def group_send(self, actor: str, data: dict) -> dict:
        if not isinstance(data, dict) or set(data) - {
            "message_id", "group_id", "sender", "body", "reply_to"
        } or not {"message_id", "group_id", "sender", "body"} <= set(data):
            raise RelayError(400, "INVALID_ENVELOPE")
        message_id = canonical_id(data["message_id"])
        group_id = data["group_id"]
        members = self._group_members(actor, group_id)
        if role_name(data["sender"]) != actor:
            raise RelayError(403, "ROLE_MISMATCH")
        body = data["body"]
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_BODY:
            raise RelayError(400, "INVALID_BODY")
        reply_to = data.get("reply_to")
        if reply_to is not None:
            reply_to = canonical_id(reply_to)
        with self._lock:
            self._gc()
            previous = self._group_messages.get(message_id)
            if previous:
                if (previous.group_id, previous.sender, previous.body, previous.reply_to) != (
                    group_id, actor, body, reply_to
                ):
                    raise RelayError(409, "MESSAGE_ID_CONFLICT")
                return {
                    "message_id": message_id, "group_id": group_id,
                    "state": "GROUP_IN_MAILBOX", "duplicate": True,
                    "recipient_count": len(members) - 1,
                }
            if message_id in self._messages:
                raise RelayError(409, "MESSAGE_ID_CONFLICT")
            if reply_to is not None:
                parent = self._group_messages.get(reply_to)
                if parent is None or parent.group_id != group_id:
                    raise RelayError(400, "INVALID_GROUP_REPLY")
            self._check_sender_quota(actor)
            if sum(msg.group_id == group_id for msg in self._group_messages.values()) >= MAX_PER_GROUP:
                raise RelayError(429, "GROUP_QUOTA_EXCEEDED")
            if len(self._messages) + len(self._group_messages) >= MAX_MESSAGES:
                raise RelayError(429, "MAILBOX_FULL")
            now = self._clock()
            self._group_messages[message_id] = GroupMessage(
                message_id, group_id, actor, body, reply_to, now, now + TTL_SECONDS
            )
            return {
                "message_id": message_id, "group_id": group_id,
                "state": "GROUP_IN_MAILBOX", "duplicate": False,
                "recipient_count": len(members) - 1,
            }

    def group_receive(self, actor: str, group_id: object, limit: int = 20) -> dict:
        self._group_members(actor, group_id)
        if not isinstance(limit, int) or not 1 <= limit <= 20:
            raise RelayError(400, "INVALID_LIMIT")
        with self._lock:
            self._gc()
            pending = [
                msg for msg in self._group_messages.values()
                if msg.group_id == group_id and msg.sender != actor
                and actor not in msg.acknowledged_by
            ]
            pending.sort(key=lambda msg: (msg.created_at, msg.message_id))
            return {
                "state": "GROUP_MAILBOX_READ", "group_id": group_id,
                "messages": [msg.view() for msg in pending[:limit]],
            }

    def group_acknowledge(self, actor: str, group_id: object, message_id: object) -> dict:
        self._group_members(actor, group_id)
        mid = canonical_id(message_id)
        with self._lock:
            self._gc()
            message = self._group_messages.get(mid)
            if message is None or message.group_id != group_id:
                raise RelayError(404, "NOT_FOUND")
            if message.sender == actor:
                raise RelayError(403, "ROLE_MISMATCH")
            message.acknowledged_by.add(actor)
            return {"state": "ACKNOWLEDGED", "group_id": group_id, "message_id": mid}


class GroupHandler(Handler):
    def do_POST(self) -> None:
        route = urlsplit(self.path)
        if route.path not in ("/v1/groups/send", "/v1/groups/ack"):
            return super().do_POST()
        try:
            if route.query:
                raise RelayError(400, "INVALID_QUERY")
            actor = self._actor()
            data = self._body()
            if route.path == "/v1/groups/send":
                result = self.server.mailbox.group_send(actor, data)
            else:
                if set(data) != {"group_id", "message_id"}:
                    raise RelayError(400, "INVALID_ENVELOPE")
                result = self.server.mailbox.group_acknowledge(
                    actor, data["group_id"], data["message_id"])
            self._json(200, result)
        except RelayError as exc:
            self._json(exc.status, {"error": exc.code})

    def do_GET(self) -> None:
        route = urlsplit(self.path)
        if route.path not in ("/v1/groups", "/v1/groups/receive"):
            return super().do_GET()
        try:
            actor = self._actor()
            if route.path == "/v1/groups":
                if route.query:
                    raise RelayError(400, "INVALID_QUERY")
                result = self.server.mailbox.groups_for(actor)
            else:
                params = parse_qs(route.query, keep_blank_values=True)
                if set(params) - {"group_id", "limit"} or any(len(v) != 1 for v in params.values()):
                    raise RelayError(400, "INVALID_QUERY")
                if "group_id" not in params:
                    raise RelayError(400, "INVALID_QUERY")
                try:
                    limit = int(params.get("limit", ["20"])[0])
                except ValueError:
                    raise RelayError(400, "INVALID_LIMIT") from None
                result = self.server.mailbox.group_receive(actor, params["group_id"][0], limit)
            self._json(200, result)
        except RelayError as exc:
            self._json(exc.status, {"error": exc.code})


class GroupLocalRelay(LocalRelay):
    """Group routes share the parent relay's bounded unauthenticated HTTP admission."""

    def __init__(self, address: tuple[str, int], mailbox: GroupMailbox):
        super().__init__(address, mailbox)
        # No serving occurs until after constructor returns, so the handler
        # swap inherits the protected LocalRelay socket/thread lifecycle.
        self.RequestHandlerClass = GroupHandler


def main() -> None:
    key = os.environ.get("LDW_CHAT_RELAY_SECRET", "")
    if len(key.encode("utf-8")) < 32:
        raise SystemExit("LDW_CHAT_RELAY_SECRET must be securely supplied (32+ bytes)")
    raw = os.environ.get("LDW_CHAT_RELAY_ROOMS", "{}")
    if len(raw.encode("utf-8")) > 4096:
        raise SystemExit("INVALID_GROUP_CONFIG")
    try:
        groups = json.loads(raw)
        mailbox = GroupMailbox(key.encode("utf-8"), groups=groups)
    except (ValueError, TypeError):
        raise SystemExit("INVALID_GROUP_CONFIG") from None
    port = int(os.environ.get("LDW_CHAT_RELAY_PORT", "8767"))
    with GroupLocalRelay(("127.0.0.1", port), mailbox) as srv:
        print(f"LDW_GROUP_RELAY_LOCAL_READY port={srv.server_port} scope=loopback-only", flush=True)
        srv.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
