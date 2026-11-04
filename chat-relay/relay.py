"""LDW Chat Relay: local, in-memory, role-authenticated message transport.

Not a ChatGPT UI integration or a conversation wake API. No runtime dependency on
GitHub, ChatGPT Work, or an OpenAI API key. Production deployment is NOT implied.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from threading import BoundedSemaphore, RLock, Timer
from urllib.parse import parse_qs, urlsplit

ROLE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
MAX_BODY = 8192
MAX_ROLES = 16
MAX_CLIENT_THREADS = 8
MAX_CONNECTION_SECONDS = 4.0
MAX_MESSAGES = 128
TTL_SECONDS = 900


class RelayError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def canonical_id(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise RelayError(400, "INVALID_MESSAGE_ID") from None
    if str(parsed) != value:
        raise RelayError(400, "INVALID_MESSAGE_ID")
    return str(parsed)


def role_name(value: object) -> str:
    if not isinstance(value, str) or not ROLE.fullmatch(value):
        raise RelayError(400, "INVALID_ROLE")
    return value


@dataclass
class Message:
    message_id: str
    sender: str
    recipient: str
    body: str
    reply_to: str | None
    created_at: float
    expires_at: float
    acknowledged: bool = False

    def view(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "body": self.body,
            "reply_to": self.reply_to,
            "created_at": self.created_at,
        }


class Mailbox:
    def __init__(self, master_secret: bytes, clock=time.time, allowed_roles: tuple[str, ...] = ()):
        if len(master_secret) < 32:
            raise ValueError("relay master secret must be at least 32 bytes")
        if not isinstance(allowed_roles, (list, tuple)) or not 2 <= len(allowed_roles) <= MAX_ROLES:
            raise ValueError("INVALID_ROLE_ROSTER")
        try:
            self._roles = frozenset(role_name(x) for x in allowed_roles)
        except RelayError:
            raise ValueError("INVALID_ROLE_ROSTER") from None
        if len(self._roles) != len(allowed_roles):
            raise ValueError("INVALID_ROLE_ROSTER")
        self._secret = master_secret
        self._clock = clock
        self._messages: dict[str, Message] = {}
        self._lock = RLock()

    def token_for_role(self, role: str) -> str:
        """For trusted local provisioning only. Never expose as an HTTP endpoint."""
        role_name(role)
        if role not in self._roles:
            raise RelayError(403, "ROLE_NOT_REGISTERED")
        return hmac.new(self._secret, b"ldw-relay-v1:" + role.encode(), hashlib.sha256).hexdigest()

    def authenticate(self, role: str, provided: str) -> None:
        try:
            role_name(role)
        except RelayError:
            raise RelayError(401, "UNAUTHORIZED") from None
        if role not in self._roles:
            raise RelayError(401, "UNAUTHORIZED")
        if not isinstance(provided, str) or not hmac.compare_digest(
            self.token_for_role(role), provided
        ):
            raise RelayError(401, "UNAUTHORIZED")

    def _gc(self) -> None:
        now = self._clock()
        for k, msg in list(self._messages.items()):
            if msg.expires_at <= now:
                del self._messages[k]

    def send(self, actor: str, data: dict) -> dict:
        if not isinstance(data, dict) or set(data) - {
            "message_id", "sender", "recipient", "body", "reply_to"
        }:
            raise RelayError(400, "INVALID_ENVELOPE")
        if set(data) < {"message_id", "sender", "recipient", "body"}:
            raise RelayError(400, "INVALID_ENVELOPE")
        msg_id = canonical_id(data["message_id"])
        sender = role_name(data["sender"])
        recipient = role_name(data["recipient"])
        if sender != actor or sender == recipient:
            raise RelayError(403, "ROLE_MISMATCH")
        if recipient not in self._roles:
            raise RelayError(403, "ROLE_NOT_REGISTERED")
        body = data["body"]
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_BODY:
            raise RelayError(400, "INVALID_BODY")
        reply_to = data.get("reply_to")
        if reply_to is not None:
            reply_to = canonical_id(reply_to)
        with self._lock:
            self._gc()
            previous = self._messages.get(msg_id)
            if previous:
                if (previous.sender, previous.recipient, previous.body, previous.reply_to) != (
                    sender, recipient, body, reply_to
                ):
                    raise RelayError(409, "MESSAGE_ID_CONFLICT")
                return {"message_id": msg_id, "state": "IN_MAILBOX", "duplicate": True}
            if reply_to is not None:
                parent = self._messages.get(reply_to)
                if parent is None or parent.sender != recipient or parent.recipient != actor:
                    raise RelayError(400, "INVALID_REPLY_TO")
            if len(self._messages) >= MAX_MESSAGES:
                raise RelayError(429, "MAILBOX_FULL")
            now = self._clock()
            self._messages[msg_id] = Message(msg_id, sender, recipient, body, reply_to, now, now + TTL_SECONDS)
            return {"message_id": msg_id, "state": "IN_MAILBOX", "duplicate": False}

    def receive(self, actor: str, limit: int = 20) -> dict:
        if not isinstance(limit, int) or not 1 <= limit <= 20:
            raise RelayError(400, "INVALID_LIMIT")
        with self._lock:
            self._gc()
            pending = [x for x in self._messages.values() if x.recipient == actor and not x.acknowledged]
            pending.sort(key=lambda x: (x.created_at, x.message_id))
            return {"messages": [x.view() for x in pending[:limit]], "state": "MAILBOX_READ"}

    def acknowledge(self, actor: str, message_id: object) -> dict:
        mid = canonical_id(message_id)
        with self._lock:
            self._gc()
            m = self._messages.get(mid)
            if m is None:
                raise RelayError(404, "NOT_FOUND")
            if m.recipient != actor:
                raise RelayError(403, "ROLE_MISMATCH")
            m.acknowledged = True
            return {"message_id": mid, "state": "ACKNOWLEDGED"}


class LocalRelay(ThreadingHTTPServer):
    allow_reuse_address = True
    request_queue_size = MAX_CLIENT_THREADS

    def __init__(self, address: tuple[str, int], mailbox: Mailbox):
        if address[0] != "127.0.0.1":
            raise ValueError("proof relay must be loopback-only")
        self.mailbox = mailbox
        self._slots = BoundedSemaphore(MAX_CLIENT_THREADS)
        super().__init__(address, Handler)

    def get_request(self):
        request, addr = super().get_request()
        request.settimeout(2.0)  # idle-read deadline, separate from absolute deadline
        return request, addr

    def process_request(self, request, client_address):
        # Refuse excess unauthenticated clients without spawning unbounded threads.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    @staticmethod
    def _expire_connection(request):
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            request.close()
        except OSError:
            pass

    def process_request_thread(self, request, client_address):
        # Absolute wall-clock cap even for clients dripping bytes indefinitely.
        deadline = Timer(MAX_CONNECTION_SECONDS, self._expire_connection, args=(request,))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    server: LocalRelay

    def log_message(self, fmt: str, *args: object) -> None:
        # No request body, token, IP or path logging. The proof stays quiet.
        return

    def _json(self, status: int, payload: dict) -> None:
        wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(wire)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(wire)

    def _actor(self) -> str:
        role = role_name(self.headers.get("X-LDW-Role"))
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise RelayError(401, "UNAUTHORIZED")
        self.server.mailbox.authenticate(role, auth[7:])
        return role

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise RelayError(411, "LENGTH_REQUIRED") from None
        if not 0 < length <= 16384:
            raise RelayError(413, "REQUEST_TOO_LARGE")
        try:
            data = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RelayError(400, "INVALID_JSON") from None
        if not isinstance(data, dict):
            raise RelayError(400, "INVALID_ENVELOPE")
        return data

    def do_POST(self) -> None:
        try:
            actor = self._actor()
            route = urlsplit(self.path).path
            data = self._body()
            if route == "/v1/send":
                self._json(200, self.server.mailbox.send(actor, data))
            elif route == "/v1/ack":
                if set(data) != {"message_id"}:
                    raise RelayError(400, "INVALID_ENVELOPE")
                self._json(200, self.server.mailbox.acknowledge(actor, data["message_id"]))
            else:
                raise RelayError(404, "NOT_FOUND")
        except RelayError as e:
            self._json(e.status, {"error": e.code})

    def do_GET(self) -> None:
        try:
            route = urlsplit(self.path)
            if route.path == "/health":
                self._json(200, {"status": "UP", "scope": "LOCAL_ONLY"})
                return
            actor = self._actor()
            if route.path != "/v1/receive":
                raise RelayError(404, "NOT_FOUND")
            p = parse_qs(route.query)
            if set(p) - {"limit"}:
                raise RelayError(400, "INVALID_QUERY")
            try:
                limit = int(p.get("limit", ["20"])[0])
            except ValueError:
                raise RelayError(400, "INVALID_LIMIT") from None
            self._json(200, self.server.mailbox.receive(actor, limit))
        except RelayError as e:
            self._json(e.status, {"error": e.code})


def main() -> None:
    key = os.environ.get("LDW_CHAT_RELAY_SECRET", "")
    if len(key.encode("utf-8")) < 32:
        raise SystemExit("LDW_CHAT_RELAY_SECRET must be supplied securely (32+ bytes)")
    try:
        roles_raw = os.environ.get("LDW_CHAT_RELAY_ROLES", "")
        if len(roles_raw) > 1024:
            raise ValueError("INVALID_ROLE_ROSTER")
        roles = json.loads(roles_raw)
        mailbox = Mailbox(key.encode("utf-8"), allowed_roles=roles)
    except (ValueError, TypeError):
        raise SystemExit("LDW_CHAT_RELAY_ROLES must be a trusted JSON list of 2–16 role names") from None
    port = int(os.environ.get("LDW_CHAT_RELAY_PORT", "8767"))
    with LocalRelay(("127.0.0.1", port), mailbox) as srv:
        print(f"LDW_CHAT_RELAY_LOCAL_READY port={srv.server_port} scope=loopback-only", flush=True)
        srv.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    main()
