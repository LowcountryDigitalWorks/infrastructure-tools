"""Synthetic LDW Commander session authority. NO shell, privilege, file or network access.

Proof of host/operator-bound grants and replay/expiry/revocation invariants only.
NOT a deployed remote-admin agent. Model messages are not session approval.
"""
from __future__ import annotations

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import json
import time
import uuid
from dataclasses import dataclass
from threading import RLock
from owner_decision import OwnerDecisionRefused, verify_decision

PRIVILEGES = ("OBSERVE", "MAINTAIN", "FULL_ADMIN")
MAX_TTL_SECONDS = 90
MAX_COMMANDS = 3
ISSUER_ID = "ldw-commander-session-proof-v0"


class SessionRefused(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(data: str) -> bytes:
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        raise SessionRefused("INVALID_GRANT") from None


def uid(value: str) -> str:
    try:
        value = str(value)
        if str(uuid.UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, TypeError, AttributeError):
        raise SessionRefused("INVALID_ID") from None


@dataclass(frozen=True)
class OwnerPolicy:
    policy_id: str
    operator: str
    host: str
    max_privilege: str
    max_ttl_seconds: int


class SessionIssuer:
    """Trusted local issuer only; not an HTTP endpoint or model-callable action."""
    def __init__(self, private_key: Ed25519PrivateKey, policy: OwnerPolicy, clock=time.time,
                 epoch: int = 1, owner_public_key: Ed25519PublicKey | None = None):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("ISSUER_PRIVATE_KEY_REQUIRED")
        if policy.max_privilege not in PRIVILEGES:
            raise ValueError("INVALID_POLICY_PRIVILEGE")
        if not 1 <= policy.max_ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("INVALID_POLICY_TTL")
        if not isinstance(epoch, int) or epoch < 1:
            raise ValueError("INVALID_EPOCH")
        self._private_key = private_key
        self._owner_public_key = owner_public_key
        self._used_decision_ids: set[str] = set()
        self._policy = policy
        self._clock = clock
        self._epoch = epoch

    def issue(self, operator: str, host: str, privilege: str, ttl_seconds: int,
              owner_decision: str | None = None) -> str:
        p = self._policy
        if operator != p.operator or host != p.host or privilege not in PRIVILEGES:
            raise SessionRefused("POLICY_REFUSED")
        if PRIVILEGES.index(privilege) > PRIVILEGES.index(p.max_privilege):
            raise SessionRefused("POLICY_REFUSED")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= p.max_ttl_seconds:
            raise SessionRefused("POLICY_REFUSED")
        issued = int(self._clock())
        if privilege == "FULL_ADMIN":
            try:
                decision = verify_decision(
                    owner_decision, self._owner_public_key,
                    policy=p.policy_id, host=host, operator=operator,
                    epoch=self._epoch, requested_ttl=ttl_seconds, now=issued,
                )
            except OwnerDecisionRefused:
                raise SessionRefused("OWNER_AUTH_NOT_PROVEN") from None
            if decision["decision_id"] in self._used_decision_ids:
                raise SessionRefused("OWNER_DECISION_REPLAY")
        elif owner_decision is not None:
            raise SessionRefused("UNEXPECTED_OWNER_DECISION")
        grant = {
            "issuer": ISSUER_ID, "policy": p.policy_id, "operator": operator,
            "host": host, "privilege": privilege, "session_id": str(uuid.uuid4()),
            "issued": issued, "expires": issued + ttl_seconds,
            "epoch": self._epoch, "max_commands": MAX_COMMANDS,
            "owner_decision": owner_decision,
        }
        payload = json.dumps(grant, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = self._private_key.sign(payload)
        token = b64(payload) + "." + b64(signature)
        if privilege == "FULL_ADMIN":
            self._used_decision_ids.add(decision["decision_id"])
        return token


class SyntheticAgent:
    """Disconnected proof. Operations intentionally cannot execute OS commands."""
    def __init__(self, public_key: Ed25519PublicKey, policy: OwnerPolicy, host: str,
                 clock=time.time, epoch: int = 1,
                 owner_public_key: Ed25519PublicKey | None = None):
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("AGENT_PUBLIC_KEY_REQUIRED")
        # The agent never holds the issuer private signing key.
        self._public_key = public_key
        self._owner_public_key = owner_public_key
        self._decision_sessions: dict[str, str] = {}
        self._policy = policy
        self._host = host
        self._clock = clock
        self._epoch = epoch
        self._active: dict[str, dict] = {}
        self._revoked: set[str] = set()
        self._lock = RLock()

    def _decode(self, token: str) -> dict:
        try:
            if not isinstance(token, str) or len(token) > 4096:
                raise ValueError()
            raw, sig = token.split(".")
            payload = unb64(raw)
            provided = unb64(sig)
        except (ValueError, TypeError):
            raise SessionRefused("INVALID_GRANT") from None
        try:
            self._public_key.verify(provided, payload)
        except InvalidSignature:
            raise SessionRefused("INVALID_SIGNATURE") from None
        try:
            result = json.loads(payload)
            if not isinstance(result, dict) or set(result) != {
                "issuer", "policy", "operator", "host", "privilege",
                "session_id", "issued", "expires", "epoch", "max_commands",
                "owner_decision"
            }:
                raise ValueError()
        except (ValueError, TypeError):
            raise SessionRefused("INVALID_GRANT") from None
        return result

    def _check(self, g: dict, operator: str) -> str:
        p = self._policy
        if g["issuer"] != ISSUER_ID or g["policy"] != p.policy_id:
            raise SessionRefused("WRONG_ISSUER_POLICY")
        if g["host"] != self._host or g["host"] != p.host:
            raise SessionRefused("WRONG_HOST")
        if operator != p.operator or g["operator"] != operator:
            raise SessionRefused("WRONG_OPERATOR")
        if g["privilege"] not in PRIVILEGES or PRIVILEGES.index(g["privilege"]) > PRIVILEGES.index(p.max_privilege):
            raise SessionRefused("POLICY_REFUSED")
        if not isinstance(g["epoch"], int) or g["epoch"] != self._epoch:
            raise SessionRefused("REVOKED_EPOCH")
        if not all(isinstance(g[k], int) for k in ("issued", "expires", "max_commands")):
            raise SessionRefused("INVALID_GRANT")
        if g["max_commands"] != MAX_COMMANDS or not 0 < g["expires"] - g["issued"] <= p.max_ttl_seconds:
            raise SessionRefused("POLICY_REFUSED")
        now = int(self._clock())
        if g["issued"] > now or now >= g["expires"]:
            raise SessionRefused("EXPIRED_OR_NOT_YET_VALID")
        sid = uid(g["session_id"])
        if g["privilege"] == "FULL_ADMIN":
            try:
                decision = verify_decision(
                    g["owner_decision"], self._owner_public_key,
                    policy=p.policy_id, host=self._host, operator=operator,
                    epoch=self._epoch, requested_ttl=g["expires"] - g["issued"],
                    now=now,
                )
            except OwnerDecisionRefused:
                raise SessionRefused("OWNER_AUTH_NOT_PROVEN") from None
            # Even a signed *issuer* grant cannot widen an independently signed
            # owner decision. No model-provided consent or role is accepted.
            if decision["issued"] > g["issued"]:
                raise SessionRefused("OWNER_AUTH_NOT_PROVEN")
        elif g["owner_decision"] is not None:
            raise SessionRefused("UNEXPECTED_OWNER_DECISION")
        return sid

    def open(self, token: str, operator: str) -> dict:
        with self._lock:
            grant = self._decode(token)
            sid = self._check(grant, operator)
            if sid in self._revoked:
                raise SessionRefused("REVOKED_SESSION")
            if grant["privilege"] == "FULL_ADMIN":
                decision = verify_decision(
                    grant["owner_decision"], self._owner_public_key,
                    policy=self._policy.policy_id, host=self._host,
                    operator=operator, epoch=self._epoch,
                    requested_ttl=grant["expires"]-grant["issued"],
                    now=int(self._clock()),
                )
                prior = self._decision_sessions.get(decision["decision_id"])
                if prior is not None and prior != sid:
                    raise SessionRefused("OWNER_DECISION_REPLAY")
            for old_sid, old_state in list(self._active.items()):
                if old_state["grant"]["expires"] <= int(self._clock()):
                    self._active.pop(old_sid, None)
            if sid not in self._active and self._active:
                raise SessionRefused("HOST_BUSY")
            if sid not in self._active:
                self._active[sid] = {"grant": grant, "commands": {}}
                if grant["privilege"] == "FULL_ADMIN":
                    self._decision_sessions[decision["decision_id"]] = sid
            elif self._active[sid]["grant"] != grant:
                raise SessionRefused("SESSION_CONFLICT")
            return {"session_id": sid, "state": "SYNTHETIC_OPEN", "host": self._host}

    def execute_canary(self, token: str, operator: str, command_id: str, message: str) -> dict:
        """This NEVER invokes a shell; it returns a bounded synthetic echo only."""
        with self._lock:
            grant = self._decode(token)
            sid = self._check(grant, operator)
            if sid in self._revoked:
                raise SessionRefused("REVOKED_SESSION")
            state = self._active.get(sid)
            if state is None or state["grant"] != grant:
                raise SessionRefused("SESSION_NOT_OPEN")
            cid = uid(command_id)
            if not isinstance(message, str) or len(message.encode("utf-8")) > 64:
                raise SessionRefused("INVALID_CANARY")
            if cid in state["commands"]:
                old, response = state["commands"][cid]
                if old != message:
                    raise SessionRefused("COMMAND_ID_CONFLICT")
                return {**response, "duplicate": True}
            if len(state["commands"]) >= MAX_COMMANDS:
                raise SessionRefused("COMMAND_BUDGET_EXHAUSTED")
            response = {
                "session_id": sid, "command_id": cid,
                "state": "SYNTHETIC_CANARY_PASS",
                "result": message.upper(), "duplicate": False,
            }
            state["commands"][cid] = (message, response)
            return response

    def revoke(self, session_id: str) -> dict:
        with self._lock:
            sid = uid(session_id)
            self._revoked.add(sid)
            self._active.pop(sid, None)
            return {"session_id": sid, "state": "REVOKED"}

    def set_epoch(self, epoch: int) -> None:
        """Synthetic local revocation test; production epoch is protected owner state."""
        if not isinstance(epoch, int) or epoch < self._epoch:
            raise ValueError("INVALID_EPOCH")
        with self._lock:
            self._epoch = epoch
            self._active.clear()
