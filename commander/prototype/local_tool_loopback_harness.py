"""Loopback-only typed tool harness for Commander normal-user preflight (#209).

No socket, HTTP, stdio RPC or model-trusted identity fields. The caller must
construct this object locally with owner policy, keys and fixture root.
"""
from __future__ import annotations

import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_session_journal import HostSessionJournal
from local_user_mode import LocalUserModeProbe
from session import OwnerPolicy, SessionIssuer, SessionRefused
from typed_local_tool_transport import (
    TrustedTransportBinding,
    TypedLocalToolDispatcher,
    TypedLocalToolRefused,
    JournalBoundLocalUserModeProbe,
    offline_denial,
)


class LocalToolLoopbackHarness:
    """Disposable trusted local tool transport (not a public service)."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        policy: OwnerPolicy,
        fixture_root: Path,
        *,
        clock=time.time,
        use_host_journal: bool = False,
        journal_path: Path | None = None,
    ):
        self._private_key = private_key
        self._policy = policy
        self._fixture_root = fixture_root
        self._clock = clock
        self._binding = TrustedTransportBinding(policy.policy_id, policy.operator, policy.host)
        self._issuer = SessionIssuer(private_key, policy, clock=clock)
        public_key = private_key.public_key()
        if use_host_journal:
            if journal_path is None:
                raise ValueError("HOST_JOURNAL_PATH_REQUIRED")
            journal = HostSessionJournal(journal_path, initialize=True)
            self._probe = JournalBoundLocalUserModeProbe(
                public_key, policy, policy.host, fixture_root,
                host_journal=journal, clock=clock,
            )
        else:
            self._probe = LocalUserModeProbe(
                public_key, policy, policy.host, fixture_root, clock=clock,
            )
        self._dispatcher = TypedLocalToolDispatcher(self._probe, self._binding)
        self._issued_grant: str | None = None
        self._offline = False

    @classmethod
    def disposable(
        cls,
        private_key: Ed25519PrivateKey,
        *,
        policy_id: str = "typed-local-transport",
        operator: str = "synthetic-operator",
        host: str = "local-disposable",
        ttl_cap: int = 30,
        use_host_journal: bool = False,
    ) -> "LocalToolLoopbackHarness":
        policy = OwnerPolicy(policy_id, operator, host, "MAINTAIN", ttl_cap)
        root = Path(tempfile.mkdtemp(prefix="ldw-commander-transport-"))
        journal_path = None
        if use_host_journal:
            journal_path = root / "host-session.db"
        harness = cls(
            private_key, policy, root,
            use_host_journal=use_host_journal, journal_path=journal_path,
        )
        harness._temp_root = root
        return harness

    def issue_grant(self, ttl_seconds: int = 20) -> str:
        grant = self._issuer.issue(
            self._binding.operator, self._binding.host, "MAINTAIN", ttl_seconds,
        )
        self._issued_grant = grant
        self._dispatcher.bind_grant(grant)
        return grant

    def set_offline(self, offline: bool = True) -> None:
        self._offline = offline

    def invoke(self, tool: str, arguments: dict | None = None) -> dict:
        if self._offline:
            return offline_denial()
        try:
            return self._dispatcher.dispatch(tool, arguments)
        except TypedLocalToolRefused as error:
            return {"state": "TOOL_REFUSED", "reason": error.reason}
        except SessionRefused as error:
            return {"state": "TOOL_REFUSED", "reason": error.reason}
        except Exception:
            return {"state": "TOOL_REFUSED", "reason": "INTERNAL_TRANSPORT_FAULT"}


def run_typed_local_canary(private_key: Ed25519PrivateKey | None = None) -> dict:
    """Sanitized end-to-end disposable proof for local_cli or tests."""
    key = private_key or Ed25519PrivateKey.generate()
    harness = LocalToolLoopbackHarness.disposable(key)
    harness.issue_grant(20)
    command = str(uuid.uuid4())
    opened = harness.invoke("session_open", {})
    hosts = harness.invoke("hosts_list", {})
    written = harness.invoke("fs_write", {
        "command_id": command,
        "name": "canary.txt",
        "value": "LDW_TYPED_TRANSPORT",
    })
    read = harness.invoke("fs_read", {
        "command_id": str(uuid.uuid4()),
        "name": "canary.txt",
    })
    process = harness.invoke("run_fixed_canary", {"command_id": str(uuid.uuid4())})
    preview = harness.invoke("process_read", {})
    closed = harness.invoke("session_close", {})
    if opened.get("state") != "SESSION_OPEN":
        raise RuntimeError("TYPED_TRANSPORT_OPEN_FAILED")
    if written.get("result", {}).get("sha256") != read.get("result", {}).get("sha256"):
        raise RuntimeError("TYPED_TRANSPORT_HASH_MISMATCH")
    if process.get("result", {}).get("exit_code") != 0:
        raise RuntimeError("TYPED_TRANSPORT_PROCESS_FAILED")
    return {
        "state": "TYPED_LOCAL_TRANSPORT_PROOF_COMPLETE",
        "hosts": hosts,
        "session_open": opened["session_id"],
        "file_integrity": "PASS",
        "child_process": "PASS",
        "process_preview": preview.get("process"),
        "session_close": closed.get("state"),
        "privileged": False,
        "remote": False,
        "model_or_plugin_connected": False,
    }
