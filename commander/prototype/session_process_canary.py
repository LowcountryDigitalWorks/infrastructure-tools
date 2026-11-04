"""SYNTHETIC-only link: approved host session -> fixed OS canary -> drain -> journal.

This is a proof of ordering, not a privilege broker. In particular:
- A session may open only through the signed, journal-backed synthetic verifier.
- Actual local fixed-process cleanup MUST be positively verified before the
  host-side journal may transition to REVOKED_VERIFIED.
- Any ambiguous cleanup/journal write leaves the host quarantined.
No arbitrary command, Administrator/root, remote ingress or recovery route.
"""
from __future__ import annotations
from threading import RLock

from host_session_journal import JournalBoundSyntheticAgent
from process_containment import FixedProcessCanary, ContainmentRefused
from preexec_admission import LocalCanaryAdmission, AdmissionRefused
from session import SessionRefused


class ProcessBoundSyntheticSession:
    def __init__(self, host_agent: JournalBoundSyntheticAgent,
                 canary: FixedProcessCanary):
        if not isinstance(host_agent, JournalBoundSyntheticAgent):
            raise ValueError("JOURNAL_BACKED_HOST_REQUIRED")
        if not isinstance(canary, FixedProcessCanary):
            raise ValueError("FIXED_CANARY_REQUIRED")
        self._agent = host_agent
        self._canary = canary
        # Host identity is injected by the trusted local agent, not the caller.
        self._admission = LocalCanaryAdmission(enrolled_host=host_agent._host)
        self._session_id = None
        self._state = "NEW"
        self._lock = RLock()

    def status(self) -> dict:
        return {"state": self._state, "privileged": False,
                "host_journal_status": self._agent._host_journal.status()["state"]}

    def start(self, signed_token: str, operator: str, proposal: dict | None = None) -> dict:
        with self._lock:
            if self._state != "NEW":
                raise SessionRefused("SESSION_NOT_ADMISSIBLE")
            # Admission precedes grant consumption and process launch. A
            # caller's risk claim, URL, argv or arbitrary file is never parsed
            # as an approved fixed operation.
            try:
                self._admission.admit(proposal)
            except AdmissionRefused:
                raise SessionRefused("COMMAND_NOT_ADMITTED") from None
            # Validate owner, host and expiry BEFORE starting a process.
            session = self._agent.open(signed_token, operator)
            self._session_id = session["session_id"]
            # An OPEN record has now been committed. Failures from here remain
            # QUARANTINED, never a freshly reusable signed grant.
            self._state = "HOST_QUARANTINED"
            self._canary.start()
            self._state = "RUNNING"
            return self.status()

    def _finish_verified(self) -> dict:
        # NEVER call journal verified revoke before the OS canary says all
        # fixed child processes have demonstrably drained.
        if self._canary.status()["state"] != "DRAINED_VERIFIED":
            self._state = "HOST_QUARANTINED"
            raise SessionRefused("PROCESS_DRAIN_NOT_VERIFIED")
        try:
            self._agent.revoke(self._session_id)
        except (SessionRefused, ValueError):
            self._state = "HOST_QUARANTINED"
            raise SessionRefused("HOST_QUARANTINED") from None
        self._state = "DRAINED_VERIFIED"
        return self.status()

    def stop(self, *, simulate_unverifiable=False) -> dict:
        with self._lock:
            if self._state != "RUNNING":
                raise SessionRefused("SESSION_NOT_RUNNING")
            self._state = "HOST_QUARANTINED"
            try:
                self._canary.stop(simulate_unverifiable=simulate_unverifiable)
            except ContainmentRefused:
                # Host journal remains OPEN. Never promote a verified status
                # after a forced/ambiguous cleanup or failed OS readback.
                raise SessionRefused("HOST_QUARANTINED") from None
            return self._finish_verified()

    def refresh(self) -> dict:
        with self._lock:
            if self._state != "RUNNING":
                return self.status()
            try:
                status = self._canary.refresh()
            except ContainmentRefused:
                self._state = "HOST_QUARANTINED"
                raise SessionRefused("HOST_QUARANTINED") from None
            if status["state"] == "DRAINED_VERIFIED":
                return self._finish_verified()
            if status["state"] != "RUNNING":
                self._state = "HOST_QUARANTINED"
                raise SessionRefused("HOST_QUARANTINED")
            return self.status()

    def close(self) -> None:
        with self._lock:
            if self._state == "RUNNING":
                try:
                    self.stop()
                except SessionRefused:
                    pass
            self._canary.close()
