"""LDW Commander Gate B pre-execution admission — disposable fixed canary ONLY.

This is a fail-closed *typed request* boundary, not a general-purpose
arbitrary-command classifier, network sandbox or Administrator/root service.

The caller supplies ONLY a canonical operation ID and the requested enrolled
host. The actual executable/arguments, file targets and network permissions
come from this source-controlled local registry, never from caller claims.
Any other field (including 'risk=safe') fails before session-open or spawn.
"""
from __future__ import annotations

from dataclasses import dataclass
import uuid

ADMISSION_CONTRACT = "ldw.commander.canary-admission.v1"
FIXED_OPERATION = "RUN_DISPOSABLE_CHILD_CANARY"
# The pinned implementation uses a hardcoded Python worker and one child.
# No arbitrary shell, caller path/argv, synthetic secret read or network egress.
FIXED_WORKLOAD = "LOCAL_FIXED_NO_NETWORK_NO_SECRETS"
EXPECTED_FIELDS = frozenset({"contract", "host", "operation", "operation_id"})


class AdmissionRefused(ValueError):
    def __init__(self):
        # Deliberately do not echo untrusted proposed executable, path or URL.
        super().__init__("COMMAND_NOT_ADMITTED")
        self.reason = "COMMAND_NOT_ADMITTED"


@dataclass(frozen=True)
class AdmissionRecord:
    """Locally derived, non-authoritative diagnostic; no bearer or user text."""
    operation_id: str
    operation: str
    host: str
    workload: str

    def safe_status(self) -> dict[str, str]:
        return {
            "contract": ADMISSION_CONTRACT,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "admission": "FIXED_CANARY_ONLY",
        }


class LocalCanaryAdmission:
    """Immutable source-side operation registry, NOT model risk classification."""

    def __init__(self, *, enrolled_host: str):
        if not isinstance(enrolled_host, str) or not enrolled_host or len(enrolled_host) > 128:
            raise ValueError("TRUSTED_ENROLLED_HOST_REQUIRED")
        self._host = enrolled_host

    def admit(self, proposed: object) -> AdmissionRecord:
        # Exact type avoids defaulting to a permissive mapping/object with
        # side-effecting properties. Never inspect, parse or run raw command.
        if type(proposed) is not dict or set(proposed) != EXPECTED_FIELDS:
            raise AdmissionRefused()
        if (type(proposed["contract"]) is not str or
            proposed["contract"] != ADMISSION_CONTRACT or
            type(proposed["host"]) is not str or
            proposed["host"] != self._host or
            type(proposed["operation"]) is not str or
            proposed["operation"] != FIXED_OPERATION):
            raise AdmissionRefused()
        proposed_id = proposed["operation_id"]
        if type(proposed_id) is not str or len(proposed_id) != 36:
            raise AdmissionRefused()
        try:
            canonical_id = str(uuid.UUID(proposed_id))
        except (ValueError, TypeError, AttributeError):
            raise AdmissionRefused() from None
        if canonical_id != proposed_id:
            raise AdmissionRefused()
        return AdmissionRecord(
            operation_id=canonical_id,
            operation=FIXED_OPERATION,
            host=self._host,
            workload=FIXED_WORKLOAD,
        )


def fixed_canary_proposal(enrolled_host: str, *, operation_id: str | None = None) -> dict:
    """Trusted test fixture factory. Not approval, signing, or a model tool."""
    return {
        "contract": ADMISSION_CONTRACT,
        "host": enrolled_host,
        "operation": FIXED_OPERATION,
        "operation_id": operation_id or str(uuid.uuid4()),
    }
