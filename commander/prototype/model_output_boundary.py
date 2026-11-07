"""Default-deny projection for model-visible Commander output.

Untrusted text, bytes, chunks, and exceptions are not inspected or decoded.
Only two exact synthetic canary status names become a one-field result.
That name does not prove an operating-system process ran. An owner-only raw
output channel is not implemented here.
"""
from __future__ import annotations

BLOCKED_STATUS = "MODEL_OUTPUT_BLOCKED"
_ALLOWED = frozenset({
    "SYNTHETIC_CANARY_NOT_STARTED",
    "SYNTHETIC_CANARY_FINISHED",
})


def project_model_output(value: object) -> dict[str, str]:
    """Return a fixed short status. Never echo, redact, or decode the input."""
    if type(value) is str and value in _ALLOWED:
        return {"status": value}
    return {"status": BLOCKED_STATUS}
