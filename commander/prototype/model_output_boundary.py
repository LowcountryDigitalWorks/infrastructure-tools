"""Default-deny projection for model-visible Commander output.

No trusted status producer exists in this module. Every input, including a
reserved canary name, is refused. The argument is not read, decoded, or
logged. An owner-only raw output channel and a separately validated status
adapter are future work and are not implemented here.
"""
from __future__ import annotations

BLOCKED_STATUS = "MODEL_OUTPUT_BLOCKED"


def project_model_output(value: object) -> dict[str, str]:
    """Return one fixed status. The argument is intentionally unused."""
    del value
    return {"status": BLOCKED_STATUS}
