"""Simulated model-facing tool result. Not a real connector.

Untrusted model/plugin payloads always receive the fixed blocked projection.
Real disposable normal-user work flows through ``local_tool_loopback_harness``
and ``typed_local_tool_transport`` with trusted owner binding only.
"""
from __future__ import annotations

from model_output_boundary import project_model_output


def model_tool_result(payload: object = None) -> dict[str, str]:
    """Route one untrusted value through the fixed output projection."""
    return project_model_output(payload)


def model_typed_tool_call(tool: object = None, arguments: object = None) -> dict[str, str]:
    """Refuse model-supplied tool names and argument bags at the boundary."""
    del tool, arguments
    return project_model_output(None)
