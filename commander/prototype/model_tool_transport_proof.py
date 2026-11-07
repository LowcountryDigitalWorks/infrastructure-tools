"""Simulated model-facing tool result. Not a real connector.

Every call returns the fixed blocked projection. Generators are not iterated
and callbacks are not invoked. This does not prove that a live MCP plugin,
ChatGPT connector, or protected host intercepts streams.
"""
from __future__ import annotations

from model_output_boundary import project_model_output


def model_tool_result(payload: object = None) -> dict[str, str]:
    """Route one untrusted value through the fixed output projection."""
    return project_model_output(payload)
