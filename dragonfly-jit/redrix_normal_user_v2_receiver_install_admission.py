#!/usr/bin/env python3
"""Read-only HW&VM admission readiness for normal-user V2 receiver install source."""
from __future__ import annotations

from typing import Any

import importlib.util
from pathlib import Path

_INSTALL = Path(__file__).with_name("redrix_normal_user_v2_receiver_install.py")
_spec = importlib.util.spec_from_file_location("redrix_normal_user_v2_receiver_install", _INSTALL)
assert _spec and _spec.loader
_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_install)
evaluate_admission = _install.evaluate_admission
load_contract = _install.load_contract


def evaluate_product_admission_readiness(_: Any = None) -> dict[str, Any]:
    contract = load_contract()
    base = evaluate_admission()
    base["schema"] = contract["schema"]
    base["runtime_enablement_gate"] = contract["runtime_enablement"]
    base["evidence_phases"] = contract["evidence_phases_required_for_physical_install"]
    base["package_identity"] = contract["package_identity"]
    return base


if __name__ == "__main__":
    import json
    import sys

    sys.stdout.write(json.dumps(evaluate_product_admission_readiness(), sort_keys=True) + "\n")
