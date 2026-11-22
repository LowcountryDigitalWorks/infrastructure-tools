"""Fail-closed static Windows Sandbox .wsb source-profile validation.

This verifier observes only fixed repository bytes. A matching XML profile is
NOT evidence a VM was started, confined, enrolled or authorized for Gate C.
It never invokes a Windows API, launcher, executable, network or privilege.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

PROFILE_NAME = "gate_c_disposable_nohostshare.wsb"
CLASSIFICATION = "SOURCE_CONFIGURATION_ONLY_NOT_GUEST_ADMITTED"
EXPECTED_SETTINGS = (
    ("vGPU", "Disable"),
    ("Networking", "Disable"),
    ("AudioInput", "Disable"),
    ("VideoInput", "Disable"),
    ("ProtectedClient", "Enable"),
    ("PrinterRedirection", "Disable"),
    ("ClipboardRedirection", "Disable"),
)


def matches_fixed_profile(xml_source: str) -> bool:
    """True only for one exact safe option set; no executable or host shares.

    String/XML matching is a SOURCE check, not cryptographic attestation of
    what Windows actually launched. Configuration bytes can be altered by a
    local user, and host policy may override effective sandbox behavior.
    """
    if not isinstance(xml_source, str) or not 64 <= len(xml_source) <= 2048:
        return False
    # ElementTree does not resolve external DTDs, but reject DTDs,
    # processing instructions and comments rather than accepting hidden data.
    if "<!" in xml_source or "<?" in xml_source:
        return False
    try:
        root = ET.fromstring(xml_source)
    except (ET.ParseError, ValueError, TypeError):
        return False
    if root.tag != "Configuration" or root.attrib or (root.text or "").strip():
        return False
    if (root.tail or "").strip():
        return False
    children = list(root)
    if len(children) != len(EXPECTED_SETTINGS):
        return False
    for child, (name, value) in zip(children, EXPECTED_SETTINGS):
        if child.tag != name or child.attrib or len(child):
            return False
        if (child.text or "").strip() != value or (child.tail or "").strip():
            return False
    return True


def inspect_source() -> dict[str, object]:
    """Read only the shipped profile. Never accept caller-selected paths."""
    try:
        content = Path(__file__).with_name(PROFILE_NAME).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        content = ""
    return {
        "classification": CLASSIFICATION,
        "fixed_profile_matches": matches_fixed_profile(content),
        "feature_installed_verified": False,
        "guest_started_verified": False,
        "external_network_confinement_verified": False,
        "owner_presence_verified": False,
        "admin_session_authorized": False,
    }


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(inspect_source(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
