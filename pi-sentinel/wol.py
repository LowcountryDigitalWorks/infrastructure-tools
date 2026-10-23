#!/usr/bin/env python3
"""Manual, allowlisted Wake-on-LAN packet helper; never invoked by the daemon."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def magic_packet(mac: str) -> bytes:
    """Build the standard 102-byte WOL magic packet for one unicast MAC."""
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
        raise ValueError("invalid MAC format")
    raw = bytes.fromhex(mac.replace(":", ""))
    if raw == b"\x00" * 6 or raw[0] & 1:
        raise ValueError("MAC must be nonzero unicast")
    return b"\xff" * 6 + raw * 16


def load_allowlist(path: str | Path) -> dict[str, str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"targets"} or not isinstance(raw["targets"], dict):
        raise ValueError("allowlist schema must contain only a targets object")
    if len(raw["targets"]) > 32:
        raise ValueError("allowlist is too large")
    clean: dict[str, str] = {}
    for name, mac in raw["targets"].items():
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ValueError("invalid logical target name")
        magic_packet(mac)
        clean[name] = mac
    return clean


def send_allowlisted(name: str, allowlist: dict[str, str], network: str) -> None:
    """Send one UDP magic packet to the configured private subnet broadcast."""
    if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name not in allowlist:
        raise ValueError("target is not allowlisted")
    subnet = ipaddress.ip_network(network, strict=False)
    if not subnet.is_private or not isinstance(subnet, ipaddress.IPv4Network):
        raise ValueError("WOL requires a private IPv4 monitor subnet")
    packet = magic_packet(allowlist[name])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (str(subnet.broadcast_address), 9))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="logical name from the local allowlist")
    parser.add_argument("--config", type=Path, required=True, help="root-managed local allowlist JSON")
    parser.add_argument("--network", required=True, help="approved private IPv4 monitor CIDR")
    args = parser.parse_args()
    try:
        send_allowlisted(args.target, load_allowlist(args.config), args.network)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        # Error text may include local network details; emit only a safe class and exit code.
        print(f"WOL not sent ({type(exc).__name__})", file=sys.stderr)
        raise SystemExit(2)
    print("WOL packet sent to the allowlisted logical target")


if __name__ == "__main__":
    main()
