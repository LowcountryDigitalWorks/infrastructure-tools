#!/usr/bin/env python3
"""Gate A1 bounded transport public identity derivation (source-only).

Derives the REDRIX Gate A3 transport-key SHA-256 from ``ssh-keygen -y`` output for
the protected LDW01 dedicated transport private key. Emits only digests and a
fixed provenance record — never private key material.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

RECORD_SCHEMA = "GATE_A1_TRANSPORT_IDENTITY_V1"
PROVENANCE = "gate-a1-ldw01-transport-private-key-unchanged-contract"
PROVENANCE_LINE = f"PROVENANCE={PROVENANCE}"
DIGEST_LINE_PREFIX = "TRANSPORT_PUBLIC_IDENTITY_SHA256="


class TransportIdentityError(ValueError):
    pass


def transport_public_identity_sha256(key_type: str, key_data: str) -> str:
    if key_type != "ssh-ed25519":
        raise TransportIdentityError("GATE_A1_TRANSPORT_KEY_TYPE_INVALID")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", key_data) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_KEY_DATA_INVALID")
    return hashlib.sha256(f"{key_type} {key_data}".encode("ascii")).hexdigest()


def digest_from_ssh_keygen_y(stdout: str) -> str:
    line = stdout.strip().splitlines()[0] if stdout.strip() else ""
    match = re.fullmatch(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,3})(?: [^\r\n]*)?", line)
    if match is None:
        raise TransportIdentityError("GATE_A1_SSH_KEYGEN_Y_OUTPUT_INVALID")
    key_type, key_data = "ssh-ed25519", match.group(1)
    return transport_public_identity_sha256(key_type, key_data)


def build_record(digest: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_SHA256_INVALID")
    return "\n".join(
        (
            RECORD_SCHEMA,
            PROVENANCE_LINE,
            DIGEST_LINE_PREFIX + digest,
            "",
        )
    )


def parse_record(text: str) -> str:
    lines = text.splitlines()
    if len(lines) != 3:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_INVALID")
    if lines[0] != RECORD_SCHEMA:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_SCHEMA_INVALID")
    if lines[1] != PROVENANCE_LINE:
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_PROVENANCE_INVALID")
    if not lines[2].startswith(DIGEST_LINE_PREFIX):
        raise TransportIdentityError("GATE_A1_TRANSPORT_IDENTITY_RECORD_INVALID")
    digest = lines[2][len(DIGEST_LINE_PREFIX) :]
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise TransportIdentityError("GATE_A1_TRANSPORT_PUBLIC_IDENTITY_SHA256_INVALID")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate A1 transport public identity helper")
    sub = parser.add_subparsers(dest="command", required=True)
    derive = sub.add_parser("derive-from-ssh-keygen-y", help="Read ssh-keygen -y line on stdin; print digest only")
    write = sub.add_parser("write-record")
    write.add_argument("--digest", required=True)
    write.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify-record")
    verify.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "derive-from-ssh-keygen-y":
            digest = digest_from_ssh_keygen_y(sys.stdin.read())
            print(digest)
            return 0
        if args.command == "write-record":
            args.output.write_text(build_record(args.digest), encoding="utf-8")
            return 0
        digest = parse_record(args.record.read_text(encoding="utf-8"))
        print("GATE_A1_TRANSPORT_IDENTITY_VERIFY=PASS")
        print(DIGEST_LINE_PREFIX + digest)
        print("TRANSPORT_KEY_PROVENANCE=" + PROVENANCE)
        return 0
    except TransportIdentityError as exc:
        print("GATE_A1_TRANSPORT_IDENTITY=HOLD", file=sys.stderr)
        print("CLASSIFICATION=" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
