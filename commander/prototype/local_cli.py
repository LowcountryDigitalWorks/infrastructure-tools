"""Standalone LDW Commander local smoke CLI (no remote/elevation capability).

Only supports --synthetic-demo. No credentials, host registry, arbitrary argv,
filesystem target or model-controlled session issuance is accepted by this CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from local_user_mode import LocalUserModeProbe
from session import OwnerPolicy, SessionIssuer


def synthetic_demo() -> dict:
    # Generated only for this disposable proof. Never used for host enrollment.
    private_key = Ed25519PrivateKey.generate()
    policy = OwnerPolicy("one-run-local-canary", "synthetic-operator",
                         "local-disposable", "MAINTAIN", 30)
    issuer = SessionIssuer(private_key, policy)
    with tempfile.TemporaryDirectory(prefix="ldw-commander-local-") as root:
        probe = LocalUserModeProbe(private_key.public_key(), policy,
                                  "local-disposable", Path(root))
        grant = issuer.issue("synthetic-operator", "local-disposable", "MAINTAIN", 20)
        session = probe.open(grant, "synthetic-operator")
        create = probe.execute(grant, "synthetic-operator", str(uuid.uuid4()),
                               "file_create", name="canary.txt", value="LDW")
        read = probe.execute(grant, "synthetic-operator", str(uuid.uuid4()),
                             "file_read", name="canary.txt")
        process = probe.execute(grant, "synthetic-operator", str(uuid.uuid4()),
                                "fixed_process")
        revoked = probe.revoke(session["session_id"])
        if create["result"]["sha256"] != read["result"]["sha256"]:
            raise RuntimeError("LOCAL_CANARY_HASH_MISMATCH")
        if process["result"]["exit_code"] != 0:
            raise RuntimeError("LOCAL_CANARY_PROCESS_FAILED")
        return {
            "state": "LOCAL_USER_MODE_PROOF_COMPLETE",
            "file_integrity": "PASS",
            "child_process": "PASS",
            "session_revocation": revoked["state"],
            "privileged": False, "remote": False,
            "model_or_plugin_connected": False,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="LDW Commander synthetic local CLI")
    parser.add_argument("--synthetic-demo", action="store_true",
                        help="run only a disposable local file/process smoke")
    args = parser.parse_args()
    if not args.synthetic_demo:
        parser.error("only --synthetic-demo is supported")
    print(json.dumps(synthetic_demo(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
