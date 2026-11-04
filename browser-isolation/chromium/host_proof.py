"""Host-side real-Chromium isolation falsification on disposable public CI only.

No model-selected URLs, profiles, mounts, Docker options or host credentials.
Source-only proof, never a production browser service.
"""
from __future__ import annotations
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from run_canary import BoundaryError, gateway_address  # parent PR #224 source

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
VECTORS = [
    "beacon", "keepalive", "ping", "websocket", "resource",
    "service_worker", "redirect", "direct_tcp",
]


def command(docker: str, image_id: str, gateway: str, port: int) -> list[str]:
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise BoundaryError("IMAGE_NOT_PINNED")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise BoundaryError("PORT_INVALID")
    if not isinstance(gateway, str) or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", gateway):
        raise BoundaryError("GATEWAY_NOT_VERIFIED")
    if not isinstance(docker, str) or not docker.startswith("/"):
        raise BoundaryError("DOCKER_PATH_NOT_PINNED")
    # Guest has no network device beyond internal loopback, no sockets/volumes,
    # no host PID/IPC, no owner profile and no model-provided Docker switches.
    return [
        docker, "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=192", "--memory=1g", "--cpus=1.0",
        "--ipc=private", "--shm-size=256m",
        "--user=10001:10001", "--tmpfs=/tmp:rw,nosuid,size=256m",
        image_id, "--probe", gateway, str(port),
    ]


def verify_guest(result: object, rc: int) -> None:
    if not isinstance(result, dict) or set(result) != {
        "result", "local_chromium", "interactions", "vectors", "redirect",
        "direct_tcp", "sandbox_requested", "source",
    }:
        raise BoundaryError("CHROMIUM_RESULT_SCHEMA")
    if result["result"] != "PASS" or result["local_chromium"] != "PASS" or result["interactions"] != "PASS":
        raise BoundaryError("CHROMIUM_GUEST_NOT_PASS")
    if result["vectors"] != VECTORS or result["redirect"] != "BLOCKED" or result["direct_tcp"] != "BLOCKED":
        raise BoundaryError("CHROMIUM_VECTOR_NOT_BLOCKED")
    if result["sandbox_requested"] is not True or result["source"] != "SYNTHETIC_GUEST_ONLY":
        raise BoundaryError("CHROMIUM_SCOPE_INVALID")
    if rc != 0:
        raise BoundaryError("CHROMIUM_GUEST_EXIT_NONZERO")


def proof(image_id: str) -> None:
    docker = shutil.which("docker")
    if not docker:
        raise BoundaryError("DOCKER_NOT_AVAILABLE")
    gateway = gateway_address(docker)
    count = [0]
    halt = threading.Event()
    host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host.settimeout(0.1)
    try:
        try:
            host.bind((gateway, 0))
            host.listen(8)
        except OSError:
            raise BoundaryError("HOST_PRIVATE_LISTENER_UNAVAILABLE") from None
        port = host.getsockname()[1]

        def observe() -> None:
            while not halt.is_set():
                try:
                    client, _ = host.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with client:
                    count[0] += 1

        thread = threading.Thread(target=observe, daemon=True)
        thread.start()
        # A real host connection establishes that the synthetic listener is
        # live. Without positive control a test could pass by doing nothing.
        with socket.create_connection((gateway, port), timeout=1):
            pass
        limit = time.monotonic() + 2
        while count[0] != 1 and time.monotonic() < limit:
            time.sleep(0.02)
        if count[0] != 1:
            raise BoundaryError("HOST_FIXTURE_POSITIVE_CONTROL_FAILED")
        args = command(docker, image_id, gateway, port)
        try:
            output = subprocess.run(args, text=True, capture_output=True,
                                    timeout=100, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("CHROMIUM_GUEST_START_OR_TIMEOUT") from None
        # Allow async browser network effects and late descendant exits to be
        # visible before readback. Any host connect is a test failure.
        time.sleep(0.5)
        if count[0] != 1:
            raise BoundaryError("CHROMIUM_HOST_CONNECT_OBSERVED")
        try:
            parsed = json.loads(output.stdout)
        except (TypeError, ValueError):
            # Never expose stderr or browser traces; these may contain URLs
            # and become sensitive in a future integrated source.
            raise BoundaryError("CHROMIUM_NO_STRUCTURED_RESULT") from None
        verify_guest(parsed, output.returncode)
        print("LDW_REAL_CHROMIUM_NETWORK_NONE=PASS")
        print("SOURCE=SYNTHETIC_OFFLINE_GUEST_ONLY")
    finally:
        halt.set()
        host.close()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("NO_START: EXACT_IMAGE_ID_REQUIRED", file=sys.stderr)
        return 2
    try:
        proof(argv[1])
    except BoundaryError as exc:
        print("NO_START: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
