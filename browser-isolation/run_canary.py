"""Run an immutable synthetic Go canary in a Docker guest with NO network.

This proves one external network boundary on a disposable CI host; it does not
run Chromium, connect ChatGPT, or authorize browser operations. Host Docker
access and the already-loaded exact image ID are trusted operator inputs.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class BoundaryError(Exception):
    pass


def command(docker: str, image_id: str, gateway: str, port: int) -> list[str]:
    if not docker or not isinstance(docker, str):
        raise BoundaryError("DOCKER_NOT_PINNED")
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise BoundaryError("IMAGE_NOT_PINNED")
    try:
        ip = ipaddress.IPv4Address(gateway)
    except ipaddress.AddressValueError:
        raise BoundaryError("GATEWAY_INVALID") from None
    if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise BoundaryError("GATEWAY_NOT_PRIVATE")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BoundaryError("PORT_INVALID")
    return [
        docker, "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
        "--pids-limit=32", "--memory=128m", "--cpus=0.5", "--ipc=private",
        "--pid=private", "--user=65532:65532",
        "--tmpfs=/tmp:rw,nosuid,noexec,size=8m",
        image_id, "--probe", str(ip), str(port),
    ]


def gateway_address(docker: str) -> str:
    # Read-only inspection. Refuse if host's private Docker bridge is absent.
    template = "{{(index .IPAM.Config 0).Gateway}}"
    try:
        result = subprocess.run(
            [docker, "network", "inspect", "bridge", "--format", template],
            capture_output=True, text=True, timeout=8, check=True,
        )
    except (subprocess.SubprocessError, OSError):
        raise BoundaryError("DOCKER_BRIDGE_NOT_PROVEN") from None
    value = result.stdout.strip()
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise BoundaryError("DOCKER_BRIDGE_NOT_PROVEN") from None
    if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise BoundaryError("DOCKER_BRIDGE_NOT_PRIVATE")
    return str(ip)


def validate_guest_result(result: object, exit_code: int) -> None:
    expected = {"guest_fixture": "PASS", "host_gateway": "BLOCKED", "off_guest": "BLOCKED"}
    if not isinstance(result, dict) or set(result) != set(expected):
        raise BoundaryError("GUEST_RESULT_INVALID")
    for key, expected_value in expected.items():
        if result[key] != expected_value:
            # Fixed, non-sensitive statuses only; never print Docker stderr,
            # guest stdout, host IPs or page/application response content.
            raise BoundaryError("GUEST_" + key.upper() + "_NOT_PROVEN")
    if exit_code != 0:
        raise BoundaryError("GUEST_EXIT_NONZERO_WITH_PASS_RESULT")


def proof(image_id: str) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise BoundaryError("DOCKER_NOT_INSTALLED")
    gateway = gateway_address(docker)
    # Binds to Docker's private bridge interface, never 0.0.0.0/public host.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(0.1)
    count = [0]
    done = threading.Event()
    try:
        try:
            listener.bind((gateway, 0))
            listener.listen(3)
        except OSError:
            raise BoundaryError("HOST_BRIDGE_LISTENER_UNAVAILABLE") from None
        port = listener.getsockname()[1]
        args = command(docker, image_id, gateway, port)

        def measure() -> None:
            while not done.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with client:
                    count[0] += 1

        worker = threading.Thread(target=measure, daemon=True)
        worker.start()
        # Positive control: the synthetic listener is actually reachable from
        # the host, so a Docker guest on the bridge network would be detected.
        try:
            with socket.create_connection((gateway, port), timeout=1):
                pass
        except OSError:
            raise BoundaryError("HOST_BRIDGE_POSITIVE_CONTROL_FAILED") from None
        limit = time.monotonic() + 2
        while count[0] < 1 and time.monotonic() < limit:
            time.sleep(0.01)
        if count[0] != 1:
            raise BoundaryError("HOST_BRIDGE_POSITIVE_CONTROL_FAILED")
        try:
            run = subprocess.run(
                args, capture_output=True, text=True, timeout=25, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("CONTAINER_NO_START_OR_AMBIGUOUS") from None
        # Do not print stdout/stderr or host addresses, even on an error.
        time.sleep(0.2)
        if count[0] != 1:
            raise BoundaryError("HOST_GATEWAY_REACHED_FROM_GUEST")
        try:
            result = json.loads(run.stdout)
        except (json.JSONDecodeError, TypeError):
            # No guest-emitted result indicates a Docker/OCI start or runtime
            # problem, NOT evidence of an OS network block.
            raise BoundaryError("GUEST_NO_STRUCTURED_RESULT") from None
        validate_guest_result(result, run.returncode)
        print("LDW_BROWSER_NETWORK_NONE_CANARY=PASS")
        print("SCOPE=OFFLINE_SYNTHETIC_GUEST_ONLY")
    finally:
        done.set()
        listener.close()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("NO_START: EXACT_IMAGE_SHA256_REQUIRED", file=sys.stderr)
        return 2
    try:
        proof(argv[1])
    except BoundaryError as exc:
        print("NO_START: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
