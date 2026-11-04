"""Host-side real-Chromium isolation falsification on disposable public CI only.

No model-selected URLs, profiles, mounts, Docker options or host credentials.
Source-only proof, never a production browser service.
"""
from __future__ import annotations
import hashlib
import json
import os
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
SECCOMP_GIT_BLOB_SHA = "fddc05fb520affb145404e6f6f647ca96af8087d"


def verified_seccomp_path() -> str:
    # Pin the EXACT official Playwright seccomp file to upstream git blob.
    # No insecure fallback to --security-opt seccomp=unconfined or default.
    profile = pathlib.Path(__file__).resolve().parent / "seccomp_profile.json"
    try:
        data = profile.read_bytes()
    except OSError:
        raise BoundaryError("SECCOMP_PROFILE_MISSING") from None
    fingerprint = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\x00" + data
    ).hexdigest()
    if fingerprint != SECCOMP_GIT_BLOB_SHA:
        raise BoundaryError("SECCOMP_PROFILE_MISMATCH")
    return str(profile)


VECTORS = [
    "beacon", "keepalive", "ping", "websocket", "resource",
    "service_worker", "redirect", "direct_tcp",
]


def command(docker: str, image_id: str, gateway: str, port: int,
            trusted_synthetic: bool = False) -> list[str]:
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise BoundaryError("IMAGE_NOT_PINNED")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise BoundaryError("PORT_INVALID")
    if not isinstance(gateway, str) or not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", gateway):
        raise BoundaryError("GATEWAY_NOT_VERIFIED")
    if not isinstance(docker, str) or not docker.startswith("/"):
        raise BoundaryError("DOCKER_PATH_NOT_PINNED")
    seccomp = verified_seccomp_path()
    if not isinstance(trusted_synthetic, bool):
        raise BoundaryError("MODE_INVALID")
    # Guest has no network device beyond internal loopback, no sockets/volumes,
    # no host PID/IPC, no owner profile and no model-provided Docker switches.
    args = [
        docker, "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=" + seccomp,
        "--pids-limit=192", "--memory=1g", "--cpus=1.0",
        "--ipc=private", "--shm-size=256m",
        "--user=10001:10001", "--tmpfs=/tmp:rw,nosuid,size=256m",
        image_id, "--probe", gateway, str(port),
    ]
    if trusted_synthetic:
        args.append("--trusted-synthetic-only")
    return args


def verify_guest(result: object, rc: int,
                 trusted_synthetic: bool = False) -> None:
    # The actual browser process may refuse to start under strict userns /
    # seccomp. Display only a fixed phase classification; never raw stderr.
    if isinstance(result, dict) and set(result) == {"result", "reason"} and result["result"] == "NO_START":
        allowed = {
            "INVALID_ARGS", "INVALID_TARGET", "LOCAL_BROWSER_NAVIGATION",
            "LOCAL_INTERACTION", "SCREENSHOT", "BROWSER_VECTOR_NOT_INVOKED",
            "SERVICE_WORKER_NOT_INVOKED", "OFF_GUEST_REDIRECT_WAS_ALLOWED",
            "DIRECT_TCP_REACHED_HOST", "GUEST_WATCHDOG",
            "GUEST_INIT_ERROR", "GUEST_BROWSER_LAUNCH_ERROR",
            "GUEST_LOCAL_NAVIGATION_ERROR", "GUEST_LOCAL_ACTIONS_ERROR",
            "GUEST_PAGE_VECTOR_ERROR", "GUEST_SERVICE_WORKER_ERROR",
            "GUEST_REDIRECT_ERROR", "GUEST_DIRECT_TCP_ERROR",
        }
        raise BoundaryError("CHROMIUM_NO_START_" +
                            (result["reason"] if result["reason"] in allowed else "UNCLASSIFIED")) from None
    if not isinstance(result, dict) or set(result) != {
        "result", "local_chromium", "interactions", "vectors", "redirect",
        "direct_tcp", "sandbox_requested", "source",
    }:
        raise BoundaryError("CHROMIUM_RESULT_SCHEMA")
    if result["result"] != "PASS" or result["local_chromium"] != "PASS" or result["interactions"] != "PASS":
        raise BoundaryError("CHROMIUM_GUEST_NOT_PASS")
    if result["vectors"] != VECTORS or result["redirect"] != "BLOCKED" or result["direct_tcp"] != "BLOCKED":
        raise BoundaryError("CHROMIUM_VECTOR_NOT_BLOCKED")
    expected_source = ("TRUSTED_SYNTHETIC_NO_CHROMIUM_SANDBOX"
                       if trusted_synthetic else "SYNTHETIC_GUEST_ONLY")
    if result["sandbox_requested"] is not (not trusted_synthetic) or result["source"] != expected_source:
        raise BoundaryError("CHROMIUM_SCOPE_INVALID")
    if rc != 0:
        raise BoundaryError("CHROMIUM_GUEST_EXIT_NONZERO")


def proof(image_id: str, trusted_synthetic: bool = False) -> None:
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
        args = command(docker, image_id, gateway, port, trusted_synthetic)
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
        verify_guest(parsed, output.returncode, trusted_synthetic)
        print("LDW_TRUSTED_SYNTHETIC_CHROMIUM_NETWORK_NONE=PASS" if trusted_synthetic
              else "LDW_REAL_CHROMIUM_NETWORK_NONE=PASS")
        print("SOURCE=TRUSTED_SYNTHETIC_NO_CHROMIUM_SANDBOX" if trusted_synthetic
              else "SOURCE=SYNTHETIC_OFFLINE_GUEST_ONLY")
    finally:
        halt.set()
        host.close()


def userns_precheck(image_id: str) -> None:
    # Read-only capability probe in an unprivileged, network-none *guest*.
    # Does not change host sysctl, AppArmor, seccomp, Docker daemon or account.
    # This is diagnosis, not acceptance of a Chromium sandbox.
    if not IMAGE_ID.fullmatch(image_id):
        raise BoundaryError("IMAGE_NOT_PINNED")
    docker = shutil.which("docker")
    if not docker:
        raise BoundaryError("DOCKER_NOT_AVAILABLE")
    seccomp = verified_seccomp_path()
    args = [docker, "run", "--rm", "--pull=never", "--network=none",
            "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--security-opt=seccomp=" + seccomp,
            "--pids-limit=32", "--memory=256m", "--ipc=private",
            "--user=10001:10001", "--entrypoint=/usr/bin/unshare",
            image_id, "--user", "--map-root-user", "true"]
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise BoundaryError("USERNS_PRECHECK_NO_START") from None
    # The only permitted output is a fixed result; NEVER echo stderr/raw data.
    print("GUEST_UNPRIV_USERNS_PRECHECK=" +
          ("AVAILABLE" if result.returncode == 0 else "UNAVAILABLE"))
    print("USERNS_PRECHECK_NOT_BROWSER_SANDBOX_ATTESTATION")


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] not in (
        "--trusted-synthetic-only", "--userns-check",
    )):
        print("NO_START: EXACT_IMAGE_ID_REQUIRED", file=sys.stderr)
        return 2
    mode = argv[2] if len(argv) == 3 else "strict"
    try:
        if mode != "strict" and os.environ.get("GITHUB_ACTIONS") != "true":
            raise BoundaryError("DIAGNOSTIC_CI_ONLY")
        if mode == "--userns-check":
            userns_precheck(argv[1])
        else:
            proof(argv[1], mode == "--trusted-synthetic-only")
    except BoundaryError as exc:
        print("NO_START: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
