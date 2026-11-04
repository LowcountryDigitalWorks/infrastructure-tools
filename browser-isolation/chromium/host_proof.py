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
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from run_canary import BoundaryError, gateway_address  # parent PR #224 source

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[0-9a-f]{24}$")
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
            trusted_synthetic: bool = False, *, nonce: str) -> list[str]:
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
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise BoundaryError("PROOF_NONCE_INVALID")
    # Guest has no network device beyond internal loopback, no sockets/volumes,
    # no host PID/IPC, no owner profile and no model-provided Docker switches.
    args = [
        docker, "container", "create", "--init",
        "--name=ldw-chromium-proof-" + nonce,
        "--label=ldw.proof.nonce=" + nonce,
        "--pull=never", "--network=none",
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
            "GUEST_BROWSER_LAUNCH_NO_USABLE_SANDBOX",
            "GUEST_BROWSER_LAUNCH_NAMESPACE_DENIED",
            "GUEST_BROWSER_LAUNCH_OPERATION_DENIED",
            "GUEST_BROWSER_LAUNCH_SHARED_LIBRARY",
            "GUEST_BROWSER_LAUNCH_PROCESS_EXITED",
            "GUEST_BROWSER_LAUNCH_DIRECT_NO_USABLE_SANDBOX",
            "GUEST_BROWSER_LAUNCH_DIRECT_NAMESPACE_MOVE_DENIED",
            "GUEST_BROWSER_LAUNCH_DIRECT_OPERATION_NOT_PERMITTED",
            "GUEST_BROWSER_LAUNCH_DIRECT_PERMISSION_DENIED",
            "GUEST_BROWSER_LAUNCH_DIRECT_READ_ONLY_FILESYSTEM",
            "GUEST_BROWSER_LAUNCH_DIRECT_SHARED_MEMORY",
            "GUEST_BROWSER_LAUNCH_DIRECT_SECCOMP",
            "GUEST_BROWSER_LAUNCH_DIRECT_ZYGOTE",
            "GUEST_BROWSER_LAUNCH_DIRECT_SANDBOX",
            "GUEST_BROWSER_LAUNCH_DIRECT_TIMEOUT",
            "GUEST_BROWSER_LAUNCH_DIRECT_SUCCESS_PLAYWRIGHT_FAILED",
            "GUEST_BROWSER_LAUNCH_DIRECT_UNKNOWN",
            "GUEST_BROWSER_LAUNCH_DIRECT_DIAG_UNAVAILABLE",
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


def inspect_container(docker: str, name: str) -> tuple[str, str, str] | None:
    """Inspect only the exact randomly named guest; fail if daemon is unhealthy."""
    try:
        read = subprocess.run(
            [docker, "container", "inspect", "--format",
             '{{.Id}}|{{.Image}}|{{index .Config.Labels "ldw.proof.nonce"}}',
             name], capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise BoundaryError("PROOF_DOCKER_INSPECT_AMBIGUOUS") from None
    if read.returncode == 0:
        parts = read.stdout.strip().split("|")
        if (len(parts) != 3 or not CONTAINER_ID.fullmatch(parts[0])
                or not IMAGE_ID.fullmatch(parts[1])
                or not NONCE.fullmatch(parts[2])):
            raise BoundaryError("PROOF_CONTAINER_IDENTITY_INVALID")
        return parts[0], parts[1], parts[2]
    # Nonzero inspect is NOT automatically equivalent to absent. Verify the
    # Docker daemon can still answer a separate read-only health command.
    try:
        ping = subprocess.run([docker, "info", "--format", "{{.ID}}"],
                              capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        raise BoundaryError("PROOF_DOCKER_HEALTH_AMBIGUOUS") from None
    if ping.returncode != 0:
        raise BoundaryError("PROOF_DOCKER_HEALTH_AMBIGUOUS")
    return None


def guarded_container_cleanup(docker: str, name: str, nonce: str,
                              image_id: str) -> None:
    """Remove only the exact labeled guest created for this proof."""
    state = inspect_container(docker, name)
    if state is not None:
        _id, inspected_image, inspected_nonce = state
        if inspected_image != image_id or inspected_nonce != nonce:
            raise BoundaryError("PROOF_CONTAINER_PROVENANCE_MISMATCH")
        try:
            result = subprocess.run(
                [docker, "container", "rm", "--force", name],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("PROOF_CONTAINER_CLEANUP_AMBIGUOUS") from None
        if result.returncode != 0:
            raise BoundaryError("PROOF_CONTAINER_CLEANUP_FAILED")
    if inspect_container(docker, name) is not None:
        raise BoundaryError("PROOF_CONTAINER_RESIDUE")
    # Host runner's Docker daemon answered both readbacks. Do not silently
    # treat a failed rm or opaque daemon state as successful cleanup.


def run_bound_guest(docker: str, image_id: str, gateway: str, port: int,
                    trusted_synthetic: bool) -> subprocess.CompletedProcess:
    """Create, verify, attach and deterministically tear down one named guest."""
    nonce = secrets.token_hex(12)
    name = "ldw-chromium-proof-" + nonce
    args = command(docker, image_id, gateway, port, trusted_synthetic,
                   nonce=nonce)
    if inspect_container(docker, name) is not None:
        raise BoundaryError("PROOF_CONTAINER_NAME_COLLISION")
    try:
        try:
            made = subprocess.run(args, capture_output=True, text=True,
                                  timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("PROOF_CONTAINER_CREATE_AMBIGUOUS") from None
        if made.returncode != 0 or not CONTAINER_ID.fullmatch(made.stdout.strip()):
            raise BoundaryError("PROOF_CONTAINER_CREATE_FAILED")
        state = inspect_container(docker, name)
        if state != (made.stdout.strip(), image_id, nonce):
            raise BoundaryError("PROOF_CONTAINER_PROVENANCE_MISMATCH")
        try:
            return subprocess.run(
                [docker, "container", "start", "--attach", name],
                capture_output=True, text=True, timeout=100, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("CHROMIUM_GUEST_START_OR_TIMEOUT") from None
    finally:
        # Even if the CLI crashes/exits ambiguously, never abandon a
        # long-running Chromium container to continue after this return.
        guarded_container_cleanup(docker, name, nonce, image_id)


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
        output = run_bound_guest(docker, image_id, gateway, port,
                                 trusted_synthetic)
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
        # run_bound_guest returned only AFTER verified provenance and
        # terminal Docker residue readback, including on guest failure.
        print("LDW_BROWSER_CONTAINER_CLEANUP_VERIFIED=PASS")
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
    base = [docker, "run", "--rm", "--pull=never", "--network=none",
            "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--security-opt=seccomp=" + seccomp,
            "--pids-limit=32", "--memory=256m", "--ipc=private",
            "--user=10001:10001", "--entrypoint=/usr/bin/unshare", image_id]
    # Each step is a *separate*, disposable non-root process in the existing
    # Docker network-none guest. No host namespace/policy changes or real sites.
    probes = (
        ("GUEST_UNPRIV_USERNS_PRECHECK", ["--user", "--map-root-user", "true"]),
        ("GUEST_UNPRIV_USERNS_PID", ["--user", "--map-root-user",
                                   "--pid", "--fork", "true"]),
        ("GUEST_UNPRIV_USERNS_PID_NET", ["--user", "--map-root-user",
                                       "--pid", "--net", "--fork", "true"]),
    )
    for key, flags in probes:
        try:
            result = subprocess.run(base + flags, capture_output=True,
                                    text=True, timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("USERNS_PRECHECK_NO_START") from None
        # Only fixed status labels are model/CI visible, not stderr/host paths.
        print(key + "=" + ("AVAILABLE" if result.returncode == 0
                           else "UNAVAILABLE"))
    print("USERNS_PRECHECK_NOT_BROWSER_SANDBOX_ATTESTATION")


def host_policy_readback() -> None:
    """Read only fixed public kernel policy toggles on an ephemeral CI host.

    No raw /proc content, process identities, host paths, profiles or sysctl
    changes are disclosed. This helps triage but does NOT establish cause.
    """
    fields = (
        ("HOST_APPARMOR_MODULE", "/sys/module/apparmor/parameters/enabled",
         {"Y": "ENABLED", "N": "DISABLED"}),
        ("HOST_APPARMOR_RESTRICT_UNPRIV_USERNS",
         "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
         {"1": "ENABLED", "0": "DISABLED"}),
        ("HOST_UNPRIV_USERNS_CLONE",
         "/proc/sys/kernel/unprivileged_userns_clone",
         {"1": "ENABLED", "0": "DISABLED"}),
    )
    for label, path, valid in fields:
        try:
            actual = pathlib.Path(path).read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            actual = ""
        print(label + "=" + valid.get(actual, "UNAVAILABLE"))
    print("HOST_POLICY_READBACK_NOT_SANDBOX_ATTESTATION")


def clone3_invalid_argument_precheck(image_id: str) -> None:
    """Probe only whether a deliberately invalid clone3 syscall reaches errno.

    No child is created because the argument pointer and size are invalid.
    Result is diagnostic, not proof of Chromium sandbox / namespace support.
    The x86_64 syscall number is fixed for this GitHub-hosted x64 CI lane.
    """
    if not IMAGE_ID.fullmatch(image_id):
        raise BoundaryError("IMAGE_NOT_PINNED")
    docker = shutil.which("docker")
    if not docker:
        raise BoundaryError("DOCKER_NOT_AVAILABLE")
    seccomp = verified_seccomp_path()
    script = (
        "import ctypes, errno, platform; "
        "machine=platform.machine(); "
        "libc=ctypes.CDLL(None,use_errno=True); "
        "rv=libc.syscall(ctypes.c_long(435),ctypes.c_void_p(0),ctypes.c_size_t(0)) "
        "if machine=='x86_64' else 0; "
        "err=ctypes.get_errno(); "
        "status=('NON_X64' if machine!='x86_64' else "
        "('UNEXPECTED' if rv!=-1 else "
        "{errno.EPERM:'DENIED_EPERM',errno.EACCES:'DENIED_EACCES',"
        "errno.ENOSYS:'UNSUPPORTED_ENOSYS',"
        "errno.EINVAL:'ARGUMENT_REJECTED_EINVAL',"
        "errno.EFAULT:'ARGUMENT_REJECTED_EFAULT'}.get(err,'OTHER'))); "
        "print(status)"
    )
    args = [
        docker, "run", "--rm", "--pull=never", "--network=none",
        "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=" + seccomp,
        "--pids-limit=32", "--memory=256m", "--ipc=private",
        "--user=10001:10001", "--entrypoint=/usr/bin/python3",
        image_id, "-c", script,
    ]
    try:
        output = subprocess.run(args, capture_output=True, text=True,
                                timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        print("GUEST_CLONE3_NULL_PROBE=UNAVAILABLE")
        return
    allowed = {
        "DENIED_EPERM", "DENIED_EACCES", "UNSUPPORTED_ENOSYS",
        "ARGUMENT_REJECTED_EINVAL", "ARGUMENT_REJECTED_EFAULT", "NON_X64",
        "OTHER",
    }
    code = output.stdout.strip()
    print("GUEST_CLONE3_NULL_PROBE=" +
          (code if output.returncode == 0 and code in allowed else "UNAVAILABLE"))
    print("CLONE3_INVALID_ARGUMENT_PROBE_NOT_SANDBOX_ATTESTATION")


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] not in (
        "--trusted-synthetic-only", "--userns-check", "--host-policy-readback",
        "--clone3-null-check",
    )):
        print("NO_START: EXACT_IMAGE_ID_REQUIRED", file=sys.stderr)
        return 2
    mode = argv[2] if len(argv) == 3 else "strict"
    try:
        if mode != "strict" and os.environ.get("GITHUB_ACTIONS") != "true":
            raise BoundaryError("DIAGNOSTIC_CI_ONLY")
        if mode == "--userns-check":
            userns_precheck(argv[1])
        elif mode == "--host-policy-readback":
            host_policy_readback()
        elif mode == "--clone3-null-check":
            clone3_invalid_argument_precheck(argv[1])
        else:
            proof(argv[1], mode == "--trusted-synthetic-only")
    except BoundaryError as exc:
        print("NO_START: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
