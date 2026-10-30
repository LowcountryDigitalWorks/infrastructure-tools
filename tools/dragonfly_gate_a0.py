#!/usr/bin/env python3
"""Standalone read-only REDRIX Gate A0 evidence for issue #139.

The helper performs point-in-time local readback only. It creates no local
checkout/task directory and exposes no provider, runner, transport-client,
service-mutation, install, recovery, or VM-launch path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from typing import Callable

MARKER = "DRAGONFLY_GATE_A0_V2"
PRODUCTION_HOME = Path("/home/eddie")
PRODUCTION_UID = 1000
STATE_ROOT = PRODUCTION_HOME / ".local/state/ldw-dragonfly-jit"
RUNS_ROOT = STATE_ROOT / "runs"
STATUS_PATH = STATE_ROOT / "status.json"
STATE_LOCK_PATH = STATE_ROOT / "state.lock"
GUEST_LOCK_PATH = STATE_ROOT / "guest.lock"
TRANSACTION_PATH = PRODUCTION_HOME / ".local/state/ldw/dragonfly-canary-publication/install-transaction.json"
RECEIPT_PATH = PRODUCTION_HOME / ".local/state/ldw/dragonfly-canary-publication/install-receipt.json"
AUTHORIZED_KEYS_PATH = PRODUCTION_HOME / ".ssh/authorized_keys"
AUTHORIZED_KEYS2_PATH = PRODUCTION_HOME / ".ssh/authorized_keys2"
FORCED_COMMAND = "/home/eddie/.local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"
EXPECTED_OPENSSH_PREFIX = "OpenSSH_10.0p2 Debian-7+deb13u4"
EXPECTED_TAILSCALE_VERSION = "1.104.4"
ACCEPTED_LOCAL_ALIASES = {"redrix", "penguin"}
QEMU_NAMES = {"qemu-kvm", "kvm"}
PROC_ROOT = Path("/proc")

REQUIRED_ACCEPTED_115 = {
    Path(".local/lib/ldw-dragonfly-jit/ssh_forced_receiver.py"): ("bb7401de594623aa3f879150a92b20f0f6bbf607", 0o700),
    Path(".local/lib/ldw-dragonfly-jit/handoff_contract.py"): ("2f7892275bacd9f56abaa0cdf204f46f79c046c0", 0o600),
}
OPTIONAL_ACCEPTED_CURRENT = {
    Path(".local/lib/ldw-dragonfly-jit/canary_executor.py"): ("c8c51040b99b0f2f8fd6b10156395244505d61cc", 0o600),
    Path(".local/lib/ldw-dragonfly-jit/dragonfly_jit.py"): ("dd6808cb1eb282c8c859a4cfcc641f4a5c574c2a", 0o600),
    Path(".local/lib/ldw-dragonfly-jit/canary-guest/bootstrap.sh"): ("0fa167cba3f30652caac3bf822a616f31183d62a", 0o700),
    Path(".local/lib/ci-runner/guest/run-one.sh"): ("a17ee1fa2ae307ce142572eb7dff9b2bbcfb56ee", 0o755),
    Path(".local/lib/ci-runner/guest/ci7-runner.service"): ("b5a7cdad0d7ec457b3aacee59167454a5078022e", 0o644),
}

CommandRunner = Callable[[tuple[str, ...]], tuple[int, str]]


class A0Error(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _assert_home(home: Path, uid: int) -> Path:
    candidate = home.absolute()
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise A0Error("A0_HOME_INVALID") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise A0Error("A0_HOME_INVALID")
    if candidate.resolve(strict=True) != candidate:
        raise A0Error("A0_HOME_INVALID")
    return candidate


def _assert_path_chain(home: Path, target: Path, uid: int) -> None:
    home = _assert_home(home, uid)
    candidate = target.absolute()
    try:
        relative = candidate.relative_to(home)
    except ValueError as exc:
        raise A0Error("A0_TARGET_OUTSIDE_HOME") from exc
    cursor = home
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            info = cursor.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise A0Error("A0_TARGET_PARENT_INVALID")


def _assert_exact_directory(home: Path, path: Path, uid: int, mode: int, classification: str) -> Path:
    _assert_path_chain(home, path / ".sentinel", uid)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise A0Error(classification) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise A0Error(classification)
    return path


def _assert_owned_directory(home: Path, path: Path, uid: int, label: str) -> Path:
    _assert_path_chain(home, path / ".sentinel", uid)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise A0Error(label + "_MISSING") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise A0Error(label + "_INVALID")
    return path


def _read_owned_regular(home: Path, path: Path, uid: int, mode: int | None = None) -> bytes:
    _assert_path_chain(home, path, uid)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise A0Error("A0_REQUIRED_FILE_MISSING") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        raise A0Error("A0_FILE_OWNERSHIP_INVALID")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        raise A0Error("A0_FILE_MODE_INVALID")
    return path.read_bytes()


def _lock_available_readonly(home: Path, path: Path, uid: int) -> tuple[bool, bool]:
    _assert_path_chain(home, path, uid)
    present = path.exists() or path.is_symlink()
    if not present:
        return True, False
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        raise A0Error("A0_LOCK_PATH_INVALID")
    with path.open("rb") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False, True
        try:
            return True, True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _validate_jit_state(home: Path, uid: int) -> dict:
    _assert_owned_directory(home, STATE_ROOT, uid, "A0_STATE_ROOT")
    runs_root = _assert_owned_directory(home, RUNS_ROOT, uid, "A0_RUNS_ROOT")
    _assert_path_chain(home, STATUS_PATH, uid)
    if STATUS_PATH.is_symlink():
        raise A0Error("A0_STATUS_PATH_INVALID")
    status_present = STATUS_PATH.exists()
    if status_present:
        data = _read_owned_regular(home, STATUS_PATH, uid, 0o600)
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise A0Error("A0_STATUS_JSON_INVALID") from exc
        if not isinstance(value, dict):
            raise A0Error("A0_STATUS_OBJECT_REQUIRED")
    else:
        value = {
            "schema": 1,
            "marker": "CI-RUNNER-DRAGONFLY-JIT-001",
            "state": "STOPPED",
            "updated_at": None,
            "run_id": None,
            "qemu_pid": None,
            "reason": None,
        }
    allowed = {"schema", "marker", "state", "updated_at", "run_id", "qemu_pid", "reason"}
    if set(value) - allowed:
        raise A0Error("A0_STATUS_FIELDS_INVALID")
    if value.get("schema") != 1 or value.get("marker") != "CI-RUNNER-DRAGONFLY-JIT-001":
        raise A0Error("A0_STATUS_CONTRACT_INVALID")
    if value.get("state") != "STOPPED":
        raise A0Error("A0_JIT_STATE_NOT_STOPPED")
    if value.get("run_id") is not None:
        raise A0Error("A0_JIT_RUN_ID_PRESENT")
    if value.get("qemu_pid") is not None:
        raise A0Error("A0_JIT_QEMU_PID_PRESENT")

    entries = list(runs_root.iterdir())
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir():
            raise A0Error("A0_RUN_ROOT_CONTAMINATED")
    if entries:
        raise A0Error("A0_RUN_RESIDUE_PRESENT")

    guest_available, guest_present = _lock_available_readonly(home, GUEST_LOCK_PATH, uid)
    state_available, state_present = _lock_available_readonly(home, STATE_LOCK_PATH, uid)
    if not guest_available:
        raise A0Error("A0_GUEST_LOCK_BUSY")
    if not state_available:
        raise A0Error("A0_STATE_LOCK_BUSY")
    return {
        "jitState": "STOPPED",
        "jitStateSource": "file-backed" if status_present else "implicit-default",
        "statusFilePresent": status_present,
        "runIdPresent": False,
        "qemuPidPresent": False,
        "runResidueCount": 0,
        "guestLockAvailable": True,
        "guestLockFilePresent": guest_present,
        "stateLockAvailable": True,
        "stateLockFilePresent": state_present,
    }


def _looks_like_qemu(token: str) -> bool:
    token = token.strip("'\";()[]{}:,=")
    if not token:
        return False
    name = Path(token).name
    return name in QEMU_NAMES or name.startswith("qemu-system-")


def _qemu_process_ids_from_ps(text: str) -> list[int]:
    matches: list[int] = []
    for raw in text.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        comm = parts[1]
        args = parts[2] if len(parts) > 2 else ""
        tokens = [comm]
        if args:
            tokens.extend(args.replace('"', " ").replace("'", " ").split())
        if any(_looks_like_qemu(token) for token in tokens):
            matches.append(pid)
    return sorted(set(matches))


def _kvm_fd_pids(proc_root: Path = PROC_ROOT) -> list[int]:
    try:
        processes = list(proc_root.iterdir())
    except OSError as exc:
        raise A0Error("A0_PROCESS_ENUMERATION_FAILED") from exc
    matches: set[int] = set()
    for process in processes:
        if not process.name.isdigit():
            continue
        fd_root = process / "fd"
        try:
            descriptors = list(fd_root.iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                continue
            if target == "/dev/kvm":
                matches.add(int(process.name))
                break
    return sorted(matches)


def _default_runner(argv: tuple[str, ...]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise A0Error("A0_READBACK_COMMAND_FAILED") from exc
    return proc.returncode, proc.stdout.strip()


def _run(runner: CommandRunner, argv: tuple[str, ...], classification: str) -> str:
    rc, output = runner(argv)
    if rc != 0:
        raise A0Error(classification)
    return output.strip()


def _transport_files(home: Path, uid: int) -> dict:
    for rel, (blob, mode) in REQUIRED_ACCEPTED_115.items():
        data = _read_owned_regular(home, home / rel, uid, mode)
        if _git_blob(data) != blob:
            raise A0Error("A0_TRANSPORT_BASELINE_UNRECOGNIZED")
    optional_present = 0
    for rel, (blob, mode) in OPTIONAL_ACCEPTED_CURRENT.items():
        path = home / rel
        _assert_path_chain(home, path, uid)
        if not path.exists() and not path.is_symlink():
            continue
        data = _read_owned_regular(home, path, uid, mode)
        if _git_blob(data) != blob:
            raise A0Error("A0_TRANSPORT_BASELINE_UNRECOGNIZED")
        optional_present += 1
    return {
        "transportBaseline": "accepted-115",
        "transportRequiredFiles": len(REQUIRED_ACCEPTED_115),
        "optionalAcceptedFilesPresent": optional_present,
    }


def _transport_authorized_key(home: Path, uid: int, expected_key_sha256: str) -> dict:
    if re.fullmatch(r"[a-f0-9]{64}", expected_key_sha256) is None:
        raise A0Error("A0_EXPECTED_TRANSPORT_KEY_SHA256_INVALID")
    _assert_exact_directory(home, home / ".ssh", uid, 0o700, "A0_SSH_DIR_INVALID")
    _assert_path_chain(home, AUTHORIZED_KEYS2_PATH, uid)
    if AUTHORIZED_KEYS2_PATH.exists() or AUTHORIZED_KEYS2_PATH.is_symlink():
        raise A0Error("A0_AUTHORIZED_KEYS_ALTERNATE_PRESENT")
    data = _read_owned_regular(home, AUTHORIZED_KEYS_PATH, uid, 0o600)
    if len(data) > 1024 * 1024 or b"\x00" in data:
        raise A0Error("A0_AUTHORIZED_KEYS_INVALID")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise A0Error("A0_AUTHORIZED_KEYS_INVALID") from exc

    active = [
        raw.strip()
        for raw in text.splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    ]
    if len(active) != 1:
        raise A0Error("A0_AUTHORIZED_KEYS_NOT_UNIQUE")

    command = re.escape(FORCED_COMMAND)
    match = re.fullmatch(
        rf'restrict,command="{command}" (ssh-ed25519) ([A-Za-z0-9+/]+={{0,3}})(?: [^\r\n]*)?',
        active[0],
    )
    if match is None:
        raise A0Error("A0_TRANSPORT_KEY_IDENTITY_INVALID")
    key_type, key_data = match.groups()
    key_hash = hashlib.sha256(f"{key_type} {key_data}".encode("ascii")).hexdigest()
    if key_hash != expected_key_sha256:
        raise A0Error("A0_TRANSPORT_KEY_IDENTITY_INVALID")
    return {
        "authorizedKeysInvariant": True,
        "authorizedKeysActiveEntries": 1,
        "sshDirectoryMode": "0700",
        "transportKeyIdentity": "expected",
    }


def _pref_empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _parse_tailscale_status(text: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise A0Error("A0_TAILSCALE_STATUS_INVALID") from exc
    if not isinstance(value, dict):
        raise A0Error("A0_TAILSCALE_STATUS_INVALID")
    if value.get("BackendState") != "Running":
        raise A0Error("A0_TAILSCALE_BACKEND_NOT_RUNNING")
    self_node = value.get("Self")
    if not isinstance(self_node, dict) or self_node.get("Online") is not True:
        raise A0Error("A0_TAILSCALE_SELF_NOT_ONLINE")
    health = value.get("Health")
    if health not in (None, []):
        raise A0Error("A0_TAILSCALE_HEALTH_WARNING")
    return {
        "tailscaleBackend": "Running",
        "tailscaleSelfOnline": True,
        "tailscaleHealthWarnings": 0,
    }


def _parse_tailscale_prefs(text: str) -> dict:
    try:
        prefs = json.loads(text)
    except json.JSONDecodeError as exc:
        raise A0Error("A0_TAILSCALE_PREFS_INVALID") from exc
    if not isinstance(prefs, dict):
        raise A0Error("A0_TAILSCALE_PREFS_INVALID")
    required_bools = {
        "WantRunning": True,
        "RunSSH": False,
        "RouteAll": False,
        "RunWebClient": False,
    }
    for key, expected in required_bools.items():
        if prefs.get(key) is not expected:
            raise A0Error("A0_TAILSCALE_PREFS_DRIFT")
    for key in ("ExitNodeID", "ExitNodeIP", "AutoExitNode", "AdvertiseRoutes", "AdvertiseServices"):
        if key in prefs and not _pref_empty(prefs.get(key)):
            raise A0Error("A0_TAILSCALE_PREFS_DRIFT")
    return {
        "tailscaleSsh": False,
        "tailscaleAcceptRoutes": False,
        "tailscaleExitNodeUse": False,
        "tailscaleAdvertisedRoutes": 0,
        "tailscaleWebClient": False,
    }


def _json_config_empty(text: str) -> bool:
    if not text.strip():
        return True
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise A0Error("A0_TAILSCALE_SERVE_STATUS_INVALID") from exc

    def empty(item: object) -> bool:
        if item is None or item == "":
            return True
        if isinstance(item, dict):
            return len(item) == 0 or all(empty(v) for v in item.values())
        if isinstance(item, list):
            return len(item) == 0 or all(empty(v) for v in item)
        return False

    return empty(value)


def _listener_host(local: str) -> tuple[str, int] | None:
    if ":" not in local:
        return None
    host, port_text = local.rsplit(":", 1)
    if port_text != "22":
        return None
    host = host.strip("[]")
    return host, 22


def _has_nonloopback_tcp22(text: str) -> bool:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        parsed = _listener_host(parts[3])
        if parsed is None:
            continue
        host, _port = parsed
        if host in {"*", "0.0.0.0", "::"}:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        if not address.is_loopback:
            return True
    return False


def _network_snapshot(runner: CommandRunner, expected_host_fingerprint: str) -> dict:
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]+={0,2}", expected_host_fingerprint):
        raise A0Error("A0_EXPECTED_HOST_FINGERPRINT_INVALID")

    sshd_version = _run(runner, ("/usr/sbin/sshd", "-V"), "A0_SSHD_VERSION_UNAVAILABLE")
    if not sshd_version.startswith(EXPECTED_OPENSSH_PREFIX):
        raise A0Error("A0_SSHD_VERSION_DRIFT")
    if _run(runner, ("/usr/bin/systemctl", "is-active", "ssh.service"), "A0_SSH_SERVICE_NOT_ACTIVE") != "active":
        raise A0Error("A0_SSH_SERVICE_NOT_ACTIVE")
    if _run(runner, ("/usr/bin/systemctl", "is-enabled", "ssh.service"), "A0_SSH_SERVICE_NOT_ENABLED") != "enabled":
        raise A0Error("A0_SSH_SERVICE_NOT_ENABLED")
    listeners = _run(runner, ("/usr/bin/ss", "-ltnH"), "A0_TCP_LISTENER_READBACK_FAILED")
    if not _has_nonloopback_tcp22(listeners):
        raise A0Error("A0_TCP22_NOT_NONLOOPBACK")

    manpage = Path("/usr/share/man/man5/authorized_keys.5.gz")
    try:
        if manpage.is_symlink() or not manpage.is_file():
            raise A0Error("A0_AUTHORIZED_KEYS_RESTRICT_DOC_MISSING")
        with gzip.open(manpage, "rt", encoding="utf-8", errors="replace") as handle:
            doc = handle.read()
    except OSError as exc:
        raise A0Error("A0_AUTHORIZED_KEYS_RESTRICT_DOC_MISSING") from exc
    if re.search(r"\brestrict\b", doc) is None:
        raise A0Error("A0_AUTHORIZED_KEYS_RESTRICT_DOC_MISSING")

    host_key = _run(
        runner,
        ("/usr/bin/ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"),
        "A0_HOST_FINGERPRINT_UNAVAILABLE",
    )
    host_fields = host_key.split()
    if len(host_fields) < 2 or host_fields[1] != expected_host_fingerprint:
        raise A0Error("A0_HOST_FINGERPRINT_MISMATCH")

    if _run(runner, ("/usr/bin/systemctl", "is-active", "tailscaled.service"), "A0_TAILSCALED_NOT_ACTIVE") != "active":
        raise A0Error("A0_TAILSCALED_NOT_ACTIVE")
    if _run(runner, ("/usr/bin/systemctl", "is-enabled", "tailscaled.service"), "A0_TAILSCALED_NOT_ENABLED") != "enabled":
        raise A0Error("A0_TAILSCALED_NOT_ENABLED")
    version_text = _run(runner, ("/usr/bin/tailscale", "version"), "A0_TAILSCALE_VERSION_UNAVAILABLE")
    version_line = next((line.strip() for line in version_text.splitlines() if line.strip()), "")
    if version_line != EXPECTED_TAILSCALE_VERSION:
        raise A0Error("A0_TAILSCALE_VERSION_DRIFT")

    status = _parse_tailscale_status(
        _run(runner, ("/usr/bin/tailscale", "status", "--json"), "A0_TAILSCALE_STATUS_FAILED")
    )
    prefs = _parse_tailscale_prefs(
        _run(runner, ("/usr/bin/tailscale", "debug", "prefs"), "A0_TAILSCALE_PREFS_FAILED")
    )
    serve = _run(
        runner,
        ("/usr/bin/tailscale", "serve", "status", "--json"),
        "A0_TAILSCALE_SERVE_STATUS_FAILED",
    )
    if not _json_config_empty(serve):
        raise A0Error("A0_TAILSCALE_SERVE_OR_FUNNEL_CONFIGURED")

    return {
        "openSshVersion": EXPECTED_OPENSSH_PREFIX,
        "sshServiceActive": True,
        "sshServiceEnabled": True,
        "tcp22Listening": True,
        "tcp22NonLoopbackListening": True,
        "authorizedKeysRestrictSemantics": True,
        "hostFingerprintInvariant": True,
        "tailscaleVersion": EXPECTED_TAILSCALE_VERSION,
        "tailscaledActive": True,
        "tailscaledEnabled": True,
        **status,
        **prefs,
        "tailscaleServeOrFunnelConfigured": False,
    }


def _qemu_snapshot(runner: CommandRunner, proc_root: Path = PROC_ROOT) -> dict:
    output = _run(runner, ("/usr/bin/ps", "-eo", "pid=,comm=,args="), "A0_PROCESS_ENUMERATION_FAILED")
    pids = _qemu_process_ids_from_ps(output)
    kvm_pids = _kvm_fd_pids(proc_root)
    if pids or kvm_pids:
        raise A0Error("A0_QEMU_PROCESS_PRESENT")
    return {"qemuProcessCount": 0, "kvmFdProcessCount": 0}


def _publication_state(home: Path, uid: int) -> dict:
    for path, classification in (
        (TRANSACTION_PATH, "A0_INSTALL_TRANSACTION_PRESENT"),
        (RECEIPT_PATH, "A0_INSTALL_RECEIPT_PRESENT"),
    ):
        _assert_path_chain(home, path, uid)
        if path.exists() or path.is_symlink():
            raise A0Error(classification)
    return {"installTransactionPending": False, "installReceiptPresent": False}


def _collect_once(
    *,
    home: Path,
    uid: int,
    runner: CommandRunner,
    expected_local_alias: str,
    expected_host_fingerprint: str,
    expected_transport_key_sha256: str,
    proc_root: Path = PROC_ROOT,
) -> dict:
    alias = socket.gethostname().split(".", 1)[0].lower()
    if expected_local_alias not in ACCEPTED_LOCAL_ALIASES:
        raise A0Error("A0_EXPECTED_LOCAL_HOST_IDENTITY_INVALID")
    if alias != expected_local_alias:
        raise A0Error("A0_LOCAL_HOST_IDENTITY_MISMATCH")
    return {
        "schema": 2,
        "marker": MARKER,
        "localHostAlias": alias,
        **_validate_jit_state(home, uid),
        **_qemu_snapshot(runner, proc_root),
        **_publication_state(home, uid),
        **_transport_files(home, uid),
        **_transport_authorized_key(home, uid, expected_transport_key_sha256),
        **_network_snapshot(runner, expected_host_fingerprint),
    }


def collect_a0(
    *,
    home: Path,
    uid: int,
    runner: CommandRunner,
    expected_local_alias: str,
    expected_host_fingerprint: str,
    expected_transport_key_sha256: str,
    proc_root: Path = PROC_ROOT,
) -> dict:
    home = _assert_home(home, uid)
    first = _collect_once(
        home=home,
        uid=uid,
        runner=runner,
        expected_local_alias=expected_local_alias,
        expected_host_fingerprint=expected_host_fingerprint,
        expected_transport_key_sha256=expected_transport_key_sha256,
        proc_root=proc_root,
    )
    second = _collect_once(
        home=home,
        uid=uid,
        runner=runner,
        expected_local_alias=expected_local_alias,
        expected_host_fingerprint=expected_host_fingerprint,
        expected_transport_key_sha256=expected_transport_key_sha256,
        proc_root=proc_root,
    )
    if first != second:
        raise A0Error("A0_SNAPSHOT_CHANGED_DURING_READBACK")
    snapshot_sha = hashlib.sha256(_canonical(second)).hexdigest()
    generated_at = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return {
        **second,
        "stabilityPasses": 2,
        "snapshotSha256": snapshot_sha,
        "generatedAt": generated_at,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone read-only REDRIX Gate A0 evidence")
    parser.add_argument("--expected-local-alias", required=True, choices=sorted(ACCEPTED_LOCAL_ALIASES))
    parser.add_argument("--expected-host-fingerprint", required=True)
    parser.add_argument("--expected-transport-key-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux":
            raise A0Error("A0_LINUX_REQUIRED")
        if os.geteuid() != PRODUCTION_UID or Path.home() != PRODUCTION_HOME:
            raise A0Error("A0_OWNER_IDENTITY_INVALID")
        evidence = collect_a0(
            home=PRODUCTION_HOME,
            uid=PRODUCTION_UID,
            runner=_default_runner,
            expected_local_alias=args.expected_local_alias,
            expected_host_fingerprint=args.expected_host_fingerprint,
            expected_transport_key_sha256=args.expected_transport_key_sha256,
        )
        print("DRAGONFLY_GATE_A0=PASS")
        print("EVIDENCE_JSON=" + json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    except (A0Error, OSError, ValueError, json.JSONDecodeError) as exc:
        code = str(exc)
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", code) is None:
            code = "A0_READBACK_FAILED"
        print("DRAGONFLY_GATE_A0=HOLD")
        print("CLASSIFICATION=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
