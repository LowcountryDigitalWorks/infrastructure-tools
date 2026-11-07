"""Read-only process/FD preflight for a future REDRIX A4 protected launcher (#139).

DATA-ONLY / NON-AUTHORIZING. This module is not a launcher, root tool, or
privileged channel. It has no CLI, no entrypoint, and it does not select a
proc root, command, or path. A later reviewed launcher may call
``collect_fd_preflight`` with an injected ``ProcPort`` and, when it has
actually measured kernel state, an injected ``PrivilegePort``.

Caller dictionaries, path strings, and ``claims_receiver_authenticated`` cannot
attest root, namespaces, or capabilities. A clean synthetic result stays
``DATA_ONLY_NOT_AUTHORIZED``. This module never sets ``a4Pass``,
``runtimeAuthority``, or ``privilegedChannelAuthenticated`` true.

Process identity, UID quartet, start-time reuse, FD denial, QEMU, and
``/dev/kvm`` decisions are delegated to the accepted FD inspector core. The
fingerprint reads file descriptors only for effective UID 1000, matching that
core, while the core still detects QEMU across every visible UID. The nonce
set is supplied by the future launcher; this module does not store replay
state and cannot prove that set is complete. A class rename or a substituted
``sys.modules`` entry is not package authentication.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import importlib.util
from pathlib import Path
import re
import sys
from typing import Optional, Protocol

MARKER = "DRAGONFLY_GATE_A4_FD_PREFLIGHT_V1"
_REASON = re.compile(r"A4_(PF|FD)_[A-Z0-9_]+")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PORT_METHODS = ("list_numeric_pids", "read_stat_line", "read_status_text", "list_fd_targets")
_REFUSED_PORT_TYPES = {
    "str",
    "bytes",
    "bytearray",
    "dict",
    "list",
    "tuple",
    "set",
    "Path",
    "PosixPath",
    "WindowsPath",
    "LinuxProcPort",
}


class PrivilegePort(Protocol):
    def read_privilege(self) -> "PrivilegeSnapshot": ...


@dataclass(frozen=True)
class PrivilegeSnapshot:
    """Measured privilege view. Constructing this value is not attestation."""

    kernel_measured: bool
    euid: int
    cap_sys_ptrace: bool
    cap_dac_read_search: bool
    user_namespace: str
    pid_namespace: str
    target_user_namespace: str
    target_pid_namespace: str
    read_scope_complete: bool
    correlation: str
    nonce: str
    claims_receiver_authenticated: bool


class _Refusal(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def hold(reason: str) -> dict[str, object]:
    if not _REASON.fullmatch(reason):
        reason = "A4_PF_PROCESS_VISIBILITY_UNCERTAIN"
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "HOLD",
        "reasonCode": reason,
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "complementaryA0QemuEnumerationRequired": True,
        "preflightConsistent": False,
    }


def _data_only(core: dict[str, object], *, consistent: bool) -> dict[str, object]:
    return {
        "schema": 1,
        "marker": MARKER,
        "classification": "DATA_ONLY_NOT_AUTHORIZED",
        "reasonCode": "EXTERNAL_TRUST_GATES_REQUIRED",
        "runtimeAuthority": False,
        "a4Pass": False,
        "privilegedChannelAuthenticated": False,
        "complementaryA0QemuEnumerationRequired": True,
        "preflightConsistent": consistent,
        "stabilityPasses": 2,
        "sameUidProcessCount": core.get("sameUidProcessCount"),
        "kvmFdProcessCount": core.get("kvmFdProcessCount"),
        "qemuLikeProcessCount": core.get("qemuLikeProcessCount"),
        "allUidQemuProcessCount": core.get("allUidQemuProcessCount"),
    }


def _token(value: object) -> bool:
    return isinstance(value, str) and _TOKEN.fullmatch(value) is not None


def _snapshot_shape(value: object) -> Optional[PrivilegeSnapshot]:
    if type(value) is not PrivilegeSnapshot:
        return None
    if (
        type(value.kernel_measured) is not bool
        or type(value.euid) is not int
        or value.euid < 0
        or type(value.cap_sys_ptrace) is not bool
        or type(value.cap_dac_read_search) is not bool
        or type(value.read_scope_complete) is not bool
        or type(value.claims_receiver_authenticated) is not bool
    ):
        return None
    if not all(
        _token(item)
        for item in (
            value.user_namespace,
            value.pid_namespace,
            value.target_user_namespace,
            value.target_pid_namespace,
            value.correlation,
            value.nonce,
        )
    ):
        return None
    return value


def _type_name(value: object) -> Optional[str]:
    try:
        name = type(value).__name__
    except Exception:
        return None
    if type(name) is not str:
        return None
    return name


def _lookup(value: object, name: str) -> tuple[str, object]:
    """Return found, missing, or error. Only a thrown property is an error."""
    try:
        return "found", getattr(value, name)
    except AttributeError:
        return "missing", None
    except Exception:
        return "error", None


def _refuse_port(port: object) -> Optional[dict[str, object]]:
    if isinstance(port, (str, bytes, dict, list, tuple)):
        return hold("A4_PF_CALLER_SELECTED_ROOT")
    name = _type_name(port)
    if name is None:
        return hold("A4_PF_PORT_REFUSED")
    if name in _REFUSED_PORT_TYPES:
        return hold("A4_PF_CALLER_SELECTED_ROOT")
    state, proc_root = _lookup(port, "_proc_root")
    if state == "error":
        return hold("A4_PF_PORT_REFUSED")
    if state == "found" and proc_root is not None:
        return hold("A4_PF_CALLER_SELECTED_ROOT")
    for method in _PORT_METHODS:
        state, attr = _lookup(port, method)
        if state != "found" or not callable(attr):
            return hold("A4_PF_PORT_REFUSED")
    return None


def _refuse_privilege(privilege: object) -> Optional[dict[str, object]]:
    if privilege is None:
        return None
    if isinstance(privilege, (str, bytes, dict, list, tuple, set)):
        return hold("A4_PF_UNTRUSTED_ATTESTATION")
    name = _type_name(privilege)
    if name is None or name in _REFUSED_PORT_TYPES:
        return hold("A4_PF_UNTRUSTED_ATTESTATION")
    state, reader = _lookup(privilege, "read_privilege")
    if state == "error":
        return hold("A4_PF_UNTRUSTED_ATTESTATION")
    if state != "found" or not callable(reader):
        return hold("A4_PF_PORT_REFUSED")
    return None


def _map_os(exc: OSError, *, privilege: bool) -> str:
    if exc.errno in (errno.EACCES, errno.EPERM):
        return "A4_PF_PRIVILEGE_DENIED" if privilege else "A4_PF_FD_DENIED"
    return "A4_PF_PRIVILEGE_UNREADABLE" if privilege else "A4_PF_FD_UNREADABLE"


def _read_privilege(privilege: PrivilegePort) -> PrivilegeSnapshot:
    try:
        snapshot = privilege.read_privilege()
    except OSError as exc:
        raise _Refusal(_map_os(exc, privilege=True)) from exc
    except _Refusal:
        raise
    except Exception as exc:
        raise _Refusal("A4_PF_PRIVILEGE_UNREADABLE") from exc
    parsed = _snapshot_shape(snapshot)
    if parsed is None:
        raise _Refusal("A4_PF_UNTRUSTED_ATTESTATION")
    return parsed


def _privilege_reason(snapshot: PrivilegeSnapshot, seen_nonces: frozenset[str]) -> Optional[str]:
    if snapshot.claims_receiver_authenticated:
        return "A4_PF_FALSE_RECEIVER_AUTH"
    if snapshot.nonce in seen_nonces:
        return "A4_PF_REPLAY"
    claimed = snapshot.euid == 0 or snapshot.cap_sys_ptrace or snapshot.cap_dac_read_search
    if not snapshot.kernel_measured:
        return "A4_PF_UNPROVEN_PRIVILEGE" if claimed else "A4_PF_PRIVILEGE_NOT_PROVABLE"
    if not (snapshot.cap_sys_ptrace and snapshot.cap_dac_read_search):
        return "A4_PF_PRIVILEGE_NOT_PROVABLE"
    if snapshot.user_namespace != snapshot.target_user_namespace:
        return "A4_PF_USER_NAMESPACE_MISMATCH"
    if snapshot.pid_namespace != snapshot.target_pid_namespace:
        return "A4_PF_PID_NAMESPACE_MISMATCH"
    if not snapshot.read_scope_complete:
        return "A4_PF_READ_SCOPE_INCOMPLETE"
    return None


def _snapshot_drift(before: PrivilegeSnapshot, after: PrivilegeSnapshot) -> Optional[str]:
    if before.correlation != after.correlation or before.nonce != after.nonce:
        return "A4_PF_CORRELATION_MISMATCH"
    same = (
        before.kernel_measured == after.kernel_measured
        and before.euid == after.euid
        and before.cap_sys_ptrace == after.cap_sys_ptrace
        and before.cap_dac_read_search == after.cap_dac_read_search
        and before.user_namespace == after.user_namespace
        and before.pid_namespace == after.pid_namespace
        and before.target_user_namespace == after.target_user_namespace
        and before.target_pid_namespace == after.target_pid_namespace
        and before.read_scope_complete == after.read_scope_complete
        and before.claims_receiver_authenticated == after.claims_receiver_authenticated
    )
    if not same:
        return "A4_PF_TWO_SNAPSHOT_INCONSISTENT"
    return None


def _core_path() -> Path:
    return Path(__file__).resolve().with_name("dragonfly_gate_a4_fd_inspector_core.py")


def _path_matches(candidate: object, expected: Path) -> bool:
    if type(candidate) is not str or not candidate:
        return False
    try:
        return Path(candidate).resolve() == expected
    except (OSError, RuntimeError, ValueError):
        return False


def _accepted_core():
    """Load the sibling core. A pre-seeded or swapped cache entry is refused."""
    path = _core_path()
    name = "_ldw_a4_fd_preflight_core"
    module = sys.modules.get(name)
    if module is not None:
        found, module_file = _lookup(module, "__file__")
        if found != "found" or not _path_matches(module_file, path):
            raise _Refusal("A4_PF_CORE_REFUSED")
    if module is None:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise _Refusal("A4_PF_CORE_REFUSED")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        found, module_file = _lookup(module, "__file__")
        if found != "found" or not _path_matches(module_file, path):
            raise _Refusal("A4_PF_CORE_REFUSED")
    try:
        inspect = vars(module).get("inspect_stable")
        code = getattr(inspect, "__code__", None)
        filename = getattr(code, "co_filename", None)
    except Exception as exc:
        raise _Refusal("A4_PF_CORE_REFUSED") from exc
    if not callable(inspect) or not _path_matches(filename, path):
        raise _Refusal("A4_PF_CORE_REFUSED")
    return module


def _accepted_inspect_stable():
    return _accepted_core().inspect_stable


def _reason_from_error(exc: Exception) -> str:
    if isinstance(exc, OSError):
        return _map_os(exc, privilege=False)
    code = exc.args[0] if exc.args and type(exc.args[0]) is str else None
    if code is not None and _REASON.fullmatch(code):
        return code
    return "A4_PF_SCOPE_AMBIGUOUS"


def _scope_identity(port: object, pid: int, core: object) -> tuple:
    error_type = core.FdInspectorError
    try:
        stat_line = port.read_stat_line(pid)
        status_text = port.read_status_text(pid)
    except OSError as exc:
        raise _Refusal(_map_os(exc, privilege=False)) from exc
    except error_type as exc:
        raise _Refusal(_reason_from_error(exc)) from exc
    try:
        parsed_pid, _comm, _utime, starttime = core.parse_proc_stat(stat_line)
        quartet = core.parse_proc_status_uids(status_text)
    except error_type as exc:
        raise _Refusal("A4_PF_SCOPE_AMBIGUOUS") from exc
    if parsed_pid != pid or len(quartet) != 4:
        raise _Refusal("A4_PF_IDENTITY_DRIFT")
    return (parsed_pid, starttime, quartet)


def _fingerprint(port: object) -> tuple:
    core = _accepted_core()
    try:
        pids = port.list_numeric_pids()
    except (OSError, core.FdInspectorError) as exc:
        raise _Refusal(_reason_from_error(exc)) from exc
    if not isinstance(pids, list) or any(type(pid) is not int or pid <= 0 for pid in pids):
        raise _Refusal("A4_PF_MALFORMED_ENUMERATION")
    if len(pids) != len(set(pids)):
        raise _Refusal("A4_PF_DUPLICATE_PID")
    rows = []
    for pid in pids:
        before = _scope_identity(port, pid, core)
        effective_uid = before[2][1]
        fd_targets: Optional[tuple[str, ...]] = None
        if effective_uid == core.DEFAULT_UID:
            try:
                targets = port.list_fd_targets(pid)
            except (OSError, core.FdInspectorError) as exc:
                raise _Refusal(_reason_from_error(exc)) from exc
            if not isinstance(targets, list) or any(type(item) is not str for item in targets):
                raise _Refusal("A4_PF_MALFORMED_ENUMERATION")
            after = _scope_identity(port, pid, core)
            if after != before:
                raise _Refusal("A4_PF_IDENTITY_DRIFT")
            fd_targets = tuple(sorted(targets))
        rows.append((pid, before, fd_targets))
    rows.sort(key=lambda item: item[0])
    return tuple(rows)


def _core_result(port: object) -> dict[str, object]:
    try:
        result = _accepted_inspect_stable()(port)
    except Exception as exc:
        raise _Refusal("A4_PF_CORE_REFUSED") from exc
    if not isinstance(result, dict):
        raise _Refusal("A4_PF_CORE_REFUSED")
    if (
        result.get("a4Pass") is True
        or result.get("runtimeAuthority") is True
        or result.get("privilegedChannelAuthenticated") is True
    ):
        raise _Refusal("A4_PF_CORE_REFUSED")
    classification = result.get("classification")
    if classification == "HOLD":
        reason = result.get("reasonCode")
        if not isinstance(reason, str):
            raise _Refusal("A4_PF_CORE_REFUSED")
        raise _Refusal(reason)
    if classification != "DATA_ONLY_NOT_AUTHORIZED":
        raise _Refusal("A4_PF_CORE_REFUSED")
    return result


def collect_fd_preflight(
    port: object,
    privilege: object = None,
    *,
    seen_nonces: object = frozenset(),
) -> dict[str, object]:
    """Collect one fail-closed preflight envelope. Never an A4 pass."""
    refused = _refuse_port(port)
    if refused is not None:
        return refused
    refused = _refuse_privilege(privilege)
    if refused is not None:
        return refused
    if not isinstance(seen_nonces, frozenset) or any(type(item) is not str for item in seen_nonces):
        return hold("A4_PF_UNTRUSTED_ATTESTATION")
    try:
        first: Optional[PrivilegeSnapshot] = None
        if privilege is not None:
            first = _read_privilege(privilege)
            reason = _privilege_reason(first, seen_nonces)
            if reason is not None:
                return hold(reason)
        before_refusal: Optional[_Refusal] = None
        try:
            before = _fingerprint(port)
        except _Refusal as exc:
            before_refusal = exc
            before = None
        core = _core_result(port)
        if before_refusal is not None:
            return hold(before_refusal.reason)
        after = _fingerprint(port)
        if before != after:
            return hold("A4_PF_FD_DRIFT")
        if first is not None:
            second = _read_privilege(privilege)
            drift = _snapshot_drift(first, second)
            if drift is not None:
                return hold(drift)
            reason = _privilege_reason(second, seen_nonces)
            if reason is not None:
                return hold(reason)
        return _data_only(core, consistent=first is not None)
    except _Refusal as exc:
        return hold(exc.reason)
