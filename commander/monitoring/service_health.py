"""LDW services -> Host Agent: read-only OS-manager health projection.

SOURCE-ONLY proof. No control/repair, daemon, network listener, privileged
helper, ChatGPT plugin or Host Agent runtime registration.

The source of evidence is the local operating-system service manager, not a
health value asserted by the monitored service. Only a trusted local registry
can choose service names. No command strings, shell, or remote probes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
import os
import re
import subprocess
from typing import Callable

CONTRACT = "ldw.service-status.v1"
MAX_SERVICES = 32
MAX_AGE_SECONDS = 30
MAX_FUTURE_SKEW_SECONDS = 5
PROBE_TIMEOUT_SECONDS = 2
SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
MANAGER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.@-]{0,79}$")


class Expected(str, Enum):
    RUNNING = "RUNNING"
    ON_DEMAND = "ON_DEMAND"
    DISABLED = "DISABLED"


class Observed(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


class Health(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class Manager(str, Enum):
    WINDOWS_SCM = "WINDOWS_SCM"
    LINUX_SYSTEMD = "LINUX_SYSTEMD"


class ServiceMonitorError(ValueError):
    pass


@dataclass(frozen=True)
class ServiceDefinition:
    service_id: str
    manager_name: str
    manager: Manager
    desired: Expected
    required: bool = True

    def __post_init__(self):
        if not isinstance(self.service_id, str) or not SERVICE_ID.fullmatch(self.service_id):
            raise ServiceMonitorError("INVALID_SERVICE_ID")
        if not isinstance(self.manager_name, str) or not MANAGER_NAME.fullmatch(self.manager_name):
            raise ServiceMonitorError("INVALID_MANAGER_NAME")
        if not isinstance(self.manager, Manager) or not isinstance(self.desired, Expected):
            raise ServiceMonitorError("INVALID_SERVICE_DEFINITION")
        if not isinstance(self.required, bool):
            raise ServiceMonitorError("INVALID_REQUIRED")


@dataclass(frozen=True)
class ServiceObservation:
    service_id: str
    manager: Manager
    desired: Expected
    required: bool
    observed: Observed
    health: Health
    evidence_code: str
    observed_at: datetime

    def to_wire(self) -> dict:
        """Sanitized, versioned observation; no path, user, host, PID or raw logs."""
        if self.observed_at.tzinfo is None:
            raise ServiceMonitorError("NAIVE_TIMESTAMP")
        at_utc = self.observed_at.astimezone(timezone.utc)
        return {
            "contract": CONTRACT,
            "service_id": self.service_id,
            "manager": self.manager.value,
            "desired_state": self.desired.value,
            "required": self.required,
            "observed_state": self.observed.value,
            "health_state": self.health.value,
            "observed_at_utc": at_utc.isoformat().replace("+00:00", "Z"),
            "evidence_code": self.evidence_code,
        }


def evaluate(definition: ServiceDefinition, observed: Observed) -> Health:
    if not isinstance(observed, Observed):
        raise ServiceMonitorError("INVALID_OBSERVED_STATE")
    if observed == Observed.UNKNOWN:
        return Health.UNKNOWN
    if observed == Observed.ABSENT:
        if definition.desired == Expected.ON_DEMAND:
            return Health.UNKNOWN  # not installed is NOT a healthy on-demand instance
        return Health.FAILED if definition.required else Health.DEGRADED
    expected = (
        observed == Observed.RUNNING
        if definition.desired == Expected.RUNNING
        else observed == Observed.STOPPED if definition.desired == Expected.DISABLED
        else observed in (Observed.RUNNING, Observed.STOPPED)
    )
    if expected:
        return Health.HEALTHY
    return Health.FAILED if definition.required else Health.DEGRADED


def age_guard(observation: ServiceObservation, now: datetime) -> ServiceObservation:
    """Freshness override cannot fabricate healthy/failure from old evidence."""
    if now.tzinfo is None or observation.observed_at.tzinfo is None:
        raise ServiceMonitorError("NAIVE_TIMESTAMP")
    age = (now - observation.observed_at).total_seconds()
    if not (-MAX_FUTURE_SKEW_SECONDS <= age <= MAX_AGE_SECONDS):
        return ServiceObservation(
            observation.service_id, observation.manager, observation.desired,
            observation.required, Observed.UNKNOWN, Health.UNKNOWN,
            "STALE_OR_CLOCK_UNTRUSTED", observation.observed_at
        )
    return observation


def _default_run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    # The unprivileged observer is separate from the service being monitored.
    # No shell, username, secrets, token, network address or command from a model.
    environment = {"PYTHONNOUSERSITE": "1"}
    if os.name == "nt":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        environment["SystemRoot"] = root
    return subprocess.run(
        args, shell=False, check=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        env=environment, timeout=timeout,
    )


def parse_systemd(result: subprocess.CompletedProcess) -> tuple[Observed, str]:
    out = result.stdout[:256].decode("utf-8", errors="replace").strip().lower()
    if result.returncode == 0 and out == "active":
        return Observed.RUNNING, "SYSTEMD_ACTIVE"
    if result.returncode == 3 and out in ("inactive", "failed", "deactivating"):
        return Observed.STOPPED, "SYSTEMD_NOT_ACTIVE"
    # unknown, not-found, DBus outage and malformed errors are NOT confirmed down
    return Observed.UNKNOWN, "SYSTEMD_UNVERIFIED"


_WINDOWS_STATE = re.compile(
    r"^\s*STATE\s*:\s*(?P<code>[1-4])\s+(?P<word>STOPPED|START_PENDING|STOP_PENDING|RUNNING)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_windows_scm(result: subprocess.CompletedProcess) -> tuple[Observed, str]:
    out = result.stdout[:2048].decode("utf-8", errors="replace")
    if result.returncode == 0:
        match = _WINDOWS_STATE.search(out.replace("\r", ""))
        if match:
            state = (match.group("code"), match.group("word").upper())
            if state == ("4", "RUNNING"):
                return Observed.RUNNING, "SCM_RUNNING"
            if state == ("1", "STOPPED"):
                return Observed.STOPPED, "SCM_STOPPED"
    # Error 1060 means the service does not exist; do not parse arbitrary
    # localized stderr for an unsafe positive signal.
    return Observed.UNKNOWN, "SCM_UNVERIFIED"


class LocalServiceObserver:
    def __init__(
        self,
        definitions: tuple[ServiceDefinition, ...],
        platform: str,
        runner: Callable[[list[str], int], subprocess.CompletedProcess] = _default_run,
    ):
        if not isinstance(definitions, tuple) or len(definitions) > MAX_SERVICES:
            raise ServiceMonitorError("INVALID_REGISTRY")
        if len({d.service_id for d in definitions}) != len(definitions):
            raise ServiceMonitorError("DUPLICATE_SERVICE")
        if platform not in ("windows", "linux"):
            raise ServiceMonitorError("INVALID_PLATFORM")
        self._definitions = {d.service_id: d for d in definitions}
        self._platform = platform
        self._runner = runner

    def observe(self, service_id: str, now: datetime | None = None) -> ServiceObservation:
        definition = self._definitions.get(service_id)
        if definition is None:
            raise ServiceMonitorError("SERVICE_NOT_REGISTERED")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ServiceMonitorError("NAIVE_TIMESTAMP")
        if (definition.manager == Manager.WINDOWS_SCM) != (self._platform == "windows"):
            observed, evidence = Observed.UNKNOWN, "MANAGER_NOT_ON_THIS_HOST"
        else:
            if self._platform == "linux":
                args = ["/usr/bin/systemctl", "--system", "is-active", "--", definition.manager_name]
            else:
                system_root = os.environ.get("SystemRoot", r"C:\Windows")
                # Do not allow a caller to supply an arbitrary executable path.
                args = [os.path.join(system_root, "System32", "sc.exe"),
                        "query", definition.manager_name]
            try:
                result = self._runner(args, PROBE_TIMEOUT_SECONDS)
                if not isinstance(result, subprocess.CompletedProcess):
                    raise TypeError("unsupported probe result")
                observed, evidence = (
                    parse_systemd(result) if self._platform == "linux"
                    else parse_windows_scm(result)
                )
            except (OSError, subprocess.TimeoutExpired, TypeError, ValueError):
                observed, evidence = Observed.UNKNOWN, "PROBE_UNAVAILABLE"
        item = ServiceObservation(
            definition.service_id, definition.manager, definition.desired,
            definition.required, observed, evaluate(definition, observed), evidence, now
        )
        return age_guard(item, datetime.now(timezone.utc))
