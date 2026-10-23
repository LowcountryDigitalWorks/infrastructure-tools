#!/usr/bin/env python3
"""Small, dependency-free, read-only LAN health sentinel."""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import enum
import errno
import ipaddress
import json
import logging
import os
import re
import queue
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Mapping


MAX_TARGETS = 64
MAX_STATE_BYTES = 64 * 1024
MAX_TIMEOUT = 5.0
MIN_EPOCH = 1_577_836_800  # 2020-01-01 UTC; a coarse unsynchronized-clock guard.
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$")
RESERVED_TARGET_IDS = frozenset({"monitor", "github_runner_job_state"})


class Health(str, enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNREACHABLE = "UNREACHABLE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    PARENT_UNREACHABLE = "PARENT_UNREACHABLE"
    MONITOR_NETWORK_DEGRADED = "MONITOR_NETWORK_DEGRADED"
    NOT_COLLECTED = "NOT_COLLECTED"


class Reason(str, enum.Enum):
    OK = "OK"
    SUSPECT_FAILURE = "SUSPECT_FAILURE"
    CONNECT_FAILED = "CONNECT_FAILED"
    CONNECT_REFUSED = "CONNECT_REFUSED"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    PROBE_INCONCLUSIVE = "PROBE_INCONCLUSIVE"
    RESOLUTION_FAILED = "RESOLUTION_FAILED"
    ADDRESS_OUTSIDE_MONITOR_NETWORK = "ADDRESS_OUTSIDE_MONITOR_NETWORK"
    GATEWAY_UNAVAILABLE = "GATEWAY_UNAVAILABLE"
    PARENT_UNAVAILABLE = "PARENT_UNAVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    STATE_MISSING = "STATE_MISSING"
    STATE_CORRUPT = "STATE_CORRUPT"
    CONFIG_INVALID = "CONFIG_INVALID"
    CLOCK_UNSYNCHRONIZED = "CLOCK_UNSYNCHRONIZED"


@dataclasses.dataclass(frozen=True)
class Target:
    target_id: str
    kind: str
    address: str
    port: int
    parent: str | None = None


@dataclasses.dataclass(frozen=True)
class Config:
    monitor_id: str
    gateway: str
    gateway_port: int
    monitor_cidr: str
    poll_interval: int
    timeout: float
    failure_threshold: int
    recovery_threshold: int
    state_file: Path
    targets: tuple[Target, ...]


@dataclasses.dataclass
class Track:
    state: Health = Health.UNKNOWN
    reason: Reason = Reason.STATE_MISSING
    failures: int = 0
    successes: int = 0


@dataclasses.dataclass(frozen=True)
class Result:
    reachable: bool | None
    reason: Reason


@dataclasses.dataclass(frozen=True)
class Transition:
    target_id: str
    observation_class: str
    state: Health
    reason: Reason
    observed_at: str | None
    transition_at: str | None
    clock_quality: str
    monitor_id: str
    sequence: int
    source: str = "pi-sentinel"


def _required_string(value: object, name: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"{name} must be a non-empty string of at most 253 characters")
    if pattern and not pattern.fullmatch(value):
        raise ValueError(f"{name} has an invalid format")
    return value


def load_config(path: str | Path) -> Config:
    """Load and strictly validate secret-free JSON configuration."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {
        "monitor_id", "gateway", "gateway_port", "monitor_cidr", "poll_interval", "timeout",
        "failure_threshold", "recovery_threshold", "state_file", "targets",
    }:
        raise ValueError("configuration keys do not match the supported schema")
    monitor_id = _required_string(raw["monitor_id"], "monitor_id", pattern=ID_RE)
    gateway = _required_string(raw["gateway"], "gateway")
    try:
        gateway_ip = ipaddress.ip_address(gateway)
        network = ipaddress.ip_network(raw["monitor_cidr"], strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError("gateway and monitor_cidr must be valid IP configuration") from exc
    if not gateway_ip.is_private or gateway_ip not in network:
        raise ValueError("gateway must be private and inside monitor_cidr")
    if not network.is_private:
        raise ValueError("monitor_cidr must be a private network")
    gateway_port = raw["gateway_port"]
    if type(gateway_port) is not int or not 1 <= gateway_port <= 65535:
        raise ValueError("gateway_port must be an integer from 1 to 65535")
    interval = raw["poll_interval"]
    timeout = raw["timeout"]
    failure = raw["failure_threshold"]
    recovery = raw["recovery_threshold"]
    if type(interval) is not int or not 10 <= interval <= 3600:
        raise ValueError("poll_interval must be an integer from 10 to 3600 seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError("timeout must be greater than zero and at most five seconds")
    if type(failure) is not int or not 1 <= failure <= 10:
        raise ValueError("failure_threshold must be an integer from 1 to 10")
    if type(recovery) is not int or not 1 <= recovery <= 10:
        raise ValueError("recovery_threshold must be an integer from 1 to 10")
    state_file = Path(_required_string(raw["state_file"], "state_file"))
    if state_file != Path("/var/lib/ldw-sentinel/state.json"):
        raise ValueError("state_file must be /var/lib/ldw-sentinel/state.json")
    if not isinstance(raw["targets"], list) or len(raw["targets"]) > MAX_TARGETS:
        raise ValueError(f"targets must be a list of at most {MAX_TARGETS} entries")
    targets: list[Target] = []
    ids: set[str] = set()
    for item in raw["targets"]:
        if not isinstance(item, dict) or set(item) - {"id", "kind", "address", "port", "parent"}:
            raise ValueError("target has unsupported fields")
        target_id = _required_string(item.get("id"), "target id", pattern=ID_RE)
        if target_id in RESERVED_TARGET_IDS:
            raise ValueError("target id is reserved for a synthetic health dimension")
        if target_id in ids:
            raise ValueError("target ids must be unique")
        ids.add(target_id)
        kind = item.get("kind")
        if kind not in {"host", "tcp"}:
            raise ValueError("target kind must be host or tcp")
        address = _required_string(item.get("address"), "target address")
        if not HOST_RE.fullmatch(address):
            raise ValueError("target address must be a hostname or IP literal")
        port = item.get("port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("target port must be an integer from 1 to 65535")
        parent = item.get("parent")
        if parent is not None and (not isinstance(parent, str) or not ID_RE.fullmatch(parent)):
            raise ValueError("parent must be a logical target id")
        targets.append(Target(target_id, kind, address, port, parent))
    if any(t.parent and t.parent not in ids for t in targets):
        raise ValueError("each parent must name a configured target")
    if any(t.parent == t.target_id for t in targets):
        raise ValueError("a target cannot depend on itself")
    parents = {t.target_id: t.parent for t in targets}
    for target_id in ids:
        seen: set[str] = set()
        cursor: str | None = target_id
        while cursor is not None:
            if cursor in seen:
                raise ValueError("parent dependency graph must be acyclic")
            seen.add(cursor)
            cursor = parents[cursor]
    return Config(monitor_id, gateway, gateway_port, str(network), interval, float(timeout), failure,
                  recovery, state_file, tuple(targets))


def wall_clock(synchronized_marker: str | Path = "/run/systemd/timesync/synchronized") -> tuple[str | None, str]:
    """Return wall time only after systemd-timesyncd has marked this boot synchronized."""
    now = time.time()
    if now < MIN_EPOCH or not Path(synchronized_marker).is_file():
        return None, "UNSYNCHRONIZED"
    return dt.datetime.fromtimestamp(now, dt.timezone.utc).isoformat(timespec="seconds"), "PLAUSIBLE"


_RESOLVER_SLOTS = threading.BoundedSemaphore(4)


def _resolve(address: str, port: int, timeout: float) -> list[tuple[int, tuple]]:
    """Bound blocking system DNS with a fixed number of daemon resolver threads."""
    if not _RESOLVER_SLOTS.acquire(blocking=False):
        return []
    answer: queue.Queue[object] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            value: object = socket.getaddrinfo(address, port, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            value = None
        finally:
            _RESOLVER_SLOTS.release()
        try:
            answer.put_nowait(value)
        except queue.Full:
            pass

    threading.Thread(target=lookup, name="ldw-sentinel-dns", daemon=True).start()
    try:
        results = answer.get(timeout=timeout)
    except queue.Empty:
        return []
    if not isinstance(results, list):
        return []
    return [(family, sockaddr) for family, _, _, _, sockaddr in results if family in (socket.AF_INET, socket.AF_INET6)]


def tcp_probe(address: str, port: int, timeout: float, network: str) -> Result:
    """Perform one bounded TCP probe after enforcing an on-link private-network guard."""
    try:
        allowed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return Result(None, Reason.CONFIG_INVALID)
    resolved = _resolve(address, port, timeout)
    if not resolved:
        return Result(None, Reason.RESOLUTION_FAILED)
    ips: list[ipaddress._BaseAddress] = []
    for family, sockaddr in resolved:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return Result(None, Reason.RESOLUTION_FAILED)
        if not ip.is_private or ip not in allowed:
            return Result(None, Reason.ADDRESS_OUTSIDE_MONITOR_NETWORK)
        ips.append(ip)
    deadline = time.monotonic() + timeout
    refused = False
    timed_out = False
    other_error = False
    for (family, sockaddr), _ip in zip(resolved, ips):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(remaining)
                sock.connect(sockaddr)
            return Result(True, Reason.OK)
        except OSError as exc:
            if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED):
                refused = True
                continue
            if isinstance(exc, TimeoutError) or exc.errno == errno.ETIMEDOUT:
                timed_out = True
                continue
            # A timeout, missing route, or other transport error does not prove
            # either that the host is down or that only its service is down.
            other_error = True
    if refused and not timed_out and not other_error:
        return Result(False, Reason.CONNECT_REFUSED)
    if timed_out and not refused and not other_error:
        return Result(False, Reason.CONNECT_TIMEOUT)
    return Result(None, Reason.PROBE_INCONCLUSIVE)


class Sentinel:
    """Debounced observer. It stores current state only and emits transitions only."""

    def __init__(self, config: Config, probe: Callable[[str, int, float, str], Result] = tcp_probe,
                 logger: logging.Logger | None = None):
        self.config = config
        self.probe = probe
        self.logger = logger or logging.getLogger("ldw_sentinel")
        self.tracks: dict[str, Track] = {t.target_id: Track() for t in config.targets}
        self.monitor_state = Health.UNKNOWN
        self.monitor_failures = 0
        self.monitor_successes = 0
        self.sequence = 0
        self.target_kinds = {t.target_id: t.kind for t in config.targets}
        self._load_state()

    def _load_state(self) -> None:
        try:
            with self.config.state_file.open("rb") as stream:
                data = stream.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            for track in self.tracks.values():
                track.reason = Reason.STATE_MISSING
            return
        except OSError:
            for track in self.tracks.values():
                track.reason = Reason.STATE_CORRUPT
            return
        try:
            if len(data) > MAX_STATE_BYTES:
                raise ValueError("oversized")
            raw = json.loads(data)
            if raw.get("version") != 1 or set(raw.get("targets", {})) - set(self.tracks):
                raise ValueError("schema")
            for target_id, saved in raw["targets"].items():
                track = Track(Health(saved["state"]), Reason(saved["reason"]),
                              int(saved["failures"]), int(saved["successes"]))
                if not (0 <= track.failures <= 10 and 0 <= track.successes <= 10):
                    raise ValueError("counter")
                self.tracks[target_id] = track
            self.monitor_state = Health(raw.get("monitor_state", Health.UNKNOWN.value))
            self.sequence = raw.get("sequence", 0)
            if type(self.sequence) is not int or self.sequence < 0:
                raise ValueError("sequence")
        except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
            self.tracks = {t.target_id: Track(reason=Reason.STATE_CORRUPT) for t in self.config.targets}
            self.monitor_state = Health.UNKNOWN
            self.sequence = 0

    def _persist(self) -> None:
        payload = {
            "version": 1,
            "monitor_state": self.monitor_state.value,
            "sequence": self.sequence,
            "targets": {key: {"state": value.state.value, "reason": value.reason.value,
                              "failures": value.failures, "successes": value.successes}
                        for key, value in self.tracks.items()},
        }
        path = self.config.state_file
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".ldw-sentinel-", dir=path.parent)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"), sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            try:
                dir_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _transition(self, target_id: str, track: Track, state: Health, reason: Reason,
                    observed_at: str | None, quality: str, out: list[Transition]) -> None:
        if track.state == state and track.reason == reason:
            return
        track.state, track.reason = state, reason
        self.sequence += 1
        observation_class = "monitor-network" if target_id == "monitor" else self.target_kinds.get(target_id, "dimension")
        event = Transition(target_id, observation_class, state, reason, observed_at, observed_at,
                           quality, self.config.monitor_id, self.sequence)
        out.append(event)
        # target_id is regex-validated config; address and probe exception text are never logged.
        self.logger.info("transition target=%s state=%s reason=%s clock=%s", target_id, state.value, reason.value, quality)

    def _suppress_target(self, target_id: str, state: Health, reason: Reason,
                         observed_at: str | None, quality: str, out: list[Transition]) -> None:
        track = self.tracks[target_id]
        # Suppressed samples are not observations; never carry debounce evidence
        # across the gap and call the next sample consecutive.
        track.failures = 0
        track.successes = 0
        self._transition(target_id, track, state, reason, observed_at, quality, out)

    def _monitor_transition(self, state: Health, reason: Reason, observed_at: str | None,
                            quality: str, out: list[Transition]) -> None:
        if self.monitor_state == state:
            return
        self.monitor_state = state
        self.sequence += 1
        out.append(Transition("monitor", "monitor-network", state, reason, observed_at, observed_at,
                              quality, self.config.monitor_id, self.sequence))
        self.logger.info("transition target=monitor state=%s reason=%s clock=%s", state.value, reason.value, quality)

    def _apply(self, target: Target, result: Result, observed_at: str | None, quality: str,
               out: list[Transition]) -> None:
        track = self.tracks[target.target_id]
        if target.kind == "host" and result.reason == Reason.CONNECT_REFUSED:
            # A refusal/reset means the remote TCP stack answered, so the host
            # is reachable even though the selected port did not accept a session.
            result = Result(True, Reason.OK)
        if result.reachable is True:
            track.successes = min(10, track.successes + 1)
            track.failures = 0
            if track.successes >= self.config.recovery_threshold:
                self._transition(target.target_id, track, Health.HEALTHY, Reason.OK, observed_at, quality, out)
            elif track.state not in (Health.UNKNOWN, Health.UNREACHABLE, Health.SERVICE_UNAVAILABLE):
                self._transition(target.target_id, track, Health.DEGRADED, Reason.SUSPECT_FAILURE, observed_at, quality, out)
        elif result.reachable is False:
            track.failures = min(10, track.failures + 1)
            track.successes = 0
            confirmed_failure = (target.kind == "host" and result.reason == Reason.CONNECT_TIMEOUT) or (
                target.kind == "tcp" and result.reason == Reason.CONNECT_REFUSED)
            if not confirmed_failure:
                # Only an explicit refusal/reset proves the endpoint was reached.
                self._transition(target.target_id, track, Health.UNKNOWN, result.reason,
                                 observed_at, quality, out)
                return
            failed_state = Health.UNREACHABLE if target.kind == "host" else Health.SERVICE_UNAVAILABLE
            if track.failures >= self.config.failure_threshold:
                self._transition(target.target_id, track, failed_state, result.reason, observed_at, quality, out)
            else:
                self._transition(target.target_id, track, Health.DEGRADED, Reason.SUSPECT_FAILURE, observed_at, quality, out)
        else:
            track.failures = track.successes = 0
            self._transition(target.target_id, track, Health.UNKNOWN, result.reason, observed_at, quality, out)

    def poll_once(self) -> tuple[Transition, ...]:
        observed_at, quality = wall_clock()
        out: list[Transition] = []
        gateway = self.probe(self.config.gateway, self.config.gateway_port, self.config.timeout,
                             self.config.monitor_cidr)
        # Failures stop collection immediately; the network-degraded state itself is debounced.
        if gateway.reachable is not True:
            self.monitor_failures = min(10, self.monitor_failures + 1)
            self.monitor_successes = 0
            old_monitor_state = self.monitor_state
            if self.monitor_failures >= self.config.failure_threshold:
                self._monitor_transition(Health.MONITOR_NETWORK_DEGRADED, Reason.GATEWAY_UNAVAILABLE,
                                         observed_at, quality, out)
            else:
                self._monitor_transition(Health.DEGRADED, Reason.SUSPECT_FAILURE, observed_at, quality, out)
            for target in self.config.targets:
                self._suppress_target(target.target_id, Health.UNKNOWN,
                                      Reason.GATEWAY_UNAVAILABLE, observed_at, quality, out)
            if old_monitor_state != self.monitor_state or out:
                self._persist()
            return tuple(out)
        old_monitor_state = self.monitor_state
        self.monitor_failures = 0
        self.monitor_successes = min(10, self.monitor_successes + 1)
        if self.monitor_state in (Health.DEGRADED, Health.MONITOR_NETWORK_DEGRADED) and self.monitor_successes < self.config.recovery_threshold:
            return ()
        self.monitor_successes = 0
        self._monitor_transition(Health.HEALTHY, Reason.OK, observed_at, quality, out)
        by_id = {t.target_id: t for t in self.config.targets}
        pending = set(by_id)
        # Parents are evaluated before children; bounded passes also fail closed on a cycle.
        for _ in range(len(by_id) + 1):
            progressed = False
            for target_id in tuple(pending):
                target = by_id[target_id]
                if target.parent and target.parent in pending:
                    continue
                if target.parent:
                    parent_state = self.tracks[target.parent].state
                    if parent_state in (Health.UNREACHABLE, Health.SERVICE_UNAVAILABLE,
                                        Health.PARENT_UNREACHABLE):
                        self._suppress_target(target_id, Health.PARENT_UNREACHABLE,
                                              Reason.PARENT_UNAVAILABLE, observed_at, quality, out)
                    else:
                        self._apply(target, self.probe(target.address, target.port, self.config.timeout,
                                                       self.config.monitor_cidr), observed_at, quality, out)
                else:
                    self._apply(target, self.probe(target.address, target.port, self.config.timeout,
                                                   self.config.monitor_cidr), observed_at, quality, out)
                pending.remove(target_id)
                progressed = True
            if not pending or not progressed:
                break
        for target_id in pending:
            self._transition(target_id, self.tracks[target_id], Health.UNKNOWN, Reason.CONFIG_INVALID,
                             observed_at, quality, out)
        if out or old_monitor_state != self.monitor_state:
            self._persist()
        return tuple(out)

    def snapshot(self) -> Mapping[str, Health]:
        return {"monitor": self.monitor_state,
                **{key: track.state for key, track in self.tracks.items()},
                "github_runner_job_state": Health.NOT_COLLECTED}


def serve(config_path: Path) -> None:
    config = load_config(config_path)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logger = logging.getLogger("ldw_sentinel")
    logger.info("service start version=1")
    sentinel = Sentinel(config, logger=logger)
    while True:
        started = time.monotonic()
        try:
            sentinel.poll_once()
        except Exception as exc:  # Do not leak exception text; exit so systemd can restart us.
            logger.error("fatal poll error class=%s", type(exc).__name__)
            raise SystemExit(1) from None
        time.sleep(max(0.0, config.poll_interval - (time.monotonic() - started)))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check-config", action="store_true", help="validate config and exit without probing")
    args = parser.parse_args()
    if args.check_config:
        config = load_config(args.config)
        print(f"valid config: {len(config.targets)} targets; monitor_id={config.monitor_id}")
        return
    serve(args.config)


if __name__ == "__main__":
    main()
