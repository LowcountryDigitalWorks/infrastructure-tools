import io
import json
import logging
import tempfile
import unittest
import errno
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ldw_sentinel import (
    Config, Health, Reason, Result, Sentinel, Target, Track, load_config, tcp_probe, wall_clock,
)
from wol import magic_packet, send_allowlisted


def make_config(state: Path, targets=None, **overrides):
    values = dict(monitor_id="sentinel-test", gateway="10.0.0.1", gateway_port=80,
                  monitor_cidr="10.0.0.0/24", poll_interval=60, timeout=0.2,
                  failure_threshold=3, recovery_threshold=2, state_file=state,
                  targets=tuple(targets or [Target("host-a", "host", "10.0.0.10", 22)]))
    values.update(overrides)
    return Config(**values)


class ProbeSequence:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, address, port, timeout, network):
        self.calls.append((address, port, timeout, network))
        if not self.results:
            return Result(True, Reason.OK)
        return self.results.pop(0)


class SentinelContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state.json"

    def test_healthy_baseline_requires_recovery_threshold_and_is_stable(self):
        probe = ProbeSequence([Result(True, Reason.OK)] * 3)
        sentinel = Sentinel(make_config(self.state), probe=probe)
        first = sentinel.poll_once()
        self.assertEqual([t.target_id for t in first], ["monitor"])
        self.assertEqual(sentinel.snapshot()["host-a"], Health.UNKNOWN)
        transitions = sentinel.poll_once()
        self.assertEqual([(t.target_id, t.state) for t in transitions], [("host-a", Health.HEALTHY)])
        self.assertEqual(transitions[0].observation_class, "host")
        self.assertEqual(transitions[0].monitor_id, "sentinel-test")
        self.assertEqual(transitions[0].source, "pi-sentinel")
        self.assertGreater(transitions[0].sequence, 0)
        self.assertEqual(sentinel.poll_once(), ())
        self.assertEqual(sentinel.snapshot()["host-a"], Health.HEALTHY)
        unchanged_mtime = self.state.stat().st_mtime_ns
        self.assertEqual(sentinel.poll_once(), ())
        self.assertEqual(self.state.stat().st_mtime_ns, unchanged_mtime)
        self.assertEqual(sentinel.snapshot()["github_runner_job_state"], Health.NOT_COLLECTED)

    def test_three_failures_emit_one_confirmed_transition_and_recovery_once(self):
        sequence = iter([Result(True, Reason.OK)] * 2 + [Result(False, Reason.CONNECT_TIMEOUT)] * 4 + [Result(True, Reason.OK)] * 3)
        probe = lambda address, port, timeout, network: Result(True, Reason.OK) if address == "10.0.0.1" else next(sequence)
        sentinel = Sentinel(make_config(self.state), probe=probe)
        self.assertEqual([t.target_id for t in sentinel.poll_once()], ["monitor"])
        self.assertEqual(sentinel.poll_once()[0].state, Health.HEALTHY)
        self.assertEqual(sentinel.poll_once()[0].state, Health.DEGRADED)
        self.assertEqual(sentinel.poll_once(), ())
        confirmed = sentinel.poll_once()
        self.assertEqual(confirmed[0].state, Health.UNREACHABLE)
        self.assertEqual(sentinel.poll_once(), ())
        self.assertEqual(sentinel.poll_once(), ())
        recovered = sentinel.poll_once()
        self.assertEqual(recovered[0].state, Health.HEALTHY)

    def test_resolution_failure_is_unknown_with_safe_reason(self):
        from unittest.mock import patch
        with patch("ldw_sentinel._resolve", return_value=[]):
            result = tcp_probe("missing.invalid", 443, 0.1, "10.0.0.0/24")
        self.assertIsNone(result.reachable)
        self.assertEqual(result.reason, Reason.RESOLUTION_FAILED)

    def test_probe_refusal_confirms_host_but_timeout_is_inconclusive(self):
        from unittest.mock import patch
        with patch("ldw_sentinel._resolve", return_value=[(2, ("10.0.0.10", 22))]), \
             patch("ldw_sentinel.socket.socket", side_effect=OSError(errno.ECONNREFUSED, "synthetic")):
            refused = tcp_probe("host-a.local", 22, 0.1, "10.0.0.0/24")
        self.assertFalse(refused.reachable)
        self.assertEqual(refused.reason, Reason.CONNECT_REFUSED)
        with patch("ldw_sentinel._resolve", return_value=[(2, ("10.0.0.10", 22))]), \
             patch("ldw_sentinel.socket.socket", side_effect=TimeoutError()):
            timed_out = tcp_probe("host-a.local", 22, 0.1, "10.0.0.0/24")
        self.assertFalse(timed_out.reachable)
        self.assertEqual(timed_out.reason, Reason.CONNECT_TIMEOUT)

    def test_probe_tries_later_resolved_address_after_first_refusal(self):
        from unittest.mock import patch
        attempts = []
        class FakeSocket:
            def __init__(self, sockaddr):
                self.sockaddr = sockaddr
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def settimeout(self, _timeout):
                pass
            def connect(self, sockaddr):
                attempts.append(sockaddr[0])
                if sockaddr[0] == "10.0.0.10":
                    raise OSError(errno.ECONNREFUSED, "synthetic")
        with patch("ldw_sentinel._resolve", return_value=[
            (2, ("10.0.0.10", 443)), (2, ("10.0.0.11", 443))
        ]), patch("ldw_sentinel.socket.socket", side_effect=lambda family, kind: FakeSocket(None)):
            result = tcp_probe("service.local", 443, 0.2, "10.0.0.0/24")
        self.assertTrue(result.reachable)
        self.assertEqual(attempts, ["10.0.0.10", "10.0.0.11"])

    def test_oversized_state_is_read_bounded_and_unknown(self):
        import ldw_sentinel
        self.state.write_bytes(b" " * (ldw_sentinel.MAX_STATE_BYTES + 1024))
        sentinel = Sentinel(make_config(self.state), probe=ProbeSequence([]))
        self.assertEqual(sentinel.snapshot()["host-a"], Health.UNKNOWN)
        self.assertEqual(sentinel.tracks["host-a"].reason, Reason.STATE_CORRUPT)

    def test_target_resolution_outside_monitor_network_fails_closed(self):
        from unittest.mock import patch
        with patch("ldw_sentinel._resolve", return_value=[(2, ("8.8.8.8", 443))]):
            result = tcp_probe("example.invalid", 443, 0.1, "10.0.0.0/24")
        self.assertIsNone(result.reachable)
        self.assertEqual(result.reason, Reason.ADDRESS_OUTSIDE_MONITOR_NETWORK)

    def test_missing_and_corrupt_state_load_unknown(self):
        cfg = make_config(self.state)
        missing = Sentinel(cfg, probe=ProbeSequence([]))
        self.assertEqual(missing.snapshot()["host-a"], Health.UNKNOWN)
        self.assertEqual(missing.tracks["host-a"].reason, Reason.STATE_MISSING)
        self.state.write_text("{ definitely not json", encoding="utf-8")
        corrupt = Sentinel(cfg, probe=ProbeSequence([]))
        self.assertEqual(corrupt.snapshot()["host-a"], Health.UNKNOWN)
        self.assertEqual(corrupt.tracks["host-a"].reason, Reason.STATE_CORRUPT)

    def test_gateway_failure_suppresses_targets_as_unknown_and_persists_once(self):
        probe = ProbeSequence([Result(False, Reason.CONNECT_FAILED)] * 3 + [Result(False, Reason.CONNECT_FAILED)])
        sentinel = Sentinel(make_config(self.state), probe=probe)
        first = sentinel.poll_once()
        self.assertEqual(sentinel.monitor_state, Health.DEGRADED)
        self.assertEqual(sentinel.snapshot()["host-a"], Health.UNKNOWN)
        self.assertTrue(any(t.reason == Reason.GATEWAY_UNAVAILABLE for t in first))
        self.assertEqual(sentinel.poll_once(), ())
        transitions = sentinel.poll_once()
        self.assertEqual(sentinel.snapshot()["host-a"], Health.UNKNOWN)
        self.assertEqual(sentinel.monitor_state, Health.MONITOR_NETWORK_DEGRADED)
        before = self.state.stat().st_mtime_ns
        self.assertEqual(sentinel.poll_once(), ())
        self.assertEqual(self.state.stat().st_mtime_ns, before)

    def test_monitor_network_recovery_is_debounced(self):
        target_results = iter([Result(True, Reason.OK)] * 2)
        gateway_results = iter([Result(False, Reason.CONNECT_FAILED)] * 3 + [Result(True, Reason.OK)] * 2 + [Result(True, Reason.OK)])
        def probe(address, port, timeout, network):
            return next(gateway_results) if address == "10.0.0.1" else next(target_results)
        sentinel = Sentinel(make_config(self.state), probe=probe)
        for _ in range(3):
            sentinel.poll_once()
        self.assertEqual(sentinel.monitor_state, Health.MONITOR_NETWORK_DEGRADED)
        sentinel.poll_once()
        self.assertEqual(sentinel.monitor_state, Health.MONITOR_NETWORK_DEGRADED)
        sentinel.poll_once()
        self.assertEqual(sentinel.monitor_state, Health.HEALTHY)
        self.assertEqual(sentinel.snapshot()["host-a"], Health.UNKNOWN)
        sentinel.poll_once()
        self.assertEqual(sentinel.snapshot()["host-a"], Health.HEALTHY)

    def test_unsynchronized_wall_clock_is_explicit(self):
        from unittest.mock import patch
        with patch("ldw_sentinel.time.time", return_value=1):
            observed, quality = wall_clock()
        self.assertIsNone(observed)
        self.assertEqual(quality, "UNSYNCHRONIZED")

    def test_wall_timestamp_requires_os_sync_marker(self):
        from unittest.mock import patch
        marker = Path(self.temp.name) / "synchronized"
        with patch("ldw_sentinel.time.time", return_value=1_800_000_000):
            self.assertEqual(wall_clock(marker), (None, "UNSYNCHRONIZED"))
            marker.touch()
            observed, quality = wall_clock(marker)
        self.assertIsNotNone(observed)
        self.assertEqual(quality, "PLAUSIBLE")

    def test_gateway_suppression_clears_old_target_debounce(self):
        gateway_results = iter([Result(True, Reason.OK), Result(True, Reason.OK),
                                Result(False, Reason.CONNECT_FAILED), Result(True, Reason.OK),
                                Result(True, Reason.OK)])
        target_results = iter([Result(False, Reason.CONNECT_TIMEOUT)] * 3)
        def probe(address, *_args):
            return next(gateway_results) if address == "10.0.0.1" else next(target_results)
        sentinel = Sentinel(make_config(self.state), probe=probe)
        sentinel.poll_once()
        sentinel.poll_once()
        self.assertEqual(sentinel.tracks["host-a"].failures, 2)
        sentinel.poll_once()  # gateway failure suppresses targets and clears their counters
        self.assertEqual(sentinel.tracks["host-a"].failures, 0)
        sentinel.poll_once()  # first gateway recovery sample; targets remain suppressed
        sentinel.poll_once()  # second recovery sample; first fresh target timeout
        self.assertEqual(sentinel.snapshot()["host-a"], Health.DEGRADED)
        self.assertEqual(sentinel.tracks["host-a"].failures, 1)

    def test_parent_suppression_clears_old_target_debounce(self):
        targets = (Target("parent", "host", "10.0.0.2", 22),
                   Target("child", "host", "10.0.0.3", 22, "parent"))
        sentinel = Sentinel(make_config(self.state, targets=targets), probe=ProbeSequence([]))
        child = sentinel.tracks["child"]
        child.state, child.reason, child.failures = Health.DEGRADED, Reason.SUSPECT_FAILURE, 2
        sentinel.tracks["parent"].state = Health.UNREACHABLE
        sentinel.probe = lambda address, *_args: (Result(True, Reason.OK)
            if address in {"10.0.0.1", "10.0.0.2"} else Result(False, Reason.CONNECT_TIMEOUT))
        sentinel.poll_once()
        self.assertEqual(child.state, Health.PARENT_UNREACHABLE)
        self.assertEqual(child.failures, 0)
        sentinel.tracks["parent"].state = Health.HEALTHY
        sentinel.poll_once()
        self.assertEqual(child.state, Health.DEGRADED)
        self.assertEqual(child.failures, 1)

    def test_parent_suppression_and_service_down_semantics(self):
        targets = (Target("parent", "host", "10.0.0.2", 22),
                   Target("service", "tcp", "10.0.0.3", 443, "parent"))
        parent_results = iter([Result(True, Reason.OK)] * 2 + [Result(False, Reason.CONNECT_TIMEOUT)] * 3)
        child_results = iter([Result(True, Reason.OK)] * 4)
        calls = []
        def probe(address, port, timeout, network):
            calls.append((address, port, timeout, network))
            if address == "10.0.0.1":
                return Result(True, Reason.OK)
            if address == "10.0.0.2":
                return next(parent_results)
            return next(child_results)
        sentinel = Sentinel(make_config(self.state, targets=targets), probe=probe)
        sentinel.poll_once()
        sentinel.poll_once()
        sentinel.poll_once()
        sentinel.poll_once()
        last = sentinel.poll_once()
        self.assertEqual(sentinel.snapshot()["parent"], Health.UNREACHABLE)
        self.assertEqual(sentinel.snapshot()["service"], Health.PARENT_UNREACHABLE)
        self.assertEqual(sum(call[0] == "10.0.0.3" for call in calls), 4)

    def test_parent_unreachable_suppresses_entire_descendant_chain(self):
        targets = (Target("root", "host", "10.0.0.2", 22),
                   Target("middle", "host", "10.0.0.3", 22, "root"),
                   Target("leaf", "tcp", "10.0.0.4", 443, "middle"))
        root_results = iter([Result(True, Reason.OK)] * 2 + [Result(False, Reason.CONNECT_TIMEOUT)] * 4)
        calls = []
        def probe(address, port, timeout, network):
            calls.append(address)
            if address == "10.0.0.1":
                return Result(True, Reason.OK)
            if address == "10.0.0.2":
                return next(root_results)
            return Result(True, Reason.OK)
        sentinel = Sentinel(make_config(self.state, targets=targets), probe=probe)
        for _ in range(5):
            sentinel.poll_once()
        self.assertEqual(sentinel.snapshot()["root"], Health.UNREACHABLE)
        self.assertEqual(sentinel.snapshot()["middle"], Health.PARENT_UNREACHABLE)
        self.assertEqual(sentinel.snapshot()["leaf"], Health.PARENT_UNREACHABLE)
        leaf_calls = calls.count("10.0.0.4")
        sentinel.poll_once()
        self.assertEqual(calls.count("10.0.0.4"), leaf_calls)

        independent = (Target("service", "tcp", "10.0.0.3", 443),)
        child_results = iter([Result(True, Reason.OK)] * 2 + [Result(False, Reason.CONNECT_REFUSED)] * 3)
        probe2 = lambda address, port, timeout, network: Result(True, Reason.OK) if address == "10.0.0.1" else next(child_results)
        sentinel2 = Sentinel(make_config(self.state.with_name("state2.json"), targets=independent), probe=probe2)
        for _ in range(5):
            events = sentinel2.poll_once()
        self.assertEqual(sentinel2.snapshot()["service"], Health.SERVICE_UNAVAILABLE)

    def test_logs_never_include_address_or_mac_and_stable_state_is_quiet(self):
        stream = io.StringIO()
        logger = logging.getLogger("sentinel-test-logs")
        logger.handlers.clear()
        logger.propagate = False
        logger.setLevel(logging.INFO)
        logger.addHandler(logging.StreamHandler(stream))
        probe = ProbeSequence([Result(True, Reason.OK)] * 3)
        sentinel = Sentinel(make_config(self.state), probe=probe, logger=logger)
        sentinel.poll_once()
        sentinel.poll_once()
        stable = stream.getvalue()
        sentinel.poll_once()
        self.assertEqual(stream.getvalue(), stable)
        self.assertNotIn("10.0.0.", stream.getvalue())
        self.assertNotIn("02:00:00", stream.getvalue())
        self.assertNotIn("00:00:5e", stream.getvalue())

    def test_config_rejects_commands_and_invalid_probe_kind(self):
        raw = {"monitor_id": "test", "gateway": "10.0.0.1", "gateway_port": 80,
               "monitor_cidr": "10.0.0.0/24", "poll_interval": 60, "timeout": 1,
               "failure_threshold": 3, "recovery_threshold": 2,
               "state_file": "/var/lib/ldw-sentinel/state.json",
               "targets": [{"id": "x", "kind": "shell", "address": "echo hello", "port": 1}]}
        config_file = Path(self.temp.name) / "config.json"
        config_file.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(config_file)
        raw["targets"] = [
            {"id": "x", "kind": "tcp", "address": "host-a.local", "port": 22, "parent": "y"},
            {"id": "y", "kind": "tcp", "address": "host-b.local", "port": 22, "parent": "x"},
        ]
        config_file.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "acyclic"):
            load_config(config_file)
        raw["targets"][0] = {"id": "x", "kind": "tcp", "address": "127.0.0.1", "port": 22, "command": "whoami"}
        config_file.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_config(config_file)
        for reserved in ("monitor", "github_runner_job_state"):
            raw["targets"] = [{"id": reserved, "kind": "tcp", "address": "host-a.local", "port": 22}]
            config_file.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reserved"):
                load_config(config_file)

    def test_example_separates_plex_host_from_service(self):
        example = json.loads((Path(__file__).parents[1] / "config.example.json").read_text(encoding="utf-8"))
        targets = {target["id"]: target for target in example["targets"]}
        self.assertEqual(targets["plex-host"]["kind"], "host")
        self.assertEqual(targets["plex-service"]["kind"], "tcp")
        self.assertEqual(targets["plex-service"]["parent"], "plex-host")

    def test_persistence_is_atomic_and_bounded_without_history(self):
        target = Target("host-a", "host", "10.0.0.10", 22)
        sentinel = Sentinel(make_config(self.state, targets=(target,)), probe=ProbeSequence([Result(True, Reason.OK)] * 2))
        sentinel.poll_once()
        sentinel.poll_once()
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(set(saved), {"version", "monitor_state", "sequence", "targets"})
        self.assertEqual(set(saved["targets"]), {"host-a"})
        self.assertFalse(any(p.name.startswith(".ldw-sentinel-") for p in self.state.parent.iterdir()))
        self.assertLess(self.state.stat().st_size, 1024)
        self.assertLessEqual(len(sentinel.tracks), 64)

    def test_wol_constructs_synthetic_magic_packet_and_rejects_unknown_name(self):
        mac = "02:00:00:00:00:01"  # Synthetic test fixture; never a device address.
        packet = magic_packet(mac)
        expected_mac = bytes.fromhex("020000000001")
        self.assertEqual(packet, b"\xff" * 6 + expected_mac * 16)
        self.assertEqual(len(packet), 102)
        config_file = Path(self.temp.name) / "wol.json"
        config_file.write_text(json.dumps({"monitor_cidr": "10.0.0.0/24",
                                           "targets": {"approved-host": mac}}), encoding="utf-8")
        with self.assertRaises(ValueError):
            send_allowlisted("unlisted", config_file)
        with self.assertRaises(ValueError):
            magic_packet("01:00:00:00:00:01")

    def test_wol_allowlist_owns_local_broadcast_destination(self):
        config_file = Path(self.temp.name) / "wol.json"
        config_file.write_text(json.dumps({"monitor_cidr": "10.0.0.0/24", "targets": {}}), encoding="utf-8")
        targets, subnet = __import__("wol").load_allowlist(config_file)
        self.assertEqual(str(subnet.broadcast_address), "10.0.0.255")
        self.assertEqual(targets, {})
        config_file.write_text(json.dumps({"monitor_cidr": "10.0.0.0/24",
                                           "targets": {"approved": "02:00:00:00:00:01"}}), encoding="utf-8")
        from unittest.mock import patch, MagicMock
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        with patch("wol.socket.socket", return_value=fake_socket):
            send_allowlisted("approved", config_file)
        self.assertEqual(fake_socket.sendto.call_args.args[1], ("10.0.0.255", 9))
        bad_config = Path(self.temp.name) / "wol-bad.json"
        bad_config.write_text(json.dumps({"monitor_cidr": "8.8.8.0/24", "targets": {}}), encoding="utf-8")
        with self.assertRaises(ValueError):
            send_allowlisted("approved", bad_config)


if __name__ == "__main__":
    unittest.main()
