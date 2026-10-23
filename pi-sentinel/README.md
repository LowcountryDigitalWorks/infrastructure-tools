# PI-SENTINEL-001 — implementation candidate

This directory contains a dependency-free, read-only Raspberry Pi sentinel candidate. It is source-controlled implementation material; it is not deployment approval. The hardware, network, and cold-boot proof remains governed by [business-operations#656](https://github.com/LowcountryDigitalWorks/business-operations/issues/656). GitHub runner/job status stays `NOT_COLLECTED`; the Pi does not call GitHub or infer runner state from VM reachability.

## Boundaries

- Python 3 standard library only; no database, container, listener, GitHub credential, or external API.
- Probe types are fixed to a bounded TCP connection. Configuration cannot name a shell command or executable.
- The gateway TCP port must be a service that the owner has verified responds on the local gateway. The gateway and every resolved target address must be inside the explicitly configured private monitor CIDR. DNS results outside that network fail closed.
- DNS resolution is given a per-probe deadline and uses at most four daemon resolver threads process-wide. TCP connection attempts share the configured timeout budget.
- Missing/corrupt state starts `UNKNOWN`; state files contain only bounded current state and debounce counters. Atomic replacement happens on state transitions, not on healthy polling intervals.
- Logs contain only validated logical target IDs, enumerated state/reason values, and wall-clock quality. They omit addresses, DNS answers, MACs, credentials, and probe exception text.
- Wall timestamps are emitted only when systemd-timesyncd has created its synchronization marker for the current boot and the epoch is plausible; otherwise events carry `UNSYNCHRONIZED`. Debounce uses monotonic probe-cycle counts and does not rely on wall time.
- The optional WOL utility is a separate manual command. The daemon never invokes it. It accepts only a logical name from a separate local allowlist and sends one standard packet to the configured private subnet broadcast. Actual Wi-Fi/AP behavior remains a hardware-only proof.

`config.example.json` contains placeholders by design and is not runnable until copied to a machine-local file and completed there. Never commit real addresses, hostnames that reveal private infrastructure, or MACs. `wol-targets.example.json` is intentionally empty.

## State behavior

| Input | Result |
| --- | --- |
| Gateway cannot be reached/resolved | Target polling pauses; after the configured failure threshold the monitor becomes `MONITOR_NETWORK_DEGRADED` and target states become `UNKNOWN / GATEWAY_UNAVAILABLE` |
| Target DNS lookup fails or times out | `UNKNOWN / RESOLUTION_FAILED` |
| Target resolves outside the private monitor CIDR | `UNKNOWN / ADDRESS_OUTSIDE_MONITOR_NETWORK` |
| Host TCP probe has threshold timeouts | `UNREACHABLE`; an explicit refusal/reset proves the host TCP stack answered and counts as host reachability |
| TCP service explicitly refuses/resets connections at threshold | `SERVICE_UNAVAILABLE` |
| TCP service times out or has an ambiguous routing error | `UNKNOWN`; the observer cannot tell whether the host or only the service/path failed |
| Required parent is confirmed unavailable | Child is `PARENT_UNREACHABLE`; child probe is suppressed |
| One failure before threshold | `DEGRADED / SUSPECT_FAILURE` |
| Two successes after a failure (default) | Recovery to `HEALTHY` |
| GitHub runner/job dimension | `NOT_COLLECTED` |

These are observation classifications, not service-level commitments. A host probe is TCP-only and means “the configured port accepted a connection” or “the remote TCP stack explicitly refused/reset it”; it does not prove general host health or application correctness. Host timeout requires the configured failure threshold; ambiguous path errors remain `UNKNOWN`.

## Validate and test

From the repository root:

```sh
python3 -m unittest discover -s pi-sentinel/tests -v
python3 -m py_compile pi-sentinel/ldw_sentinel.py pi-sentinel/wol.py
```

Tests use synthetic configuration and injected probe results. They never open a LAN socket or send a WOL packet.

## Install on an approved Linux appliance

These steps only describe a later owner-run installation. Do not run them on a device as part of repository review.

1. Confirm the hardware and network inventory and the Stage 1 authority in #656. Verify the current official Raspberry Pi OS image before writing media.
2. From this directory, create the service identity and directories. Re-running these commands is safe:

   ```sh
   getent passwd ldwmon >/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin ldwmon
   sudo install -d -o root -g root -m 0755 /opt/ldw-sentinel
   sudo install -d -o root -g ldwmon -m 0750 /etc/ldw-sentinel
   sudo install -d -o ldwmon -g ldwmon -m 0700 /var/lib/ldw-sentinel
   sudo install -o root -g root -m 0644 ldw_sentinel.py /opt/ldw-sentinel/ldw_sentinel.py
   sudo install -o root -g root -m 0644 wol.py /opt/ldw-sentinel/wol.py
   sudo install -o root -g root -m 0644 systemd/ldw-sentinel.service /etc/systemd/system/ldw-sentinel.service
   ```

3. Create `/etc/ldw-sentinel/config.json` locally from `config.example.json`. Replace placeholders only with owner-approved LAN values. Choose and verify the gateway TCP port. Configure only required local targets; do not add GitHub, customer, or regulated data.
4. Set the configuration owner and permissions, validate without probing, then enable the service:

   ```sh
   sudo chown root:ldwmon /etc/ldw-sentinel/config.json
   sudo chmod 0640 /etc/ldw-sentinel/config.json
   sudo -u ldwmon /usr/bin/python3 /opt/ldw-sentinel/ldw_sentinel.py --config /etc/ldw-sentinel/config.json --check-config
   sudo systemctl daemon-reload
   sudo systemctl enable --now ldw-sentinel.service
   ```

5. Check `systemctl status ldw-sentinel.service` and `journalctl -u ldw-sentinel.service`. Logs should show only transition classes and logical target IDs. Stop if values, permissions, or probe results differ from the accepted configuration; do not paste private values into GitHub or chat.

The service is deliberately constrained by systemd. It runs as non-login `ldwmon`, with no privilege escalation, no writable code/config, and write access only to its state directory. A memory cap is intentionally omitted until RSS/swap behavior is measured on the actual Zero 2 W.

## Manual optional WOL

Only after core monitoring semantics pass and an owner has approved one exact target, create `/etc/ldw-sentinel/wol-targets.json` locally with the shape `{"monitor_cidr":"OWNER_APPROVED_PRIVATE_CIDR","targets":{"logical-name":"aa:bb:cc:dd:ee:ff"}}`. The configured CIDR determines the one permitted local broadcast destination; the command accepts no destination override. Set the file root-owned and readable only by the owner-controlled invocation identity. Then use the helper manually:

```sh
sudo /usr/bin/python3 /opt/ldw-sentinel/wol.py --target logical-name --config /etc/ldw-sentinel/wol-targets.json
```

This sends one UDP packet and has no retry or automation loop. Do not execute this during software validation. Do not place target MACs in Git, issues, GitBook, or logs.

## Remove / rollback

Disable and remove the unit, code, and configuration; retain or erase local state according to the owner’s choice. These literal-file commands are safe when the service is already absent. Remove the state file only if the owner has decided it is no longer needed:

```sh
sudo systemctl disable --now ldw-sentinel.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/ldw-sentinel.service
sudo systemctl daemon-reload
sudo rm -f /opt/ldw-sentinel/ldw_sentinel.py /opt/ldw-sentinel/wol.py
sudo rm -f /etc/ldw-sentinel/config.json /etc/ldw-sentinel/wol-targets.json
sudo rm -f /var/lib/ldw-sentinel/state.json
sudo rmdir /opt/ldw-sentinel /etc/ldw-sentinel /var/lib/ldw-sentinel 2>/dev/null || true
sudo userdel ldwmon 2>/dev/null || true
```

Review the literal paths before running them. `rmdir` leaves any non-empty directory in place. No router, DNS, runner, or host-service rollback should be necessary because this service is an observer only.
