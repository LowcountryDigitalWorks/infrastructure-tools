# Host Agent probe contract

## Data hierarchy

`Device -> Environment -> Component`

Each record uses a stable non-secret identifier, display name, platform, component type, desired state, observed state, health, observation time, and short sanitized reason. Never serialize credentials, raw command output, private addresses/targets, key material, customer data, or machine-local connection paths into ordinary status exports.

## Desired state and color meaning

Health and CI activity are distinct signals. Health determines whether the component matches desired state; CI activity may change the healthy presentation color without changing health.

- **Green / Healthy:** observation matches declared desired state, including intentional stopped/disabled/on-demand state.
- **Blue / Active CI job:** a CI job is active while health remains otherwise healthy. Reserved for this meaning.
- **Purple / CI Boost enabled:** CI Boost is enabled while health remains otherwise healthy. Reserved for this meaning.
- **Yellow / Degraded:** partial observation or attention is required.
- **Red / Failed:** a required component is confirmed unavailable/down or otherwise failed.
- **Gray / Initializing or unknown:** no trustworthy observation/context is available yet.

Every status includes text/reason so color is never the only signal.

Desired states are `Running`, `Stopped`, `Disabled`, `OnDemand`, `RunningAfterLogin`, and `Reachable`. `RunningAfterLogin` requires explicit owner-session context:

1. owner session inactive + stopped/disabled -> healthy/intentionally inactive;
2. owner session active + running -> healthy;
3. owner session active + stopped/disabled -> failed when required, degraded when optional;
4. owner session unknown + stopped/disabled -> unknown.

Dependency health is availability-aware while the dependent component is expected to be active. A healthy active required component fails when a required dependency is unavailable. An intentionally inactive pre-login/on-demand component does not fail merely because its dependency is likewise inactive.

## Windows local system telemetry

The Windows adapter observes available/total physical memory, commit headroom, fixed-disk free space, and a short CPU sample. Memory pressure is evaluated separately from percent-used. A single short CPU sample is informational and does not create a failure alarm. Disk capacity below 10% free is currently mapped to Yellow/attention rather than Red/failure.

No Hyper-V query is made by the normal-user tray. If future Hyper-V telemetry cannot be observed without elevation, expose it only through a separately reviewed narrow helper rather than elevating the tray.

## Owner-session observation

The Windows tray reads the current Windows Terminal Services connection state for its own session and maps it to the platform-neutral `RuntimeContext`. No username is required or committed. Unknown/unrecognized session state fails safe to `OwnerSessionState.Unknown`.

## Remote access adapters

### Tailscale

Read-only observation uses the Windows service state/start type plus `tailscale status --json` when available. The status parser consumes only backend-running, self-online, and health-count fields. When status is otherwise ready, Host Agent also attempts the read-only `tailscale debug prefs` view and consumes only `ForceDaemon` to verify the accepted unattended/server-mode posture. If that optional posture check cannot be interpreted, readiness is Yellow/partial rather than falsely Green. Addresses, peer inventories, DNS names, routes, and raw JSON are not emitted into Host Agent diagnostics.

### RustDesk

Read-only observation uses the RustDesk service state and runtime process presence. A running automatic service satisfies the accepted unattended posture; an interactive process without the service is Yellow/partial rather than falsely Green.

### Desktop Commander Remote

The adapter observes only a machine-local configured scheduled-task name and uses its basic `schtasks /Query` state. Running task state is stronger readiness evidence than generic `node.exe` existence and avoids reading task arguments/session credentials. The accepted Limited/background-task architecture is preserved; no restart/control action exists in this slice.

## WSL / Cursor Worker

`wsl --list --verbose` is the only command used to determine distro presence/running state, so a stopped distro is never started merely for observation. If the configured distro is already Running, the Cursor Worker adapter may execute read-only `systemctl is-active <configured-unit>` inside that existing distro. Cursor Worker remains `RunningAfterLogin`; stopped post-login is a failure/degraded state according to requiredness.

## Linux node / strict SSH

The Linux-node adapter requires machine-local values for target, user, existing identity file, existing non-empty known-hosts file, and runner systemd unit. An optional validated TCP port may be supplied when the accepted SSH path does not use port 22. When the accepted trust record uses one, an existing `HostKeyAlias` is also supplied from machine-local configuration. Public code never supplies a real host/address/identity.

SSH is invoked with all of:

- explicit `-i <identity>`;
- explicit `UserKnownHostsFile=<known-hosts>`;
- optional explicit `HostKeyAlias=<existing-alias>` when the accepted trust path uses one;
- `StrictHostKeyChecking=yes`;
- `IdentitiesOnly=yes`;
- `BatchMode=yes`;
- bounded connect/probe timeout.

The remote command is fixed/read-only and does not use `sudo`. It reports kernel, uptime, load1, MemAvailable, swap used, root-disk total/free, CPU/memory PSI when supported, locally cached upgradable-package count, reboot-required marker, and the configured GitHub Runner systemd service state. The configured host/user/unit are syntax-validated before use. If strict configuration is absent/invalid, SSH cannot be trusted, or output cannot be parsed, report Unknown rather than fabricate node failure/readiness. Dynamic Hyper-V guest addressing that cannot be resolved from the unelevated owner context likewise remains Unknown; do not elevate the tray or rebuild SSH trust merely to observe it. If needed, a separately reviewed narrow read-only helper may later supply current guest addressing/Hyper-V telemetry.

## GitHub Runner

Runner control-plane status is a separate read-only source. Host Agent invokes existing authenticated `gh api` access for the locally configured repository and runner ID, then parses only id/name, online/offline, busy, and labels. No token is accepted by Host Agent configuration; no registration/label mutation exists. Busy maps to Blue activity while online health remains Healthy. The owner UI/normal copied diagnostics do not emit the concrete runner ID, name, or label values; they surface presence/count plus online/busy state to keep routine diagnostics sanitizable.

## Machine-local configuration

Public template: `config/host-agent.Local.example.json`.

Actual machine-specific configuration must stay local/gitignored. Lookup order is explicit `LDW_HOST_AGENT_CONFIG`, `%LOCALAPPDATA%\LowcountryDigitalWorks\HostAgent\host-agent.Local.json`, then an adjacent `host-agent.Local.json`. Configuration errors are summarized without echoing the path or content.

## Privilege and mutation boundary

The tray/UI and ordinary probes run as the owner and explicitly refuse elevated execution. No manifest requests elevation. This slice includes no privileged helper, service restart/control, VM action, CI Normal/Boost mutation, reboot/shutdown, listener, remote push control, or runner mutation.

A future privileged helper, if justified, must be a separately reviewed process with authenticated local IPC, narrow allowlists, and read telemetry separated from mutation. Host Agent must remain useful when privileged telemetry is unavailable by reporting Unknown/Degraded rather than elevating the whole application.
