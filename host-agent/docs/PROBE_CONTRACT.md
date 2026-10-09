# Host Agent probe contract

## Data hierarchy

`Device -> Environment -> Component`

Each record uses a stable local identifier, display name, platform, component type, desired state, observed state, health, observation time, and a short evidence/error summary. Do not serialize credentials, raw command output, private addresses, or customer data into logs or status exports.

## Desired state and color meaning

- **Green / Healthy:** observation matches the declared desired state.
- **Blue / Expected inactive:** stopped, disabled, or on-demand by design; this is not a failure.
- **Purple / Resource workload:** a known CI/build workload is active; report its resource telemetry separately from health.
- **Yellow / Degraded:** stale observation, partial telemetry, or a non-critical threshold needs attention.
- **Red / Failed:** a required component is unavailable or an observed failure is confirmed.
- **Gray / Initializing or unknown:** no valid observation is available yet.

Every status includes text and reason; color is never the only signal. Optional components and explicitly off-site nodes do not make their parent device red when absent. A dependency affects aggregate status only when its declared desired state is required.

Desired states are `Running`, `Stopped`, `Disabled`, `OnDemand`, `RunningAfterLogin`, and `Reachable`. `RunningAfterLogin` is not unhealthy before the owner session exists. `OnDemand` is healthy while inactive and is expected to become active only after an explicit local request.

## LDW01 Windows telemetry

The Windows adapter observes the current device's available/total physical memory, memory load, disk free space, and a short-interval CPU sample. Memory pressure is a separate signal from percent used: include available memory, commit headroom, paging/swap activity, and sustained OS pressure signals when available. Do not recommend memory cleanup from a single utilization percentage. No Hyper-V query is made by the tray process; a future narrowly privileged helper must expose read-only telemetry over authenticated local IPC.

## Component adapter interfaces

Implement local read-only probes for Tailscale, RustDesk, Desktop Commander Remote, WSL Ubuntu, and Cursor Worker. Integrations discover services/processes through documented local APIs or bounded commands, report `Unknown` when the component is not installed/configured, and never assume machine-specific paths or identities.

CI-RUNNER-001 uses the same Linux-node contract over Tailscale plus SSH. SSH must enforce strict host-key verification, an explicit known-hosts file, and the intended identity; connection setup must fail closed. The Linux adapter reports kernel/uptime/load, available memory, swap activity, disk, CPU/memory PSI when supported, update/reboot state, systemd runner service, and network reachability. GitHub runner status is a separate read-only source for online/busy/id/labels. Credentials are supplied by an approved secure connection provider and are never stored in the repository or emitted in probe results.

Off-site/headless Linux devices use the same data model and Linux probe contract; an agentless SSH/Tailscale adapter is preferred until measurement demonstrates a need for a node daemon. A device's absence is expected when its desired state is `OnDemand` or `Reachable` only during a declared window.

## Privilege boundary

The tray/UI and ordinary probes run as the owner. Do not run the whole application elevated. A future privileged helper must be a separate process with authenticated local IPC, a narrow allowlist, and read-only telemetry separated from mutations. Start/restart, VM power, reboot, shutdown, and profile changes require explicit confirmation and auditable results. No helper or listener is included in this foundation.
