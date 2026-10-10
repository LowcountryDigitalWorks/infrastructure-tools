# Host Agent probe contract

## Data hierarchy

`Device -> Environment -> Component`

Each record uses a stable local identifier, display name, platform, component type, desired state, observed state, health, observation time, and a short evidence/error summary. Do not serialize credentials, raw command output, private addresses, or customer data into logs or status exports.

## Desired state and color meaning

Health and CI activity are distinct signals. Health determines whether the component matches desired state; CI activity may change the healthy presentation color without changing health.

- **Green / Healthy:** observation matches the declared desired state, including intentionally stopped, disabled, or inactive on-demand components.
- **Blue / Active CI job:** a CI job is actively running while health remains otherwise healthy. Blue is reserved for this meaning.
- **Purple / CI Boost enabled:** CI Boost is enabled while health remains otherwise healthy. Purple is reserved for this meaning and takes presentation priority over Blue when both are true.
- **Yellow / Degraded:** stale observation, partial telemetry, or a non-critical threshold needs attention.
- **Red / Failed:** a required component is unavailable or an observed failure is confirmed. Failure presentation overrides CI activity.
- **Gray / Initializing or unknown:** no valid observation or required runtime context is available yet.

Every status includes text and reason; color is never the only signal. Optional components and explicitly off-site nodes do not make their parent device red when absent.

Desired states are `Running`, `Stopped`, `Disabled`, `OnDemand`, `RunningAfterLogin`, and `Reachable`. `Stopped`, `Disabled`, and inactive `OnDemand` components are healthy when that state matches configuration. `OnDemand` may also be healthy while running after an explicit request.

`RunningAfterLogin` requires explicit platform-neutral runtime context for whether the owner session is active. The evaluator must produce these deterministic outcomes:

1. owner session inactive + component stopped/disabled -> healthy / intentionally inactive;
2. owner session active + component running -> healthy;
3. owner session active + component stopped/disabled -> failed when required, degraded when optional;
4. owner session unknown + component stopped/disabled -> unknown rather than silently healthy.

Dependency health remains availability-aware. A component can be healthy for its own desired state while intentionally inactive, but if a required active component declares that inactive component as a dependency, the dependent aggregate fails because the dependency is not currently available.

## LDW01 Windows telemetry

The Windows adapter observes the current device's available/total physical memory, memory load, disk free space, and a short-interval CPU sample. Memory pressure is a separate signal from percent used: include available memory, commit headroom, paging/swap activity, and sustained OS pressure signals when available. Do not recommend memory cleanup from a single utilization percentage. No Hyper-V query is made by the tray process; a future narrowly privileged helper must expose read-only telemetry over authenticated local IPC.

## Component adapter interfaces

Implement local read-only probes for Tailscale, RustDesk, Desktop Commander Remote, WSL Ubuntu, and Cursor Worker. Integrations discover services/processes through documented local APIs or bounded commands, report `Unknown` when the component is not installed/configured, and never assume machine-specific paths or identities.

CI-RUNNER-001 uses the same Linux-node contract over Tailscale plus SSH. SSH must enforce strict host-key verification, an explicit known-hosts file, and the intended identity; connection setup must fail closed. The Linux adapter reports kernel/uptime/load, available memory, swap activity, disk, CPU/memory PSI when supported, update/reboot state, systemd runner service, and network reachability. GitHub runner status is a separate read-only source for online/busy/id/labels. Credentials are supplied by an approved secure connection provider and are never stored in the repository or emitted in probe results.

Off-site/headless Linux devices use the same data model and Linux probe contract; an agentless SSH/Tailscale adapter is preferred until measurement demonstrates a need for a node daemon. A device's absence is expected when its desired state is `OnDemand` or `Reachable` only during a declared window.

## Privilege boundary

The tray/UI and ordinary probes run as the owner. Do not run the whole application elevated. A future privileged helper must be a separate process with authenticated local IPC, a narrow allowlist, and read-only telemetry separated from mutations. Start/restart, VM power, reboot, shutdown, and profile changes require explicit confirmation and auditable results. No helper or listener is included in this foundation.
