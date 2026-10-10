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

The normal-user tray never queries Hyper-V directly. Privileged Hyper-V observation is isolated behind the separately built read-only helper described below.

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

## Hyper-V observer helper

The privileged boundary is intentionally narrower than the Host Agent tray:

- `LDW.HostAgent.HyperVObserver` must itself be elevated; the tray remains normal-user and continues to refuse elevated execution.
- The helper exposes one local named pipe created through `CreateNamedPipe` with a protected explicit DACL. LocalSystem and Administrators receive administrative pipe access and only configured explicit owner-user SIDs receive read/write access. `PIPE_REJECT_REMOTE_CLIENTS` rejects remote named-pipe connections.
- Pipe ACL access alone is insufficient: after connect, the server identifies the caller SID with `RunAsClient` and authorizes only an explicitly configured safe user SID. Everyone, Interactive, Authenticated Users, and Builtin Users are rejected by contract policy.
- The tray client requests `TokenImpersonationLevel.Identification`. It also resolves the connected pipe server PID, opens that process token read-only, and accepts the server only when the token is elevated and belongs to LocalSystem or the tray's same explicit user SID. A non-elevated or unexpected-user server fails closed before any request is sent.
- The only accepted request is the exact versioned `observe-ci-runner-001` operation. There is no VM-name, command-line, script, method, or free-form argument field in the request.
- The allowlisted VM literal is `CI-RUNNER-001`; the helper does not enumerate arbitrary VMs.
- Hyper-V observation is a fixed in-code PowerShell script using only `Get-VM -Name 'CI-RUNNER-001'` and `Get-VMNetworkAdapter -VMName 'CI-RUNNER-001'`. No caller value is interpolated into the script or command line.
- The helper captures bounded stdout/stderr but never returns or logs raw command output. Its response is limited to protocol version, authorization state, VM existence, state/running state, filtered address candidates, and a non-sensitive error code.
- Address policy rejects invalid/empty values, IPv4 0/8, loopback, APIPA/link-local, multicast/broadcast, IPv6 unspecified/loopback/link-local/multicast, and duplicates. SSH selection is additionally capped to four candidates.
- No TCP/HTTP/network listener exists. The named pipe is local IPC only.

Helper authorization is machine-local. The default file is `%ProgramData%\LowcountryDigitalWorks\HostAgent\hyperv-observer.Local.json`; `--config <local-path>` may be used for a reviewed local configuration. Only one to four explicit `S-1-5-21-...` user SIDs survive parsing; broad group SIDs are discarded. Real SIDs are never committed.

This slice contains no Hyper-V mutation request or implementation: no start/stop/restart/reset, configuration/profile/Dynamic Memory changes, checkpoints, network changes, or generic elevated command execution. It also does not install a persistent elevated service/task before exact-candidate review. If the helper is absent, not elevated, missing/invalid local authorization, inaccessible, fails server-identity verification, or returns no safe observation, Host Agent remains fail-closed.

## Linux node / strict SSH

The Linux-node adapter always requires machine-local values for user, existing identity file, existing non-empty known-hosts file, and runner systemd unit. An optional validated TCP port may be supplied when the accepted SSH path does not use port 22.

Two target modes are supported:

1. **Static target:** `linuxNode.host` supplies the syntax-validated connection target. An optional existing `HostKeyAlias` may preserve an accepted trust identity.
2. **Hyper-V observer:** `linuxNode.useHyperVObserver=true` ignores any configured `host` value. Current guest address candidates come only from the authenticated local helper. This mode requires an existing validated `HostKeyAlias` so a changing network address never becomes the SSH trust identity.

SSH is invoked with all of:

- explicit `-i <identity>`;
- explicit `UserKnownHostsFile=<known-hosts>`;
- required explicit `HostKeyAlias=<existing-alias>` in dynamic Hyper-V mode, or optional alias in static mode;
- `StrictHostKeyChecking=yes`;
- `IdentitiesOnly=yes`;
- `BatchMode=yes`;
- bounded connect/probe timeout.

The remote command is fixed/read-only and does not use `sudo`. It reports kernel, uptime, load1, MemAvailable, swap used, root-disk total/free, CPU/memory PSI when supported, locally cached upgradable-package count, reboot-required marker, and the configured GitHub Runner systemd service state. The configured user/unit and each candidate target are syntax-validated before use.

When dynamic addressing is enabled, only helper-authorized/VM-present/running responses are eligible for SSH target selection, no more than four filtered candidates are attempted, and no candidate is persisted. If configuration is absent/invalid, helper authorization/observation fails, no safe candidate exists, SSH trust fails, or telemetry cannot be parsed, report Unknown rather than scan the network, regenerate trust, or fabricate failure/readiness.

## GitHub Runner

Runner control-plane status is a separate read-only source. Host Agent invokes existing authenticated `gh api` access for the locally configured repository and runner ID, then parses only id/name, online/offline, busy, and labels. No token is accepted by Host Agent configuration; no registration/label mutation exists. Busy maps to Blue activity while online health remains Healthy. The owner UI/normal copied diagnostics do not emit the concrete runner ID, name, or label values; they surface presence/count plus online/busy state to keep routine diagnostics sanitizable.

## Machine-local configuration

Public templates: `config/host-agent.Local.example.json` and `config/hyperv-observer.Local.example.json`.

Actual machine-specific configuration must stay local/gitignored. Host Agent lookup order is explicit `LDW_HOST_AGENT_CONFIG`, `%LOCALAPPDATA%\LowcountryDigitalWorks\HostAgent\host-agent.Local.json`, then an adjacent `host-agent.Local.json`. Helper authorization defaults to `%ProgramData%\LowcountryDigitalWorks\HostAgent\hyperv-observer.Local.json` unless `--config <local-path>` is supplied. Configuration errors are handled without echoing path content, SIDs, or secrets into normal Host Agent diagnostics.

Guest address candidates received from the helper are runtime-only values. They must never be copied back into machine-local configuration or exposed through routine diagnostics/logging.

## Privilege and mutation boundary

The tray/UI and ordinary probes run as the owner and explicitly refuse elevated execution. No tray manifest requests elevation. The Hyper-V observer is a separate executable and cannot turn the tray into a privileged process.

The helper is read-only and local-only. It has no service control, VM control, CI Normal/Boost mutation, reboot/shutdown, runner mutation, TCP/HTTP listener, remote push control, arbitrary shell request, or generic elevated command surface.

Persistent installation remains separately gated. Before exact-candidate acceptance, validation may build/test the helper and prove that it refuses unelevated execution, but it must not register/start a persistent privileged service/task merely to obtain live Hyper-V evidence. An eventual live end-to-end proof requires an owner-approved UAC/elevated helper launch with a protected machine-local explicit-user allowlist; persistent scheduling/service installation remains a later ORCH01 gate.
