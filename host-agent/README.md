# LDW Host Agent

Host Agent is a device-first, local status surface for owner-controlled LDW computers and headless Linux nodes. The Windows tray process is intentionally normal-user/unelevated. GitHub and the observed machines remain authoritative; Host Agent is a read-only status surface in the current slice.

## V0.1 accepted foundation

- `src/LDW.HostAgent.Core` contains the platform-neutral device/component model, desired-state evaluation, runtime/session context, health aggregation, telemetry contracts, strict SSH policy, and parser/state-mapping contracts.
- Health and CI activity are separate: Green = desired state met, Blue = active CI job, Purple = CI Boost enabled, Yellow = degraded/attention, Red = confirmed failure/down, Gray = unknown/initializing.
- Intentionally stopped/disabled/on-demand components remain healthy when that matches desired state. `RunningAfterLogin` uses explicit owner-session context.
- Dependency availability is checked while a dependent component is expected to be active; intentionally inactive pre-login/on-demand components do not fail merely because their dependencies are also inactive.

## Read-only live-adapter slice

`src/LDW.HostAgent.Windows` wires the accepted model to normal-user observations for:

- Windows owner-session state via the current WTS session;
- Tailscale service/startup posture + sanitized `tailscale status --json` readiness and read-only unattended/server-mode (`ForceDaemon`) verification when available;
- RustDesk service/runtime readiness;
- Desktop Commander owner-scoped scheduled-task state;
- WSL distro presence/running state without starting a stopped distro;
- Cursor Worker `systemctl is-active` only when its WSL distro is already running;
- a Linux CI node over strict host-key-verified SSH using an existing identity/known-hosts file and optional existing host-key alias;
- GitHub Runner online/busy/id/labels through existing authenticated `gh api` access;
- Windows memory/commit/disk/short CPU telemetry integrated into the device snapshot and status UI.

The Linux SSH probe is fixed/read-only: kernel, uptime, load, MemAvailable, swap, root-disk capacity, CPU/memory PSI when supported, cached update count, reboot-required marker, and the configured runner systemd unit. It never uses `sudo` and refuses to run without explicit non-empty known-hosts and existing identity files.

The tray refuses to start elevated. There are no service/VM/power controls, remote push controls, runner mutations, CI profile mutations, or TCP/HTTP listeners.

## Read-only Hyper-V observer boundary

`src/LDW.HostAgent.HyperVObserver` is a separate elevated Windows helper for the single allowlisted VM `CI-RUNNER-001`. It is not a general Hyper-V control service.

- The helper refuses unelevated execution; the Host Agent tray remains unelevated.
- IPC is one local named pipe created through the Windows native pipe API with an explicit protected DACL. Only LocalSystem, Administrators, and configured explicit owner-user SIDs receive pipe access; remote pipe clients are rejected. The server then independently identifies the connected client and authorizes only a configured explicit user SID, so broad groups do not become a command surface.
- The tray connects locally using identification-level impersonation only. Before sending its fixed request it resolves the pipe server PID and verifies that server's process token is elevated and belongs either to LocalSystem or to the same explicit owner SID; a non-elevated or unexpected-user pipe server is rejected.
- The request contract has one exact versioned operation and contains no VM name, command, script, or shell text supplied by the tray.
- The privileged observation source uses a fixed read-only `Get-VM` / `Get-VMNetworkAdapter` script containing the allowlisted VM literal. No request value is interpolated into PowerShell.
- Only authorization status, VM existence, sanitized state/running state, filtered guest-address candidates, and non-sensitive error codes cross IPC. Raw PowerShell/Hyper-V output is not returned or logged.
- Loopback, link-local/APIPA, multicast/broadcast, invalid, duplicate, and excess candidates are rejected or bounded before SSH selection.
- Guest addresses are transient connection targets only. They are not written to configuration, repository files, logs, status summaries, copied diagnostics, issues, or PRs.
- When `linuxNode.useHyperVObserver` is enabled, Host Agent requires an existing `HostKeyAlias`; the helper-supplied address is used only as the network target while existing identity/known-hosts trust remains authoritative. SSH still uses strict host-key checking, `IdentitiesOnly`, `BatchMode`, and bounded timeouts.
- If the helper is absent/unauthorized, the VM is absent/not running, no safe address exists, or strict SSH fails, Linux telemetry remains Unknown rather than weakening trust or fabricating health.

The helper's machine-local allowlist defaults to `%ProgramData%\LowcountryDigitalWorks\HostAgent\hyperv-observer.Local.json`; an explicit local path may be supplied with `--config <path>`. Use `config/hyperv-observer.Local.example.json` only as the public shape. Real SIDs remain machine-local and `*.Local.json` is gitignored.

This repository slice does **not** install/register/start a persistent privileged service or task. Persistent installation and live elevated proof remain explicit post-review gates.

## Machine-local Host Agent configuration

Copy the shape from `config/host-agent.Local.example.json`, but keep the actual file outside Git or named `host-agent.Local.json` (already ignored). Configuration lookup order is:

1. `LDW_HOST_AGENT_CONFIG` when explicitly set;
2. `%LOCALAPPDATA%\LowcountryDigitalWorks\HostAgent\host-agent.Local.json`;
3. `host-agent.Local.json` beside the executable.

Machine identity, scheduled-task names, Linux target/user, SSH identity/known-hosts paths, systemd unit names, private repository names, runner IDs, addresses, tokens, credentials, and helper caller SIDs must remain machine-local. Raw command output is never copied into normal diagnostics.

For an existing dynamic Hyper-V Linux node, set `linuxNode.useHyperVObserver` only after the helper has been independently reviewed and the elevated-helper launch/install path is approved. In helper mode, `linuxNode.host` is ignored and must not be used to persist the current dynamic address; an existing trusted `hostKeyAlias` is required.

## Build and validate

Use the .NET 10 SDK. From this directory:

```powershell
dotnet build LDW.HostAgent.sln -c Release
dotnet run --project tests/LDW.HostAgent.Core.Tests/LDW.HostAgent.Core.Tests.csproj -c Release
dotnet run --project tests/LDW.HostAgent.HyperVObserver.Tests/LDW.HostAgent.HyperVObserver.Tests.csproj -c Release
dotnet run --project tools/LDW.HostAgent.LiveProbe/LDW.HostAgent.LiveProbe.csproj -c Release
```

The live-probe tool is read-only and emits sanitized component summaries for bounded local validation. Contract tests use only synthetic/documentation address values and do not query Hyper-V. No external NuGet packages are required.
