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

The tray refuses to start elevated. This slice contains no service/VM/power controls, Hyper-V helper, network listener, remote push control, runner mutation, or CI profile mutation.

## Machine-local configuration

Copy the shape from `config/host-agent.Local.example.json`, but keep the actual file outside Git or named `host-agent.Local.json` (already ignored). Configuration lookup order is:

1. `LDW_HOST_AGENT_CONFIG` when explicitly set;
2. `%LOCALAPPDATA%\LowcountryDigitalWorks\HostAgent\host-agent.Local.json`;
3. `host-agent.Local.json` beside the executable.

Machine identity, scheduled-task names, Linux target/user, SSH identity/known-hosts paths, systemd unit names, private repository names, runner IDs, addresses, tokens, and credentials must remain machine-local. Raw command output is never copied into normal diagnostics.

## Build and validate

Use the .NET 10 SDK. From this directory:

```powershell
dotnet run --project tests/LDW.HostAgent.Core.Tests/LDW.HostAgent.Core.Tests.csproj
dotnet build src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj -c Release
dotnet run --project tools/LDW.HostAgent.LiveProbe/LDW.HostAgent.LiveProbe.csproj -c Release
```

The live-probe tool is read-only and emits sanitized component summaries for bounded local validation. Core tests use synthetic input and do not contact local/remote services. No external NuGet packages are required.
