# LDW Host Agent

Host Agent is a device-first, local status surface for owner-controlled LDW computers and headless Linux nodes. The tray process runs as the signed-in user. GitHub and the local machine remain the sources of truth; this application observes state and offers bounded local controls only.

## V0.1 foundation

- `src/LDW.HostAgent.Core` contains the platform-neutral device/component model, desired-state evaluation, health aggregation, telemetry contracts, and probe interfaces.
- `src/LDW.HostAgent.Windows` is the unelevated Windows tray/status shell and first local system probe.
- `tests/LDW.HostAgent.Core.Tests` is a deterministic, dependency-free contract test executable.
- `docs/PROBE_CONTRACT.md` defines adapters for Tailscale, RustDesk, Desktop Commander, WSL Ubuntu/Cursor Worker, CI-RUNNER-001/GitHub Runner, and off-site Linux nodes.

The first release does not start/stop services, restart devices, change CI profiles, or expose a network listener. A probe reports evidence; it cannot silently perform a mutation. Any future restart/shutdown/profile action requires an explicit UI confirmation and a narrow allowlisted executor.

## Build and validate

Use the .NET 10 SDK. From this directory:

```powershell
dotnet run --project tests/LDW.HostAgent.Core.Tests/LDW.HostAgent.Core.Tests.csproj
dotnet build src/LDW.HostAgent.Windows/LDW.HostAgent.Windows.csproj
```

The Windows shell targets Windows Desktop. Core contract tests run on Windows or Linux. No NuGet packages are required.

Machine identity, node addresses, SSH keys, tokens, and private connection details belong in local secure configuration, never this public repository.
