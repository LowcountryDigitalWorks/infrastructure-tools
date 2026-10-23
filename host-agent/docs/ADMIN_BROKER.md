# LDW Local Admin Broker & Local Secret Handoff (LDW01-OWNER-ADMIN-BROKER-001)

The first source-only runnable boundary is implemented. It provides a normal-user local named-pipe host, a fixed CurrentUser DPAPI interactive secret-store lifecycle, and a synthetic fixed child-process proof. The advertised Codync and Host Agent operations still return `NOT_IMPLEMENTED`; no state-changing broker operation is available.

## Core Scope

### 1. Admin Broker Operations Enum (`LDW.AdminBroker`)

The contract names six operations. `LDW.AdminBroker.Host` creates only the fixed `LDW.AdminBroker.v1` local pipe with `PipeOptions.CurrentUserOnly`, derives the single permitted SID from its normal-user process token, and verifies the connected caller SID through pipe impersonation before policy or engine invocation. Clients must request an impersonation-capable pipe token; a missing caller token fails closed. The byte stream is one bounded UTF-8 JSON line per connection; the server handles one client at a time. There is no elevated listener, service, startup registration, remote pipe, or caller-configurable pipe/SID/operation surface.

Requests require a UUID request ID and bounded JSON. Create/update require exactly `name`, `description`, `endpointUrl`, and `capabilities` with string/string/string/array types; field lengths and capability count are bounded, endpoint credentials/fragments are rejected, and delete/Host Agent operations accept no parameters. Strict parsing and policy validation run before the engine. Every accepted request receives a short-TTL duplicate check; handlers remain unavailable and no adapter consumes requests.

- Codync create/update/delete — Unavailable; no real loopback adapter is present.
- Host Agent status/restart/repair — Unavailable; no reviewed runtime adapter is present.

The request parser rejects unknown top-level properties, duplicate properties, non-UUID request IDs, oversized requests, and any nonempty parameter object. The in-process engine caches request IDs for two minutes and reports duplicates without dispatching.

### 2. Local Secret Store & Corsair/Neon Handoff (`LDW.LocalSecretStore`)

The local secret store uses Windows DPAPI (`ProtectedData.Protect` / `Unprotect` with `DataProtectionScope.CurrentUser`) to protect local secrets.

- Secret ID: `CORSAIR_NEON_DATABASE_URL` only. The store exposes set/rotate/remove and status containing existence, ID, and update time. Production protection requires Windows CurrentUser DPAPI and fails closed elsewhere. Tests inject a test-only fake protector.
- `CorsairNeonLauncher` always returns `NOT_IMPLEMENTED`; it accepts no executable or argument inputs because no frozen proof contract exists.

## Privilege & Security Model

- **Unelevated Tray Surface:** Normal-user Host Agent tray remains unelevated.
- **Transport:** Local current-user-only named pipe with explicit owner SID caller verification. This is source and deterministic local test evidence, not proof of deployment on any machine.
- **Audit:** The logger persists bounded, fixed metadata records, redacts target and summary text, rotates at 5 MiB, and propagates write failures before a response is sent. There are still no live mutating operations.
- **Secrets:** The fixed proof launches only the companion probe. The secret value is supplied through that child's environment and is absent from arguments, response, audit, and retained output.

### 3. Interactive secret lifecycle and fixed proof child

Run `LDW.AdminBroker.Host.exe` with no arguments as the intended Windows owner. The menu supports status, hidden add/replace input with confirmation, explicit remove confirmation, and the broker listener. Input uses intercepted key events, never command-line arguments or console echo. Production storage uses CurrentUser DPAPI and the one fixed secret identity `CORSAIR_NEON_DATABASE_URL`.

The fixed `LDW.LocalSecretProbe.exe` accepts no arguments or input/network request; it checks only whether the fixed environment variable is non-empty and emits only `SECRET_PRESENT` or a fixed failure token. `CorsairNeonLauncher` resolves this companion from its own application directory, disables shell execution, supplies no arguments, injects the secret only into the child environment, bounds and discards unexpected output, and returns only fixed tokens. This synthetic proof is not a Corsair/Neon connection and does not establish a real secret/account/resource.

## Build and Test Runbook

From `host-agent/`:

```powershell
dotnet build LDW.HostAgent.sln -c Release
dotnet run --project tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj -c Release
dotnet run --project tests/LDW.HostAgent.Core.Tests/LDW.HostAgent.Core.Tests.csproj -c Release
dotnet run --project tests/LDW.HostAgent.HyperVObserver.Tests/LDW.HostAgent.HyperVObserver.Tests.csproj -c Release
```

The build and tests do not install or start the host listener, write the owner DPAPI store, create secrets, or contact providers. Live broker, Codync, Host Agent repair, provider connection, deployment, and startup behavior remain separate authorization gates.
