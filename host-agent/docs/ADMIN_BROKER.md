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
- **Audit:** The logger persists bounded, fixed metadata records, redacts target and summary text, rotates at 5 MiB, and propagates write failures before a response is sent. Interactive fixed-secret add/replace/remove is additionally gated by a durable `SecretSetRequested` / `SecretRemoveRequested` audit-intent record before the DPAPI store mutation; if that write fails, the mutation delegate is never invoked. These intent records are not success records, so a later store failure cannot be misrepresented as a completed change. There are still no live provider/broker mutating operations.
- **Secrets:** The fixed proof launches only the companion probe. The secret value is supplied through that child's environment and is absent from arguments, response, audit, and retained output.

### 3. Interactive secret lifecycle and fixed proof child

Run `LDW.AdminBroker.Host.exe` with no arguments as the intended Windows owner. The menu supports status, hidden add/replace input with confirmation, explicit remove confirmation, and the broker listener. Input uses intercepted key events, never command-line arguments or console echo. Production storage uses CurrentUser DPAPI and the one fixed secret identity `CORSAIR_NEON_DATABASE_URL`.

The fixed `LDW.LocalSecretProbe.exe` accepts no arguments or input/network request; it checks only whether the fixed environment variable is non-empty and emits only `SECRET_PRESENT` or a fixed failure token. `CorsairNeonLauncher` resolves this companion from its own application directory, disables shell execution, supplies no arguments, injects the secret only into the child environment, bounds and discards unexpected output, and returns only fixed tokens. This synthetic proof is not a Corsair/Neon connection and does not establish a real secret/account/resource.

### 4. Autonomous Reviewed Elevated-Operation Path (ADMIN-BROKER-PRIV-001 / #176)

To eliminate repetitive interactive UAC friction for authorized work on LDW01 without introducing an insecure generic shell or always-running SYSTEM daemon, an on-demand reviewed execution substrate is implemented behind the Admin Broker:

- **Broker Operations:** `ADMIN_REVIEWED_OPERATION_RUN` and `ADMIN_REVIEWED_OPERATION_GET_RESULT` over the existing `LDW.AdminBroker.v1` local current-user pipe.
- **Strict Parameter Constraints:** Callers may supply only a bounded `operationId` from a source-controlled closed registry (and `correlationId` UUID for result query). No caller-supplied command, executable, script path, argument vector, URL, or environment variables are accepted; any extraneous property fails closed.
- **On-Demand Privileged Task:** Modeled on the #92 fixed task pattern. Scheduled task `\LDW-ADMIN-REVIEWED-OPERATION` has zero triggers, schedules, or listeners. It runs elevated in the owner session only on demand. Normal owner SID is granted task execute permissions (`GRGX` / `0x001200A9`), but task write/modify is strictly denied (`TASK_DACL_REFUSED`).
- **Protected Layout:** Installed under `%ProgramData%\LDW\PrivilegedControl`:
  - `bin\`: Protected script directory (SYSTEM/Administrators write only). Protected by pinned SHA-256 worker hash verification (`PROVENANCE_MISMATCH` on any drift).
  - `requests\`: Bounded request slot (`request.json`) created via atomic rename (`.pending-<correlationId>.json` -> `request.json`). Second concurrent request while slot is occupied returns `BUSY`.
  - `results\`: Bounded result storage (`<correlationId>.json`). Bounded schema and allowlisted reason codes only.
  - `lock\`: Single-operation exclusive file lock (`operation.lock`) serializing execution.
- **Closed Registry & Proof Operation:**
  - `ELEVATED_IDENTITY_PROOF`: Inspects platform elevation facts (`WindowsBuiltInRole.Administrator` and `S-1-5-32-544` token presence) and returns bounded verification without modifying system state. Fails closed (`ELEVATION_REQUIRED`) if executed in an unelevated context.
- **Output and Leakage Prevention:** Raw child stdout and stderr are redirected to `Stream.Null`. Result files strip non-whitelisted characters, newlines, and unapproved property keys.

## Build and Test Runbook

From `host-agent/`:

```powershell
dotnet build LDW.HostAgent.sln -c Release
dotnet run --project tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj -c Release
dotnet run --project tests/LDW.HostAgent.Core.Tests/LDW.HostAgent.Core.Tests.csproj -c Release
dotnet run --project tests/LDW.HostAgent.HyperVObserver.Tests/LDW.HostAgent.HyperVObserver.Tests.csproj -c Release
pwsh deploy/tests/Test-DeploymentContracts.ps1
pwsh deploy/tests/Test-AdminBrokerPackageContracts.ps1
pwsh deploy/tests/Test-AdminPrivilegedHelperContracts.ps1
```

The build and tests do not install or start the host listener, write the owner DPAPI store, create secrets, or contact providers. Live broker, Codync, Host Agent repair, provider connection, deployment, and startup behavior remain separate authorization gates.
