# LDW Local Admin Broker & Local Secret Handoff (LDW01-OWNER-ADMIN-BROKER-001)

This source contains contract scaffolding only. No runnable broker listener, ACL-backed transport, Codync adapter, Host Agent operation adapter, or Corsair proof launcher is implemented. The advertised operations return `NOT_IMPLEMENTED`; no state-changing operation is available.

## Core Scope

### 1. Admin Broker Operations Enum (`LDW.AdminBroker`)

The contract names six operations, but the named-pipe transport is unavailable. `AdminBrokerPipeServer.ServeOneAsync` throws `NotSupportedException`; it does not create a listener or DACL. Requests require a UUID request ID and bounded JSON. Create/update require exactly `name`, `description`, `endpointUrl`, and `capabilities` with string/string/string/array types; delete and Host Agent operations accept no parameters. No adapter consumes these requests.

- Codync create/update/delete — Unavailable; no real loopback adapter is present.
- Host Agent status/restart/repair — Unavailable; no reviewed runtime adapter is present.

The request parser rejects unknown top-level properties, duplicate properties, non-UUID request IDs, oversized requests, and any nonempty parameter object. The in-process engine caches request IDs for two minutes and reports duplicates without dispatching.

### 2. Local Secret Store & Corsair/Neon Handoff (`LDW.LocalSecretStore`)

The local secret store uses Windows DPAPI (`ProtectedData.Protect` / `Unprotect` with `DataProtectionScope.CurrentUser`) to protect local secrets.

- Secret ID: `CORSAIR_NEON_DATABASE_URL` only. The store exposes set/rotate/remove and status containing existence, ID, and update time. Production protection requires Windows CurrentUser DPAPI and fails closed elsewhere. Tests inject a test-only fake protector.
- `CorsairNeonLauncher` always returns `NOT_IMPLEMENTED`; it accepts no executable or argument inputs because no frozen proof contract exists.

## Privilege & Security Model

- **Unelevated Tray Surface:** Normal-user Host Agent tray remains unelevated.
- **Transport:** Unavailable. There is no listener or runtime ACL/caller impersonation proof.
- **Audit:** The logger persists bounded metadata records and propagates write failures. Since no broker transport or mutations are available, it is not an execution gate for a live operation.
- **Secrets:** This source does not launch a child process. Secret values must not be included in logs or responses.

## Build and Test Runbook

From `host-agent/`:

```powershell
dotnet build LDW.HostAgent.sln -c Release
dotnet run --project tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj -c Release
```
