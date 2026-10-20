# LDW Local Admin Broker & Local Secret Handoff (LDW01-OWNER-ADMIN-BROKER-001)

The Local Admin Broker (`LDW.AdminBroker`) and Local Secret Store (`LDW.LocalSecretStore`) provide a deterministic, source-controlled local execution and credential boundary on LDW01.

It allows GM and approved LDW automation to invoke a narrow set of authenticated, typed, audited owner-authorized operations without exposing arbitrary shell surface or secret material through chat, Desktop Commander history, process arguments, or transcripts.

## Core Scope

### 1. Admin Broker Operations Enum (`LDW.AdminBroker`)

The broker accepts strictly typed requests over local secure named pipe IPC (`\\.\pipe\LDW.AdminBroker.v1`) for 6 allowed operations:

- `CODYNC_BOT_CREATE` — Registers a new Codync bot definition in local protected store with exact readback.
- `CODYNC_BOT_UPDATE` — Updates an existing Codync bot definition with exact readback.
- `CODYNC_BOT_DELETE` — Removes a Codync bot definition with exact readback and removal confirmation.
- `HOST_AGENT_STATUS` — Queries status of explicitly reviewed host agent components (`TrayAutostart`, `HyperVObserver`, `LiveProbe`, `SshLinuxNode`).
- `HOST_AGENT_RESTART_REVIEWED_COMPONENT` — Restarts an explicitly reviewed host agent component. Unapproved targets fail closed (`TARGET_MISMATCH`).
- `HOST_AGENT_REPAIR_REVIEWED_INSTALL` — Verifies configuration integrity, file permissions, and DACL settings for reviewed host agent components.

All requests use strict JSON parsing. Any unrecognized top-level properties, missing parameters, or invalid operation names fail closed immediately.

### 2. Local Secret Store & Corsair/Neon Handoff (`LDW.LocalSecretStore`)

The local secret store uses Windows DPAPI (`ProtectedData.Protect` / `Unprotect` with `DataProtectionScope.CurrentUser`) to protect local secrets.

- Secret ID: `CORSAIR_NEON_DATABASE_URL`
- Operations: `SetSecret`, `GetStatus` (metadata only, no plaintext), `RotateSecret`, `RemoveSecret`.
- Bounded Launcher (`CorsairNeonLauncher`): Decrypts `CORSAIR_NEON_DATABASE_URL` in-memory only and injects it as an environment variable into a child process for the Corsair/Neon proof. Standard output and error streams are sanitized so plaintext credentials never enter logs, arguments, or transcripts.

## Privilege & Security Model

- **Unelevated Tray Surface:** Normal-user Host Agent tray remains unelevated.
- **IPC Access Control:** IPC named pipe uses an explicit DACL granting access only to `LocalSystem`, `Administrators`, and explicitly configured owner user SIDs (`S-1-5-21-...`). Broad well-known SIDs (Everyone, Interactive, Authenticated Users) are rejected.
- **Fail Closed:** Target mismatch, unknown JSON fields, missing secrets, or unauthorized caller SIDs fail closed.
- **Secret Redaction:** Plaintext secrets never appear in logs, process command lines, stdout/stderr, responses, or Git diffs.
- **Bounded Audit Log:** All operations write secret-free JSON audit entries to `%LOCALAPPDATA%\LowcountryDigitalWorks\AdminBroker\audit-log.jsonl`.

## Build and Test Runbook

From `host-agent/`:

```powershell
dotnet build LDW.HostAgent.sln -c Release
dotnet run --project tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj -c Release
```
