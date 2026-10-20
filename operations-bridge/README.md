# LDW Operations Bridge (BRIDGE-001A)

This folder contains the smallest read-only source candidate for OPS-BRIDGE-001 issue #43.

Scope in this slice:
- normal-user .NET bridge client with outbound `ClientWebSocket` transport (no local inbound listener);
- protocol/envelope and fail-closed validation at Worker/DO acceptance and again before local execution;
- Cloudflare Worker + SQLite Durable Object relay using WebSocket Hibernation (`acceptWebSocket` / `getWebSockets` / attachments);
- separate Site and Bridge credentials with server-bound bridge identity;
- read-only browser adapter abstraction with exact-domain/subdomain allowlisted metadata only;
- deterministic synthetic tests for auth roles, delivery, replay/idempotency, correlation, hibernation rehydration, and SQLite persistence.

Out of scope in this slice:
- no Codync adapter implementation;
- no chat relay implementation;
- no local startup registration, scheduled task, service install, or autostart;
- no deployment/mutation of Cloudflare resources or secrets;
- no browser cookie/session export, arbitrary JavaScript, shell/admin RPC, or broad filesystem access.

## Layout

- `src/LDW.OperationsBridge.Core` - protocol, validator, relay state machine, browser adapter contracts.
- `src/LDW.OperationsBridge.Client` - outbound client, validation-before-execution, `ClientWebSocketBridgeTransport`.
- `tests/LDW.OperationsBridge.Tests` - deterministic contract tests with synthetic fixtures.
- `relay-cloudflare` - authenticated Worker + SQLite Durable Object hibernating relay source and fixtures.

## Auth roles

| Role | Credential (secret) | Allowed |
|------|---------------------|---------|
| Site | `SITE_DISPATCH_TOKEN` | `POST /relay/dispatch`, `GET /relay/dispatch/:id` |
| Bridge | `BRIDGE_CLIENT_TOKEN` | `GET /relay/connect` WebSocket upgrade only |

`BRIDGE_ID` is server-configured. Site callers never receive local connection IDs. Terminal results are accepted only from the authenticated hibernated WebSocket attachment, never from Site HTTP.

## Build and test

From this folder:

```powershell
dotnet build LDW.OperationsBridge.sln -c Release
dotnet run --project tests/LDW.OperationsBridge.Tests/LDW.OperationsBridge.Tests.csproj -c Release
node --test relay-cloudflare/tests/*.test.mjs
```

Optional (no deploy): `npx wrangler deploy --dry-run` / `npx wrangler check` when wrangler is available.

## Security posture in this slice

- closed operation enum (`browser.health`, `browser.list_tabs`, `browser.read_tab`) with fail-closed unknown operation behavior;
- protocol/client/TTL/idempotency/correlation checks fail closed at relay and client;
- dispatch is delivered over the connected outbound bridge socket; delivered only after successful send;
- terminal result constrained to `PASS | BLOCKED | FAILED | STALE | AMBIGUOUS` with bounded evidence/payload;
- Bridge bearer attach requires secure `wss:` plus exact trusted Worker endpoint configuration;
- terminal acceptance requires exact dispatch id + idempotency key + correlation/connection identity;
- terminal provenance includes bridge runtime/version, operation/result class, and started/completed timestamps;
- disconnect/expiry/adapter-fault paths resolve fail-closed to `FAILED`/`STALE`/`AMBIGUOUS` (never manufactured `PASS`) on both in-memory and SQLite DO stores;
- synthetic adapter filters to exact allowlisted hosts/subdomains and metadata-only output.

## Rollback / cleanup

This candidate is source-only. Rollback requires only reverting/removing the `operations-bridge` source and docs in Git. No machine startup state, scheduled tasks, worker secrets, or Cloudflare runtime state are created by this slice.
