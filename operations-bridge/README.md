# LDW Operations Bridge (BRIDGE-001A + CODYNC-001)

This folder contains the smallest read-only source candidate for OPS-BRIDGE-001 issue #43.

Scope in this slice:
- normal-user .NET bridge client with outbound `ClientWebSocket` transport (no local inbound listener);
- protocol/envelope and fail-closed validation at Worker/DO acceptance and again before local execution;
- Cloudflare Worker + SQLite Durable Object relay using WebSocket Hibernation (`acceptWebSocket` / `getWebSockets` / attachments);
- separate Site and Bridge credentials with server-bound bridge identity;
- read-only browser adapter abstraction with exact-domain/subdomain allowlisted metadata only;
- typed Codync health/approved roster/exact send/correlated wait adapter over Codync's supported loopback HTTP/SSE API;
- deterministic synthetic tests for auth roles, delivery, replay/idempotency, correlation, hibernation rehydration, SQLite persistence, and Codync operation schemas.

Out of scope in this slice:
- no executable bridge host or deployment in this source slice; an accepted normal-user runner and reviewed runtime configuration are still required;
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

- closed operation enum (`browser.health`, `browser.list_tabs`, `browser.read_tab`, `codync.health`, `codync.list_approved_bots_groups`, `codync.send_exact`, `codync.wait_read_exact`) with fail-closed unknown operation and argument schemas;
- protocol/client/TTL/idempotency/correlation checks fail closed at relay and client;
- dispatch is delivered over the connected outbound bridge socket; delivered only after successful send;
- terminal result constrained to `PASS | BLOCKED | FAILED | STALE | AMBIGUOUS` with bounded evidence/payload;
- Bridge bearer attach requires secure `wss:` plus exact trusted Worker endpoint configuration;
- terminal acceptance requires exact dispatch id + idempotency key + correlation/connection identity;
- terminal provenance includes bridge runtime/version, operation/result class, and started/completed timestamps;
- disconnect/expiry/adapter-fault paths resolve fail-closed to `FAILED`/`STALE`/`AMBIGUOUS` (never manufactured `PASS`) on both in-memory and SQLite DO stores;
- synthetic adapter filters to exact allowlisted hosts/subdomains and metadata-only output.
- Codync uses only `127.0.0.1:19222` and fixed `health`, `events`, `send`, and `history` methods; bearer access is injected by the runtime's owner-protected credential provider and never returned or logged.
- Codync destinations are pinned by ID/name/kind and group membership from #621/#644; live roster mismatches fail closed. Group sends require explicit selected-member mentions and reject `@all`/`@everyone`.
- Codync replies require the exact dispatch-derived client nonce, root entry ID/sequence/turn, exact destination and expected author, provider start state, and final agent entry. Accepted send alone is explicitly not provider-positive completion.

## Rollback / cleanup

These changes are source-only. Rollback requires only reverting/removing the `operations-bridge` source and docs in Git. No machine startup state, scheduled tasks, worker secrets, or Cloudflare runtime state are created by this slice.
