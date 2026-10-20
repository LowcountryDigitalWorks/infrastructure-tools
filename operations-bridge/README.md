# LDW Operations Bridge (BRIDGE-001A)

This folder contains the smallest read-only source candidate for OPS-BRIDGE-001 issue #43.

Scope in this slice:
- normal-user .NET bridge client skeleton with event-driven outbound transport semantics;
- protocol/envelope and deterministic fail-closed validation;
- transport/correlation relay state machine plus minimal Cloudflare Worker + SQLite Durable Object source mapping;
- read-only browser adapter abstraction with sanitized allowlisted tab metadata only;
- deterministic synthetic tests for schema/auth/replay/idempotency/reconnect/correlation behavior.

Out of scope in this slice:
- no Codync adapter implementation;
- no chat relay implementation;
- no local startup registration, scheduled task, service install, or autostart;
- no deployment/mutation of Cloudflare resources or secrets;
- no browser cookie/session export, arbitrary JavaScript, shell/admin RPC, or broad filesystem access.

## Layout

- `src/LDW.OperationsBridge.Core` - protocol, validator, relay state machine, browser adapter contracts.
- `src/LDW.OperationsBridge.Client` - outbound normal-user client and event-driven dispatch handler.
- `tests/LDW.OperationsBridge.Tests` - deterministic contract tests with synthetic fixtures.
- `relay-cloudflare` - minimal authenticated Worker + SQLite Durable Object relay source with synthetic fixtures/tests.

## Build and test

From this folder:

```powershell
dotnet build LDW.OperationsBridge.sln -c Release
dotnet run --project tests/LDW.OperationsBridge.Tests/LDW.OperationsBridge.Tests.csproj -c Release
node --test relay-cloudflare/tests/*.test.mjs
```

## Security posture in this slice

- closed operation enum (`BrowserHealth`, `ListTabs`, `ReadTabMetadata`) with fail-closed unknown operation behavior;
- protocol/client/TTL/idempotency/correlation checks fail closed;
- terminal result constrained to `PASS | BLOCKED | FAILED | STALE | AMBIGUOUS`;
- disconnect/lost-correlation scenarios cannot synthesize `PASS`;
- synthetic adapter filters to allowlisted hosts and metadata-only output.

## Rollback / cleanup

This candidate is source-only. Rollback requires only reverting/removing the `operations-bridge` source and docs in Git. No machine startup state, scheduled tasks, worker secrets, or Cloudflare runtime state are created by this slice.
