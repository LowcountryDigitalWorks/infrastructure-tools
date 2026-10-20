# Operations Bridge Notes

## BRIDGE-001A status

`operations-bridge/` contains a bounded read-only source candidate for OPS-BRIDGE-001 (#43) using:
- normal-user .NET local process boundary with outbound `ClientWebSocket` only;
- separate Site/Bridge credentials and server-bound bridge identity;
- Cloudflare Worker + SQLite Durable Object WebSocket Hibernation transport;
- fail-closed protocol + correlation state machine with immutable one-terminal-result semantics;
- browser metadata-only read adapter with exact-domain/subdomain allowlisting.

Cloud relay state in this candidate is intentionally transport/correlation only and does not become an LDW authority or queue database.

## Runbook (source validation only)

1. Build: `dotnet build operations-bridge/LDW.OperationsBridge.sln -c Release`
2. Run deterministic tests: `dotnet run --project operations-bridge/tests/LDW.OperationsBridge.Tests/LDW.OperationsBridge.Tests.csproj -c Release`
3. Run relay synthetic tests: `node --test operations-bridge/relay-cloudflare/tests/*.test.mjs`
4. Optional wrangler dry-run/check when available (no deploy).
5. Inspect diff for secrets/private identifiers before commit.

## Cleanup / rollback

No runtime installation/deployment is performed by this source slice. Cleanup is a git revert/removal of:
- `operations-bridge/`
- this documentation file
- any top-level docs index references.
