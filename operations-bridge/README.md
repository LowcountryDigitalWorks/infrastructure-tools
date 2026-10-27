# LDW Operations Bridge (BRIDGE-001A + CODYNC-001)

This folder contains the bounded Operations Bridge source for OPS-BRIDGE-001 issue #43 plus the separately reviewed typed REDRIX/Dragonfly owner-control path under #98.

Scope in this slice:
- normal-user .NET executable bridge runner with outbound `ClientWebSocket` transport (no local inbound listener);
- protocol/envelope and fail-closed validation at Worker/DO acceptance and again before local execution;
- Cloudflare Worker + SQLite Durable Object relay using WebSocket Hibernation (`acceptWebSocket` / `getWebSockets` / attachments);
- separate Site and Bridge credentials with server-bound bridge identity;
- read-only Opera DevTools MCP 0.7.0 adapter; fixed stdio client invokes only typed `list_pages` and returns sanitized metadata from the dedicated LDW profile;
- typed Codync health/approved roster/exact send/correlated wait adapter over Codync's supported loopback HTTP/SSE API;
- Linux REDRIX mode with fixed `dragonfly-redrix-01` identity and only `dragonfly.runner.status`, `dragonfly.runner.start`, and `dragonfly.runner.drain`;
- deterministic synthetic tests for auth roles, delivery, replay/idempotency, correlation, hibernation rehydration, SQLite persistence, Codync operation schemas, and typed runner configuration.

Out of scope in this slice:
- no live Bridge credential provisioning, provider deployment, startup registration, scheduled task, service install, or autostart;
- no chat relay implementation;
- no deployment/mutation of Cloudflare resources or secrets;
- no browser cookie/session export, arbitrary JavaScript, shell/admin RPC, or broad filesystem access;
- no GitHub queue polling/JIT authority in the REDRIX Operations Bridge bearer.

## Layout

- `src/LDW.OperationsBridge.Core` - protocol, validator, relay state machine, browser adapter contracts.
- `src/LDW.OperationsBridge.Client` - outbound client, validation-before-execution, WebSocket transport, and the fixed Opera metadata adapter.
- `src/LDW.OperationsBridge.Runner` - normal-user executable, trusted endpoint/config checks, protected credential readers, reconnect lifecycle, and sanitized status readback.
- `tests/LDW.OperationsBridge.Tests` - deterministic contract tests with synthetic fixtures.
- `relay-cloudflare` - authenticated Worker + SQLite Durable Object hibernating relay source and fixtures.
- `scripts/build-dragonfly-linux-package.sh` - exact-source self-contained `linux-x64` packager.
- `scripts/verify-dragonfly-linux-package.sh` - archive/integrity/provenance verifier.

## Auth roles

| Role | Credential (secret) | Allowed |
|------|---------------------|---------|
| Site | `SITE_DISPATCH_TOKEN` | `POST /relay/dispatch`, `GET /relay/dispatch/:id` |
| Bridge | `BRIDGE_CLIENT_TOKEN` | `GET /relay/connect` WebSocket upgrade only |

`BRIDGE_ID` is server-configured. Site callers never receive local connection IDs. Terminal results are accepted only from the authenticated hibernated WebSocket attachment, never from Site HTTP.

The Windows runner reads non-secret configuration from `%LOCALAPPDATA%\LDW\OperationsBridge\config.json` and the bearer from `%LOCALAPPDATA%\LDW\OperationsBridge\bridge-token.dpapi`, protected to the current Windows user with DPAPI. The config contains only `bridgeId` and the exact reviewed relay URI. Run `LDW.OperationsBridge.Runner --run` manually; `--status` reports sanitized lifecycle state. No CLI option accepts a bearer or arbitrary process/tool path.

The REDRIX Linux runner uses fixed identity `dragonfly-redrix-01`, exact reviewed WSS route, non-secret config at `~/.config/ldw/operations-bridge/dragonfly/config.json`, bounded health state at `~/.local/state/ldw/operations-bridge/dragonfly/health.json`, and lookup-only Secret Service access through fixed `/usr/bin/secret-tool`. No bearer is accepted from configuration, argv, environment, stdin, or plaintext file.

The browser adapter starts the fixed Node executable and `opera-devtools-mcp` 0.7.0 package entry point, verifies its manifest and MCP server identity, uses the fixed Opera binary and profile `%LOCALAPPDATA%\LDW\AutoBrowser\bridge-001a-mcp-0.7.0`, disables JavaScript evaluation and usage statistics, and calls only `list_pages`.

## Build and test

From this folder:

```powershell
dotnet build LDW.OperationsBridge.sln -c Release
dotnet run --project tests/LDW.OperationsBridge.Tests/LDW.OperationsBridge.Tests.csproj -c Release
node --test relay-cloudflare/tests/*.test.mjs
```

Optional (no deploy): `npx wrangler deploy --dry-run` / `npx wrangler check` when wrangler is available.

## REDRIX self-contained package

Issue #109 packages the accepted Dragonfly runner for Debian x86_64 without installing a standing system .NET runtime on REDRIX.

From a **clean exact Git checkout**, build with the checked-out commit SHA:

```bash
SOURCE_COMMIT="$(git rev-parse HEAD)"
bash operations-bridge/scripts/build-dragonfly-linux-package.sh "$SOURCE_COMMIT" /tmp/dragonfly-package
bash operations-bridge/scripts/verify-dragonfly-linux-package.sh \
  /tmp/dragonfly-package/ldw-operations-bridge-dragonfly-linux-x64.tar.gz \
  /tmp/dragonfly-package/ldw-operations-bridge-dragonfly-linux-x64.tar.gz.sha256 \
  "$SOURCE_COMMIT"
```

The builder fails closed unless the requested source commit equals the current clean checkout HEAD and the output directory does not already exist. It publishes `LDW.OperationsBridge.Runner` as `linux-x64`, `--self-contained true`, normalizes archive timestamps to the exact source commit timestamp, records SHA-256 + size for every payload file, and emits:

- `ldw-operations-bridge-dragonfly-linux-x64.tar.gz`;
- `ldw-operations-bridge-dragonfly-linux-x64.tar.gz.sha256`;
- an internal `manifest.json` with exact source provenance and fixed runtime/install/config/state identities.

The fixed owner-local install root is:

`~/.local/lib/ldw/operations-bridge/dragonfly`

The archive root contains only `manifest.json` plus the self-contained `payload/`. It deliberately contains **no runtime `config.json` and no credential/keyring material**. Configuration remains a separately installed non-secret file at the accepted config path; the Bridge bearer remains a separately provisioned Secret Service item.

Hosted `Dragonfly Package Validation` builds the package twice from the same exact candidate, verifies both archives and manifests, requires byte-identical archives/checksums, executes the packaged `--dragonfly-status` with `PATH=/nonexistent` to avoid reliance on a `dotnet` command, rejects configuration/credential files, and uploads the exact archive/checksum/manifest as a short-lived GitHub Actions artifact. The workflow has no schedule, no secrets, and `contents: read` only.

### Credential-free REDRIX proof boundary

After #109 source is independently accepted, the first device proof remains intentionally credential-free:

1. verify the accepted archive checksum and manifest/source commit;
2. install archive contents only into the fixed owner-local install root;
3. separately create the exact non-secret config for `dragonfly-redrix-01` and the reviewed WSS route;
4. run `payload/LDW.OperationsBridge.Runner --dragonfly-status`;
5. run `payload/LDW.OperationsBridge.Runner --dragonfly-run` with **no real Dragonfly Bridge credential present**;
6. require bounded `blocked` behavior and clean exit, with no plaintext/env/argv fallback or indefinite prompt;
7. independently verify the Dragonfly JIT controller remains STOPPED, QEMU is absent, residue is zero, and existing owner launchers/base are unchanged.

No real scoped Bridge credential or relay identity is provisioned until that proof passes and the separate owner/security gate is reached.

## Security posture in this slice

- closed operation enum with fail-closed unknown operation and argument schemas;
- protocol/client/TTL/idempotency/correlation checks fail closed at relay and client;
- dispatch is delivered over the connected outbound bridge socket; delivered only after successful send;
- terminal result constrained to `PASS | BLOCKED | FAILED | STALE | AMBIGUOUS` with bounded evidence/payload;
- Bridge bearer attach requires secure `wss:` plus exact trusted Worker endpoint configuration;
- terminal acceptance requires exact dispatch id + idempotency key + correlation/connection identity;
- terminal provenance includes bridge runtime/version, operation/result class, and started/completed timestamps;
- disconnect/expiry/adapter-fault paths resolve fail-closed to `FAILED`/`STALE`/`AMBIGUOUS` (never manufactured `PASS`) on both in-memory and SQLite DO stores;
- synthetic adapter filters to exact allowlisted hosts/subdomains and metadata-only output;
- Codync uses only `127.0.0.1:19222` and fixed `health`, `events`, `send`, and `history` methods; bearer access is injected by the runtime's owner-protected credential provider and never returned or logged;
- Codync destinations are pinned by ID/name/kind and group membership from #621/#644; live roster mismatches fail closed. Group sends require explicit selected-member mentions and reject `@all`/`@everyone`;
- Codync replies require the exact dispatch-derived client nonce, root entry ID/sequence/turn, exact destination and expected author, provider start state, and final agent entry. Accepted send alone is explicitly not provider-positive completion;
- REDRIX Dragonfly mode is Linux normal-user only, exposes only the exact three reviewed local controller operations, and never becomes GitHub/JIT authority.

## Rollback / cleanup

Repository changes are source-only until a separately accepted live proof. No machine startup state, scheduled task, service, worker secret, provider runtime, or Cloudflare state is created by source packaging.

For a credential-free REDRIX package proof, rollback removes only the exact owner-local package/config proof paths created for #109; it must not alter the existing Dragonfly JIT controller, owner launchers, pinned KVM base, keyring configuration, or unrelated user state.
