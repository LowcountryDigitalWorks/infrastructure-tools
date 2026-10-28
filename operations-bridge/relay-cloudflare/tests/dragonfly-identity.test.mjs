import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import relayWorker, {
  DRAGONFLY_RELAY_CONTRACT,
  DragonflyBridgeRelayDurableObject,
  normalizeDragonflyDispatchPayload
} from "../src/relay-multi.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WRANGLER_SOURCE = readFileSync(join(__dirname, "../wrangler.toml"), "utf8");

const DRAGONFLY_ID = "dragonfly-redrix-01";
const LDW01_ID = "ldw01-bridge";

function recordingNamespace() {
  const calls = [];
  return {
    calls,
    idFromName(name) {
      return `id:${name}`;
    },
    get(id) {
      return {
        async fetch(request) {
          calls.push({
            id,
            url: request.url,
            method: request.method,
            authorization: request.headers.get("authorization"),
            protocol: request.headers.get("X-LDW-Protocol-Version"),
            runtime: request.headers.get("X-LDW-Bridge-Runtime"),
            version: request.headers.get("X-LDW-Bridge-Version")
          });
          return new Response(null, { status: 204 });
        }
      };
    }
  };
}

function buildEnv() {
  return {
    SITE_DISPATCH_TOKEN: "site-token",
    BRIDGE_CLIENT_TOKEN: "ldw01-token",
    DRAGONFLY_BRIDGE_CLIENT_TOKEN: "dragonfly-token",
    BRIDGE_ID: LDW01_ID,
    BRIDGE_RELAY: recordingNamespace(),
    DRAGONFLY_BRIDGE_RELAY: recordingNamespace()
  };
}

function bridgeHeaders() {
  return {
    Upgrade: "websocket",
    "X-LDW-Protocol-Version": "1.0",
    "X-LDW-Bridge-Runtime": "ldw-operations-bridge",
    "X-LDW-Bridge-Version": "1.0.0"
  };
}

function send(env, token, path, method = "GET", body = null, extraHeaders = {}) {
  const headers = {
    authorization: `Bearer ${token}`,
    ...extraHeaders
  };
  const init = { method, headers };
  if (body !== null) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  return relayWorker.fetch(new Request(`https://relay.example${path}`, init), env);
}

function buildDragonflyDispatch(overrides = {}) {
  const now = Date.now();
  return {
    protocolVersion: "1.0",
    dispatchId: crypto.randomUUID(),
    bridgeId: DRAGONFLY_ID,
    operation: "dragonfly.runner.status",
    idempotencyKey: `idem-${crypto.randomUUID()}`,
    correlationId: `corr-${crypto.randomUUID()}`,
    issuedAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    args: {},
    ...overrides
  };
}

test("wrangler selects the isolated multi-bridge entrypoint and second Durable Object", () => {
  assert.match(WRANGLER_SOURCE, /main\s*=\s*"src\/relay-multi\.js"/);
  assert.match(WRANGLER_SOURCE, /name\s*=\s*"DRAGONFLY_BRIDGE_RELAY"/);
  assert.match(WRANGLER_SOURCE, /class_name\s*=\s*"DragonflyBridgeRelayDurableObject"/);
  assert.match(WRANGLER_SOURCE, /DRAGONFLY_BRIDGE_CLIENT_TOKEN/);
});

test("contract exposes exactly one REDRIX identity and exactly three typed operations", () => {
  assert.equal(DRAGONFLY_RELAY_CONTRACT.bridgeId, DRAGONFLY_ID);
  assert.equal(DRAGONFLY_RELAY_CONTRACT.dispatchPath, "/relay/dragonfly/dispatch");
  assert.deepEqual(
    [...DRAGONFLY_RELAY_CONTRACT.operations].sort(),
    ["dragonfly.runner.drain", "dragonfly.runner.start", "dragonfly.runner.status"]
  );
});

test("Dragonfly token authenticates only the exact Dragonfly connect identity", async () => {
  const env = buildEnv();
  const response = await send(
    env,
    env.DRAGONFLY_BRIDGE_CLIENT_TOKEN,
    `/relay/connect?bridgeId=${DRAGONFLY_ID}`,
    "GET",
    null,
    bridgeHeaders()
  );
  assert.equal(response.status, 204);
  assert.equal(env.DRAGONFLY_BRIDGE_RELAY.calls.length, 1);
  const call = env.DRAGONFLY_BRIDGE_RELAY.calls[0];
  assert.equal(call.id, `id:${DRAGONFLY_ID}`);
  assert.equal(call.url, `https://relay.internal/connect?bridgeId=${DRAGONFLY_ID}`);
  assert.equal(call.authorization, null, "bridge bearer is not forwarded into the Durable Object");
  assert.equal(call.protocol, "1.0");
  assert.equal(call.runtime, "ldw-operations-bridge");
  assert.equal(call.version, "1.0.0");

  const wrongIdentity = await send(
    env,
    env.DRAGONFLY_BRIDGE_CLIENT_TOKEN,
    `/relay/connect?bridgeId=${LDW01_ID}`,
    "GET",
    null,
    bridgeHeaders()
  );
  assert.equal(wrongIdentity.status, 403);

  const ldwTokenToDragonfly = await send(
    env,
    env.BRIDGE_CLIENT_TOKEN,
    `/relay/connect?bridgeId=${DRAGONFLY_ID}`,
    "GET",
    null,
    bridgeHeaders()
  );
  assert.equal(ldwTokenToDragonfly.status, 403);
});

test("existing LDW01 path remains usable before Dragonfly secret provisioning", async () => {
  const env = buildEnv();
  delete env.DRAGONFLY_BRIDGE_CLIENT_TOKEN;

  const existingStatus = await send(env, env.SITE_DISPATCH_TOKEN, "/relay/status");
  assert.equal(existingStatus.status, 204);
  assert.equal(env.BRIDGE_RELAY.calls.length, 1);

  const unavailableDragonfly = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch()
  );
  assert.equal(unavailableDragonfly.status, 503);
});

test("any Dragonfly token reuse with Site or LDW01 token fails closed", async () => {
  for (const collision of ["site-token", "ldw01-token"]) {
    const env = buildEnv();
    env.DRAGONFLY_BRIDGE_CLIENT_TOKEN = collision;
    const response = await send(env, env.SITE_DISPATCH_TOKEN, "/relay/status");
    assert.equal(response.status, 401);
    assert.equal(env.BRIDGE_RELAY.calls.length, 0);
    assert.equal(env.DRAGONFLY_BRIDGE_RELAY.calls.length, 0);
  }
});

test("Dragonfly dispatch route is Site-authenticated and fixed to exact identity/operation/empty args", async () => {
  const env = buildEnv();
  const accepted = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch({ operation: "dragonfly.runner.start" })
  );
  assert.equal(accepted.status, 204);
  assert.equal(env.DRAGONFLY_BRIDGE_RELAY.calls.length, 1);
  assert.equal(env.DRAGONFLY_BRIDGE_RELAY.calls[0].url, "https://relay.internal/dispatch");

  const wrongBridge = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch({ bridgeId: LDW01_ID })
  );
  assert.equal(wrongBridge.status, 400);

  const wrongOperation = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch({ operation: "browser.list_tabs" })
  );
  assert.equal(wrongOperation.status, 400);

  const nonemptyArgs = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch({ args: { force: "true" } })
  );
  assert.equal(nonemptyArgs.status, 400);

  const bridgeCredentialCannotDispatch = await send(
    env,
    env.DRAGONFLY_BRIDGE_CLIENT_TOKEN,
    "/relay/dragonfly/dispatch",
    "POST",
    buildDragonflyDispatch()
  );
  assert.equal(bridgeCredentialCannotDispatch.status, 403);
});

test("Dragonfly normalizer rejects cross-identity operations and accepts exact three-operation contract", () => {
  const nowIso = new Date().toISOString();
  for (const operation of DRAGONFLY_RELAY_CONTRACT.operations) {
    const result = normalizeDragonflyDispatchPayload(buildDragonflyDispatch({ operation }), nowIso);
    assert.equal(result.ok, true, operation);
    assert.equal(result.record.bridge_id, DRAGONFLY_ID);
    assert.equal(result.record.operation, operation);
    assert.equal(result.record.args_json, "{}");
  }

  const browser = normalizeDragonflyDispatchPayload(
    buildDragonflyDispatch({ operation: "browser.list_tabs" }),
    nowIso
  );
  assert.deepEqual(browser, { ok: false, error: "unknown-operation" });

  const codync = normalizeDragonflyDispatchPayload(
    buildDragonflyDispatch({ operation: "codync.health" }),
    nowIso
  );
  assert.deepEqual(codync, { ok: false, error: "unknown-operation" });

  const wrongBridge = normalizeDragonflyDispatchPayload(
    buildDragonflyDispatch({ bridgeId: LDW01_ID }),
    nowIso
  );
  assert.deepEqual(wrongBridge, { ok: false, error: "unknown-bridge" });

  const wrongArgs = normalizeDragonflyDispatchPayload(
    buildDragonflyDispatch({ args: { anything: "no" } }),
    nowIso
  );
  assert.deepEqual(wrongArgs, { ok: false, error: "invalid-operation-args" });
});

test("Dragonfly Durable Object persists only exact Dragonfly dispatches", async () => {
  const durable = new DragonflyBridgeRelayDurableObject({});
  const acceptedDispatch = buildDragonflyDispatch({ operation: "dragonfly.runner.drain" });
  const accepted = await durable.fetch(new Request("https://relay.internal/dispatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(acceptedDispatch)
  }));
  assert.equal(accepted.status, 200);
  const acceptedBody = await accepted.json();
  assert.equal(acceptedBody.state, "accepted");
  assert.equal(acceptedBody.delivery, "pending");

  const rejected = await durable.fetch(new Request("https://relay.internal/dispatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(buildDragonflyDispatch({ operation: "browser.list_tabs" }))
  }));
  assert.equal(rejected.status, 400);

  const lookup = await durable.fetch(
    new Request(`https://relay.internal/dispatch/${acceptedDispatch.dispatchId}`)
  );
  assert.equal(lookup.status, 200);
  const record = await lookup.json();
  assert.equal(record.bridge_id, DRAGONFLY_ID);
  assert.equal(record.operation, "dragonfly.runner.drain");
  assert.equal(Object.hasOwn(record, "delivery_connection_id"), false);
});

test("Dragonfly dispatch result route is identity-specific and rejects malformed ids", async () => {
  const env = buildEnv();
  const dispatchId = crypto.randomUUID();
  const response = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    `/relay/dragonfly/dispatch/${dispatchId}`
  );
  assert.equal(response.status, 204);
  assert.equal(
    env.DRAGONFLY_BRIDGE_RELAY.calls[0].url,
    `https://relay.internal/dispatch/${dispatchId}`
  );

  const malformed = await send(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/dragonfly/dispatch/not-a-uuid"
  );
  assert.equal(malformed.status, 400);
});
