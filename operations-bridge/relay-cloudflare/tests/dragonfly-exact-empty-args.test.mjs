import test from "node:test";
import assert from "node:assert/strict";

import relayWorker, { normalizeDragonflyDispatchPayload } from "../src/relay-multi.js";

const DRAGONFLY_ID = "dragonfly-redrix-01";

function buildDispatch(overrides = {}) {
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

function env() {
  return {
    SITE_DISPATCH_TOKEN: "site-token",
    BRIDGE_CLIENT_TOKEN: "ldw01-token",
    DRAGONFLY_BRIDGE_CLIENT_TOKEN: "dragonfly-token"
  };
}

async function dispatch(body) {
  return relayWorker.fetch(new Request("https://relay.example/relay/dragonfly/dispatch", {
    method: "POST",
    headers: {
      authorization: "Bearer site-token",
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  }), env());
}

test("Dragonfly normalizer rejects omitted args", () => {
  const payload = buildDispatch();
  delete payload.args;
  assert.deepEqual(
    normalizeDragonflyDispatchPayload(payload, new Date().toISOString()),
    { ok: false, error: "invalid-operation-args" }
  );
});

test("Dragonfly normalizer rejects null args", () => {
  const payload = buildDispatch({ args: null });
  assert.deepEqual(
    normalizeDragonflyDispatchPayload(payload, new Date().toISOString()),
    { ok: false, error: "invalid-operation-args" }
  );
});

test("Dragonfly route rejects omitted and null args before Durable Object forwarding", async () => {
  const omitted = buildDispatch();
  delete omitted.args;
  assert.equal((await dispatch(omitted)).status, 400);
  assert.equal((await dispatch(buildDispatch({ args: null }))).status, 400);
});

test("Dragonfly route still accepts literal empty args object up to forwarding boundary", async () => {
  const response = await dispatch(buildDispatch({ args: {} }));
  assert.equal(response.status, 500, "exact empty args pass route validation and then fail only because the test env intentionally has no DO binding");
});
