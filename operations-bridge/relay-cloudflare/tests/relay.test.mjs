import test from "node:test";
import assert from "node:assert/strict";

import relayWorker, { BridgeRelayDurableObject } from "../src/relay.js";

test("rejects unauthenticated dispatch requests", async () => {
  const env = buildEnv();
  const request = new Request("https://relay.example/relay/dispatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(buildDispatch("bridge-a", "idem-1", "corr-1"))
  });

  const response = await relayWorker.fetch(request, env);
  assert.equal(response.status, 401);
});

test("accepts then de-duplicates dispatch by idempotency key", async () => {
  const env = buildEnv();
  await connectSyntheticClient(env, "bridge-a", "conn-a");

  const accepted = await sendAuthorized(env, "/relay/dispatch", "POST", buildDispatch("bridge-a", "idem-1", "corr-1"));
  assert.equal(accepted.status, 200);
  const acceptedBody = await accepted.json();
  assert.equal(acceptedBody.state, "accepted");
  assert.equal(acceptedBody.deliveryConnectionId, "conn-a");

  const duplicate = await sendAuthorized(env, "/relay/dispatch", "POST", buildDispatch("bridge-a", "idem-1", "corr-other"));
  assert.equal(duplicate.status, 200);
  const duplicateBody = await duplicate.json();
  assert.equal(duplicateBody.state, "duplicate");
  assert.equal(duplicateBody.correlationId, "corr-1");
});

test("connection/correlation mismatch becomes AMBIGUOUS and keeps original correlation identity", async () => {
  const env = buildEnv();
  await connectSyntheticClient(env, "bridge-a", "conn-good");
  const dispatch = buildDispatch("bridge-a", "idem-2", "corr-2");

  const accepted = await sendAuthorized(env, "/relay/dispatch", "POST", dispatch);
  assert.equal(accepted.status, 200);

  const terminal = await sendAuthorized(env, "/relay/terminal", "POST", {
    bridgeId: "bridge-a",
    connectionId: "conn-wrong",
    dispatchId: dispatch.dispatchId,
    correlationId: "corr-wrong",
    status: "PASS",
    evidence: "should not pass",
    payload: { ready: "true" }
  });
  assert.equal(terminal.status, 200);
  const terminalBody = await terminal.json();
  assert.equal(terminalBody.result.terminalStatus, "AMBIGUOUS");
  assert.equal(terminalBody.result.correlationId, "corr-2");

  const stored = await sendAuthorized(env, `/relay/dispatch/${dispatch.dispatchId}?bridgeId=bridge-a`, "GET");
  assert.equal(stored.status, 200);
  const storedBody = await stored.json();
  assert.equal(storedBody.terminal_status, "AMBIGUOUS");
  assert.equal(storedBody.terminal_correlation_id, "corr-2");
});

test("connect endpoint enforces WebSocket upgrade", async () => {
  const env = buildEnv();
  const response = await sendAuthorized(env, "/relay/connect?bridgeId=bridge-a&connectionId=conn-a", "GET");
  assert.equal(response.status, 426);
});

function buildEnv() {
  const namespaces = new Map();
  return {
    BRIDGE_SHARED_TOKEN: "synthetic-token",
    BRIDGE_RELAY: {
      idFromName(name) {
        return name;
      },
      get(id) {
        if (!namespaces.has(id)) {
          namespaces.set(id, new BridgeRelayDurableObject({ storage: {} }, {}));
        }

        return {
          fetch: (request) => namespaces.get(id).fetch(request)
        };
      }
    }
  };
}

async function connectSyntheticClient(env, bridgeId, connectionId) {
  const response = await sendAuthorized(env, "/relay/synthetic/connect", "POST", {
    bridgeId,
    connectionId
  });
  assert.equal(response.status, 200);
}

function buildDispatch(bridgeId, idempotencyKey, correlationId) {
  const now = new Date();
  return {
    bridgeId,
    dispatchId: `dispatch-${idempotencyKey}`,
    idempotencyKey,
    correlationId,
    issuedAt: new Date(now.getTime() - 5_000).toISOString(),
    expiresAt: new Date(now.getTime() + 120_000).toISOString()
  };
}

function sendAuthorized(env, path, method, body) {
  return relayWorker.fetch(
    new Request(`https://relay.example${path}`, {
      method,
      headers: {
        authorization: "Bearer synthetic-token",
        "content-type": "application/json"
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }),
    env
  );
}
