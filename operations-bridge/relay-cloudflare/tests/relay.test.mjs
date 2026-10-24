import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import relayWorker, {
  BridgeRelayDurableObject,
  HIBERNATION_RUNTIME_CONTRACT,
  SqliteRelayRepository,
  createRepository,
  normalizeDispatchPayload,
  finalizeTerminal
} from "../src/relay.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const RELAY_SOURCE = readFileSync(join(__dirname, "../src/relay.js"), "utf8");

test("source/runtime contract requires Cloudflare hibernation APIs", () => {
  assert.match(RELAY_SOURCE, /acceptWebSocket\s*\(/);
  assert.match(RELAY_SOURCE, /getWebSockets\s*\(/);
  assert.match(RELAY_SOURCE, /serializeAttachment\s*\(/);
  assert.match(RELAY_SOURCE, /deserializeAttachment\s*\(/);
  assert.match(RELAY_SOURCE, /async\s+webSocketMessage\s*\(/);
  assert.match(RELAY_SOURCE, /async\s+webSocketClose\s*\(/);
  assert.equal(typeof BridgeRelayDurableObject.prototype.webSocketMessage, "function");
  assert.equal(typeof BridgeRelayDurableObject.prototype.webSocketClose, "function");
  assert.equal(typeof BridgeRelayDurableObject.prototype.selectBridgeSocket, "function");
  assert.equal(typeof BridgeRelayDurableObject.prototype.deliverQueuedDispatches, "function");
  assert.match(RELAY_SOURCE, /this\.deliverQueuedDispatches\(bridgeId, connectionId, server\)/);
  assert.ok(HIBERNATION_RUNTIME_CONTRACT.acceptWebSocket.includes("acceptWebSocket"));
  assert.ok(!/\bserver\.accept\s*\(/.test(RELAY_SOURCE));
  assert.ok(!RELAY_SOURCE.includes("this.connections = new Map"));
});

test("role separation: Site cannot connect or submit terminal; Bridge cannot dispatch", async () => {
  const env = buildEnv();

  const bridgeDispatch = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/dispatch", "POST", buildDispatch());
  assert.equal(bridgeDispatch.status, 403);

  const siteConnect = await sendWithToken(
    env,
    env.SITE_DISPATCH_TOKEN,
    "/relay/connect?bridgeId=ldw01-bridge",
    "GET"
  );
  assert.equal(siteConnect.status, 403);

  const siteTerminal = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/terminal", "POST", {
    bridgeId: "ldw01-bridge",
    connectionId: "forged",
    dispatchId: crypto.randomUUID(),
    correlationId: "corr",
    status: "PASS"
  });
  assert.equal(siteTerminal.status, 405);

  const bridgeTerminalHttp = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/terminal", "POST", {
    status: "PASS"
  });
  assert.equal(bridgeTerminalHttp.status, 405);
});

test("shared or missing dual tokens fail closed", async () => {
  const env = buildEnv();
  env.SITE_DISPATCH_TOKEN = "same";
  env.BRIDGE_CLIENT_TOKEN = "same";
  const response = await sendWithToken(env, "same", "/relay/dispatch", "POST", buildDispatch());
  assert.equal(response.status, 401);
});

test("bridge identity is server-bound; Site responses omit connection ids", async () => {
  const env = buildEnv();
  const { socket } = attachSocket(env, "ldw01-bridge");

  const wrongBridge = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", {
    ...buildDispatch(),
    bridgeId: "other-bridge"
  });
  assert.equal(wrongBridge.status, 400);

  const dispatch = buildDispatch();
  const accepted = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);
  assert.equal(accepted.status, 200);
  const acceptedBody = await accepted.json();
  assert.equal(acceptedBody.state, "delivered");
  assert.equal(acceptedBody.delivery, "sent");
  assert.equal(Object.hasOwn(acceptedBody, "deliveryConnectionId"), false);

  const stored = await sendWithToken(
    env,
    env.SITE_DISPATCH_TOKEN,
    `/relay/dispatch/${dispatch.dispatchId}`,
    "GET"
  );
  const storedBody = await stored.json();
  assert.equal(Object.hasOwn(storedBody, "delivery_connection_id"), false);
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].type, "dispatch");
  assert.equal(socket.sent[0].operation, "browser.list_tabs");
  assert.equal(socket.sent[0].protocolVersion, "1.0");
  assert.equal(socket.sent[0].correlationId, dispatch.correlationId);
});

test("full-envelope socket delivery and send failure does not mark delivered", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  socket.send = () => {
    throw new Error("send failed");
  };

  const dispatch = buildDispatch({ idempotencyKey: "idem-send-fail" });
  const response = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.state, "accepted");
  assert.equal(body.delivery, "send_failed");

  const row = durable.repository.getDispatch(dispatch.dispatchId);
  assert.equal(row.lifecycle, "queued");
  assert.equal(row.delivery_connection_id, null);
  assert.ok(row.protocol_version);
  assert.ok(row.operation);
  assert.ok(row.args_json);
});

test("queued dispatch drains on bridge reconnect without duplicate execution", async () => {
  const env = buildEnv();
  const dispatch = buildDispatch({ idempotencyKey: "idem-reconnect", correlationId: "corr-reconnect" });

  const queuedResponse = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);
  const queuedBody = await queuedResponse.json();
  assert.equal(queuedBody.state, "accepted");
  assert.equal(queuedBody.delivery, "pending");

  const stub = env.BRIDGE_RELAY.get(env.BRIDGE_RELAY.idFromName("ldw01-bridge"));
  const durable = stub.__durable();
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).lifecycle, "queued");

  const { socket } = attachSocket(env, "ldw01-bridge");
  const record = durable.repository.getDispatch(dispatch.dispatchId);
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].dispatchId, dispatch.dispatchId);
  assert.equal(socket.sent[0].idempotencyKey, dispatch.idempotencyKey);
  assert.equal(socket.sent[0].correlationId, dispatch.correlationId);
  assert.equal(record.lifecycle, "delivered");
  assert.equal(record.delivery_connection_id, socket.deserializeAttachment().connectionId);

  const retry = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", {
    ...buildDispatch({ idempotencyKey: dispatch.idempotencyKey, correlationId: "corr-retry" }),
    dispatchId: crypto.randomUUID()
  });
  const retryBody = await retry.json();
  assert.equal(retryBody.state, "duplicate");
  assert.equal(retryBody.dispatchId, dispatch.dispatchId);
  assert.equal(retryBody.correlationId, dispatch.correlationId);
  assert.equal(retryBody.delivery, "sent");
  assert.equal(socket.sent.length, 1);
});

test("reconnect drains a bounded window and advances one queued item per accepted terminal", async () => {
  const env = buildEnv();
  const dispatches = [];
  for (let index = 0; index < 34; index += 1) {
    const dispatch = buildDispatch({
      idempotencyKey: `idem-backlog-${index}`,
      correlationId: `corr-backlog-${index}`
    });
    dispatches.push(dispatch);
    const response = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);
    assert.equal(response.status, 200);
  }

  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  const connectionId = socket.deserializeAttachment().connectionId;
  assert.equal(socket.sent.length, 32);
  const remaining = durable.repository.listQueued("ldw01-bridge", 32);
  assert.equal(remaining.length, 2);
  assert.equal(durable.repository.getDispatch(remaining[1].dispatch_id).lifecycle, "queued");

  const terminal = {
    type: "terminal",
    dispatchId: dispatches[0].dispatchId,
    idempotencyKey: dispatches[0].idempotencyKey,
    correlationId: dispatches[0].correlationId,
    status: "PASS",
    bridgeRuntime: "ldw-operations-bridge",
    bridgeVersion: "1.0.0",
    operation: dispatches[0].operation,
    resultClass: "PASS",
    startedAt: new Date(Date.now() - 500).toISOString(),
    evidence: "completed",
    payload: {}
  };
  await durable.webSocketMessage(socket, JSON.stringify(terminal));
  assert.equal(socket.sent.length, 33);
  assert.equal(socket.sent[32].dispatchId, remaining[0].dispatch_id);
  assert.equal(durable.repository.getDispatch(remaining[0].dispatch_id).delivery_connection_id, connectionId);
  assert.equal(durable.repository.getDispatch(remaining[1].dispatch_id).lifecycle, "queued");

  await durable.webSocketMessage(socket, JSON.stringify(terminal));
  assert.equal(socket.sent.length, 33, "duplicate terminal does not advance the queue");
  assert.equal(durable.repository.getDispatch(remaining[1].dispatch_id).lifecycle, "queued");
});
test("stale and unknown envelopes are rejected before persistence", () => {
  const now = new Date().toISOString();
  const stale = normalizeDispatchPayload(
    buildDispatch({
      issuedAt: new Date(Date.now() - 10 * 60_000).toISOString(),
      expiresAt: new Date(Date.now() - 60_000).toISOString()
    }),
    now
  );
  assert.equal(stale.ok, false);
  assert.equal(stale.error, "stale-or-expired");

  const unknown = normalizeDispatchPayload(buildDispatch({ operation: "browser.eval" }), now);
  assert.equal(unknown.ok, false);
  assert.equal(unknown.error, "unknown-operation");
});

test("Codync operations accept only their typed bounded argument schemas", () => {
  const now = new Date().toISOString();
  const dispatchId = crypto.randomUUID();
  const destinationId = crypto.randomUUID();
  const validSend = normalizeDispatchPayload(buildDispatch({
    operation: "codync.send_exact",
    args: { destination_id: destinationId, destination_name: "Reviewer", text: "Read-only sentinel", mentioned_member_ids: "" }
  }), now);
  assert.equal(validSend.ok, true);

  const validLongSend = normalizeDispatchPayload(buildDispatch({
    operation: "codync.send_exact",
    args: { destination_id: destinationId, destination_name: "Reviewer", text: "x".repeat(300), mentioned_member_ids: "" }
  }), now);
  assert.equal(validLongSend.ok, true);
  const oversizedCodyncSend = normalizeDispatchPayload(buildDispatch({
    operation: "codync.send_exact",
    args: { destination_id: destinationId, destination_name: "Reviewer", text: "x".repeat(8193), mentioned_member_ids: "" }
  }), now);
  assert.equal(oversizedCodyncSend.ok, false);

  const unsafeGroup = normalizeDispatchPayload(buildDispatch({
    operation: "codync.send_exact",
    args: { destination_id: destinationId, destination_name: "Board", text: "@all review this", mentioned_member_ids: "" }
  }), now);
  assert.equal(unsafeGroup.ok, false);
  assert.equal(unsafeGroup.error, "invalid-operation-args");

  const genericRpc = normalizeDispatchPayload(buildDispatch({
    operation: "codync.send_exact",
    args: { destination_id: destinationId, destination_name: "Reviewer", text: "Read-only", method: "createBot" }
  }), now);
  assert.equal(genericRpc.ok, false);

  const wait = normalizeDispatchPayload(buildDispatch({
    operation: "codync.wait_read_exact",
    args: {
      destination_id: destinationId,
      destination_name: "Reviewer",
      send_dispatch_id: dispatchId,
      client_nonce: `ldw-operations-${dispatchId}`,
      root_entry_id: crypto.randomUUID(),
      root_sequence: "4",
      root_turn: "2",
      root_revision: "9",
      submitted_at: new Date().toISOString(),
      expected_author_id: destinationId,
      timeout_seconds: "120"
    }
  }), now);
  assert.equal(wait.ok, true);
});

test("terminal enum/payload bounds and lost correlation never PASS", () => {
  const row = {
    dispatch_id: crypto.randomUUID(),
    idempotency_key: "idem-term",
    correlation_id: "corr-term",
    delivery_connection_id: "conn-1",
    operation: "browser.list_tabs",
    expires_at: new Date(Date.now() + 60_000).toISOString()
  };

  const nowIso = new Date().toISOString();
  const observedProvenance = {
    bridgeRuntime: "ldw-operations-bridge",
    bridgeVersion: "1.0.0",
    startedAt: new Date(Date.now() - 500).toISOString()
  };

  const missingProvenance = finalizeTerminal(
    row,
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "PASS",
      evidence: "missing provenance"
    },
    nowIso
  );
  assert.equal(missingProvenance.ok, false);
  assert.equal(missingProvenance.error, "missing-started-at");

  const unsupported = finalizeTerminal(
    row,
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "SUCCESS",
      evidence: "unsupported",
      payload: { ready: "true" },
      ...observedProvenance
    },
    nowIso
  );
  assert.equal(unsupported.ok, true);
  assert.equal(unsupported.result.terminalStatus, "FAILED");
  assert.deepEqual(unsupported.result.payload, {});

  const bounded = finalizeTerminal(
    row,
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "BLOCKED",
      evidence: "x".repeat(600),
      payload: { a: "1", b: "2", huge: "y".repeat(400) },
      ...observedProvenance
    },
    nowIso
  );
  assert.equal(bounded.ok, true);
  assert.equal(bounded.result.terminalStatus, "BLOCKED");
  assert.ok(bounded.result.evidence.length <= 512);
  assert.ok(bounded.result.payload.huge.length <= 256);
  assert.equal(bounded.result.bridgeRuntime, "ldw-operations-bridge");
  assert.equal(bounded.result.operation, "browser.list_tabs");
  assert.equal(bounded.result.resultClass, "BLOCKED");
  assert.equal(bounded.result.startedAt, new Date(observedProvenance.startedAt).toISOString());

  const lost = finalizeTerminal(
    row,
    "conn-wrong",
    {
      correlationId: "corr-wrong",
      idempotencyKey: "idem-term",
      status: "PASS",
      evidence: "forged",
      payload: { ready: "true" },
      ...observedProvenance
    },
    nowIso
  );
  assert.equal(lost.ok, true);
  assert.equal(lost.result.terminalStatus, "AMBIGUOUS");
  assert.equal(lost.result.correlationId, "corr-term");
  assert.deepEqual(lost.result.payload, {});

  const acceptedSendOnly = finalizeTerminal(
    { ...row, operation: "codync.send_exact" },
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "PASS",
      evidence: "provider replied",
      payload: { root_entry_id: crypto.randomUUID() },
      ...observedProvenance
    },
    nowIso
  );
  assert.equal(acceptedSendOnly.ok, true);
  assert.equal(acceptedSendOnly.result.terminalStatus, "BLOCKED");
  assert.deepEqual(acceptedSendOnly.result.payload, {});

  const rosterResult = finalizeTerminal(
    { ...row, operation: "codync.list_approved_bots_groups" },
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "PASS",
      evidence: "exact roster",
      payload: { approved_destinations_json: "r".repeat(3000) },
      ...observedProvenance
    },
    nowIso
  );
  assert.equal(rosterResult.ok, true);
  assert.equal(rosterResult.result.payload.approved_destinations_json.length, 3000);
});

test("duplicate idempotency and immutable one terminal via hibernated socket path", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  const dispatch = buildDispatch({ idempotencyKey: "idem-dup", correlationId: "corr-dup" });

  const first = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);
  assert.equal((await first.json()).state, "delivered");

  const duplicate = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", {
    ...buildDispatch({ idempotencyKey: "idem-dup", correlationId: "corr-other" }),
    dispatchId: crypto.randomUUID()
  });
  const duplicateBody = await duplicate.json();
  assert.equal(duplicateBody.state, "duplicate");
  assert.equal(duplicateBody.correlationId, "corr-dup");

  const startedAt = new Date().toISOString();
  await durable.webSocketMessage(
    socket,
    JSON.stringify({
      type: "terminal",
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: "corr-dup",
      status: "PASS",
      bridgeRuntime: "ldw-operations-bridge",
      bridgeVersion: "1.0.0",
      operation: "browser.list_tabs",
      resultClass: "PASS",
      startedAt,
      evidence: "ok",
      payload: { tab_count: "1" }
    })
  );

  const row = durable.repository.getDispatch(dispatch.dispatchId);
  assert.equal(row.terminal_status, "PASS");
  assert.equal(row.bridge_runtime, "ldw-operations-bridge");
  assert.equal(row.bridge_version, "1.0.0");
  assert.equal(row.result_class, "PASS");
  assert.equal(row.started_at, new Date(startedAt).toISOString());
  assert.ok(row.completed_at);

  const second = durable.repository.completeFromClient(
    socket.deserializeAttachment().connectionId,
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: "corr-dup",
      status: "FAILED",
      evidence: "late"
    },
    new Date().toISOString()
  );
  assert.equal(second.ok, false);
  assert.equal(second.error, "already-terminal");
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).terminal_status, "PASS");
});

test("missing or mismatched idempotency key never records PASS", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  const dispatch = buildDispatch({ idempotencyKey: "idem-required", correlationId: "corr-required" });
  await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);

  const missing = durable.repository.completeFromClient(
    socket.deserializeAttachment().connectionId,
    {
      dispatchId: dispatch.dispatchId,
      correlationId: "corr-required",
      status: "PASS",
      evidence: "no key"
    },
    new Date().toISOString()
  );
  assert.equal(missing.ok, false);
  assert.equal(missing.error, "missing-idempotency-key");
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).terminal_status, null);

  const mismatched = durable.repository.completeFromClient(
    socket.deserializeAttachment().connectionId,
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: "wrong-key",
      correlationId: "corr-required",
      status: "PASS",
      evidence: "wrong key"
    },
    new Date().toISOString()
  );
  assert.equal(mismatched.ok, false);
  assert.equal(mismatched.error, "idempotency-mismatch");
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).terminal_status, null);
});

test("SQLite path resolves expiry and disconnect without manufacturing PASS", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");

  const expiredQueued = buildDispatch({
    idempotencyKey: "idem-expire-queued",
    issuedAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() - 30_000).toISOString()
  });
  // Bypass accept validation by inserting via repository after normalizing a fresh window, then backdating.
  const fresh = buildDispatch({ idempotencyKey: "idem-expire-queued" });
  const accepted = durable.repository.acceptDispatch(fresh, new Date().toISOString());
  assert.equal(accepted.ok, true);
  const queuedRow = durable.repository.getDispatch(fresh.dispatchId);
  queuedRow.issued_at = expiredQueued.issuedAt;
  queuedRow.expires_at = expiredQueued.expiresAt;

  const resolved = durable.repository.resolveNonterminal(new Date().toISOString());
  assert.ok(resolved >= 1);
  assert.equal(durable.repository.getDispatch(fresh.dispatchId).terminal_status, "STALE");
  assert.equal(durable.repository.getDispatch(fresh.dispatchId).result_class, "STALE");

  const delivered = buildDispatch({ idempotencyKey: "idem-disconnect" });
  await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", delivered);
  assert.equal(durable.repository.getDispatch(delivered.dispatchId).lifecycle, "delivered");

  await durable.webSocketClose(socket, 1000, "bye");
  const afterClose = durable.repository.getDispatch(delivered.dispatchId);
  assert.equal(afterClose.terminal_status, "AMBIGUOUS");
  assert.equal(afterClose.result_class, "AMBIGUOUS");
  assert.notEqual(afterClose.terminal_status, "PASS");
  assert.equal(afterClose.started_at, null);
  assert.equal(afterClose.bridge_runtime, null);
  assert.equal(afterClose.bridge_version, null);
});

test("client terminal without observed provenance is rejected; relay resolution keeps start unobserved", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  const dispatch = buildDispatch({ idempotencyKey: "idem-obs-prov" });
  await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);

  const missingRuntime = durable.repository.completeFromClient(
    socket.deserializeAttachment().connectionId,
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: dispatch.correlationId,
      status: "PASS",
      startedAt: new Date().toISOString(),
      bridgeVersion: "1.0.0",
      evidence: "no runtime"
    },
    new Date().toISOString()
  );
  assert.equal(missingRuntime.ok, false);
  assert.equal(missingRuntime.error, "missing-bridge-runtime");
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).terminal_status, null);

  const futureStart = durable.repository.completeFromClient(
    socket.deserializeAttachment().connectionId,
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: dispatch.correlationId,
      status: "PASS",
      bridgeRuntime: "ldw-operations-bridge",
      bridgeVersion: "1.0.0",
      startedAt: new Date(Date.now() + 60_000).toISOString(),
      evidence: "future start"
    },
    new Date().toISOString()
  );
  assert.equal(futureStart.ok, false);
  assert.equal(futureStart.error, "invalid-started-at-order");
  assert.equal(durable.repository.getDispatch(dispatch.dispatchId).terminal_status, null);

  await durable.webSocketClose(socket, 1000, "bye");
  const resolved = durable.repository.getDispatch(dispatch.dispatchId);
  assert.equal(resolved.terminal_status, "AMBIGUOUS");
  assert.equal(resolved.started_at, null);
  assert.equal(resolved.bridge_runtime, null);
  assert.equal(resolved.bridge_version, null);
});

test("terminal provenance fields are stored and returned to Site", async () => {
  const env = buildEnv();
  const { durable, socket } = attachSocket(env, "ldw01-bridge");
  const dispatch = buildDispatch({ idempotencyKey: "idem-provenance" });
  await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/dispatch", "POST", dispatch);

  const startedAt = new Date(Date.now() - 1_000).toISOString();
  await durable.webSocketMessage(
    socket,
    JSON.stringify({
      type: "terminal",
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: dispatch.correlationId,
      status: "PASS",
      bridgeRuntime: "ldw-operations-bridge",
      bridgeVersion: "1.0.0",
      operation: "browser.list_tabs",
      resultClass: "PASS",
      startedAt,
      evidence: "ok",
      payload: { tab_count: "1" }
    })
  );

  const status = await sendWithToken(
    env,
    env.SITE_DISPATCH_TOKEN,
    `/relay/dispatch/${dispatch.dispatchId}`,
    "GET"
  );
  const body = await status.json();
  assert.equal(body.terminal_status, "PASS");
  assert.equal(body.bridge_runtime, "ldw-operations-bridge");
  assert.equal(body.bridge_version, "1.0.0");
  assert.equal(body.result_class, "PASS");
  assert.equal(body.operation, "browser.list_tabs");
  assert.equal(body.started_at, new Date(startedAt).toISOString());
  assert.ok(body.completed_at);
  assert.equal(Object.hasOwn(body, "delivery_connection_id"), false);
});

test("hibernation rehydration uses getWebSockets + attachment, not instance maps", async () => {
  const env = buildEnv();
  const first = env.BRIDGE_RELAY.get(env.BRIDGE_RELAY.idFromName("ldw01-bridge")).__durable();
  const hibernationState = first.__state;
  const socket = createFakeSocket("ldw01-bridge");
  hibernationState.acceptWebSocket(socket, ["ldw01-bridge"]);
  socket.serializeAttachment({ bridgeId: "ldw01-bridge", connectionId: crypto.randomUUID() });

  // Simulate eviction: new DO instance, same hibernation state surface.
  const rehydrated = new BridgeRelayDurableObject(hibernationState);
  const selected = rehydrated.selectBridgeSocket("ldw01-bridge");
  assert.ok(selected);
  assert.equal(selected.connectionId, socket.deserializeAttachment().connectionId);

  const dispatch = buildDispatch({ idempotencyKey: "idem-hibernated" });
  const response = await rehydrated.fetch(
    new Request("https://relay.internal/dispatch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(dispatch)
    })
  );
  const body = await response.json();
  assert.equal(body.state, "delivered");
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].operation, dispatch.operation);
});

test("SQLite repository persists full envelope and enforces one terminal", () => {
  const sql = createFakeSql();
  const repository = new SqliteRelayRepository(sql);
  repository.initialize();

  assert.equal(createRepository({ storage: { sql } }) instanceof SqliteRelayRepository, true);

  const dispatch = buildDispatch({ idempotencyKey: "idem-sql", args: { tab_id: "1" } });
  const accepted = repository.acceptDispatch(dispatch, new Date().toISOString());
  assert.equal(accepted.ok, true);
  assert.equal(accepted.state, "accepted");
  assert.equal(accepted.record.operation, "browser.list_tabs");
  assert.equal(JSON.parse(accepted.record.args_json).tab_id, "1");

  const duplicate = repository.acceptDispatch(
    { ...dispatch, dispatchId: crypto.randomUUID(), correlationId: "other" },
    new Date().toISOString()
  );
  assert.equal(duplicate.state, "duplicate");

  repository.markDelivered(dispatch.dispatchId, "conn-sql");
  const first = repository.completeFromClient(
    "conn-sql",
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: dispatch.correlationId,
      status: "PASS",
      bridgeRuntime: "ldw-operations-bridge",
      bridgeVersion: "1.0.0",
      startedAt: new Date().toISOString(),
      evidence: "ok",
      payload: { ready: "true" }
    },
    new Date().toISOString()
  );
  assert.equal(first.ok, true);
  assert.equal(first.result.terminalStatus, "PASS");
  assert.equal(first.result.bridgeRuntime, "ldw-operations-bridge");
  assert.equal(first.result.resultClass, "PASS");

  const second = repository.completeFromClient(
    "conn-sql",
    {
      dispatchId: dispatch.dispatchId,
      idempotencyKey: dispatch.idempotencyKey,
      correlationId: dispatch.correlationId,
      status: "FAILED",
      evidence: "nope"
    },
    new Date().toISOString()
  );
  assert.equal(second.ok, false);
  assert.equal(repository.getDispatch(dispatch.dispatchId).terminal_status, "PASS");
});

test("connect requires fixed authenticated protocol/runtime metadata after bridge role and identity checks", async () => {
  const env = buildEnv();
  const site = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET");
  assert.equal(site.status, 403);
  const missing = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET");
  assert.equal(missing.status, 400);
  const drift = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET", undefined, {"X-LDW-Protocol-Version":"9"});
  assert.equal(drift.status, 400);
  const bridge = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET", undefined, connectIdentityHeaders());
  assert.equal(bridge.status, 426); // Valid metadata reaches the Durable Object upgrade check.
});

test("status is Site-only, fixed-identity, bounded, and fails closed across socket states", async () => {
  const env = buildEnv();
  const unauthenticated = await relayWorker.fetch(new Request("https://relay.example/relay/status"), env);
  assert.equal(unauthenticated.status, 401);
  const bridge = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/status", "GET");
  assert.equal(bridge.status, 403);
  const query = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status?bridgeId=other", "GET");
  assert.equal(query.status, 400);

  const first = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET");
  const unknown = await first.json();
  assert.equal(unknown.state, "UNKNOWN");
  assert.equal(unknown.freshness, "UNKNOWN");
  assert.equal(unknown.last_authenticated_at, null);
  const unobservedSocket = attachSocket(env, "ldw01-bridge");
  const unobservedOnline = await (await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET")).json();
  assert.equal(unobservedOnline.state, "UNKNOWN");
  assert.equal(unobservedOnline.freshness, "UNKNOWN");
  unobservedSocket.socket.readyState = 3;

  const stub = env.BRIDGE_RELAY.get(env.BRIDGE_RELAY.idFromName("ldw01-bridge"));
  const durable = stub.__durable();
  durable.repository.saveStatusObservation("ldw01-bridge", {last_authenticated_at:"2026-10-24T12:00:00.000Z", protocol_version:"1.0", runtime_version:"1.0.0"});
  const rehydrated = new BridgeRelayDurableObject(durable.__state);
  assert.equal(rehydrated.repository.getStatusObservation("ldw01-bridge").last_authenticated_at, "2026-10-24T12:00:00.000Z");
  const offline = await (await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET")).json();
  assert.equal(offline.state, "OFFLINE");
  assert.equal(offline.freshness, "STALE");

  const a = attachSocket(env, "ldw01-bridge");
  const online = await (await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET")).json();
  assert.equal(online.state, "ONLINE");
  assert.equal(online.freshness, "FRESH");
  a.socket.readyState = 3;
  const stale = await (await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET")).json();
  assert.equal(stale.state, "OFFLINE");
  assert.equal(stale.freshness, "STALE");

  const b = attachSocket(env, "ldw01-bridge");
  const c = attachSocket(env, "ldw01-bridge");
  const degraded = await (await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/status", "GET")).json();
  assert.equal(degraded.state, "DEGRADED");
  assert.equal(degraded.freshness, "UNKNOWN");
  assert.deepEqual(Object.keys(degraded).sort(), ["bridge_id","state","protocol_version","runtime_version","last_authenticated_at","supported_operations","freshness"].sort());
  assert.deepEqual(degraded.supported_operations, ["BROWSER_LIST_TABS","BROWSER_READ_TAB_METADATA"]);
  assert.equal(degraded.bridge_id, "ldw01-primary");
  assert.equal(JSON.stringify(degraded).includes("connectionId"), false);
  assert.equal(JSON.stringify(degraded).includes("ldw01-bridge"), false);
});

function connectIdentityHeaders() {
  return {"X-LDW-Protocol-Version":"1.0", "X-LDW-Bridge-Runtime":"ldw-operations-bridge", "X-LDW-Bridge-Version":"1.0.0"};
}

function buildEnv() {
  const namespaces = new Map();
  return {
    SITE_DISPATCH_TOKEN: "site-token",
    BRIDGE_CLIENT_TOKEN: "bridge-token",
    BRIDGE_ID: "ldw01-bridge",
    BRIDGE_RELAY: {
      idFromName(name) {
        return name;
      },
      get(id) {
        if (!namespaces.has(id)) {
          const state = createHibernationState();
          const durable = new BridgeRelayDurableObject(state);
          durable.__state = state;
          namespaces.set(id, durable);
        }

        return {
          fetch: (request) => namespaces.get(id).fetch(request),
          __durable: () => namespaces.get(id)
        };
      }
    }
  };
}

function attachSocket(env, bridgeId) {
  const stub = env.BRIDGE_RELAY.get(env.BRIDGE_RELAY.idFromName(bridgeId));
  const durable = stub.__durable();
  const socket = createFakeSocket(bridgeId);
  durable.__state.acceptWebSocket(socket, [bridgeId]);
  const connectionId = crypto.randomUUID();
  socket.serializeAttachment({ bridgeId, connectionId });
  durable.deliverQueuedDispatches(bridgeId, connectionId, socket);
  return { durable, socket };
}

function createHibernationState() {
  const socketsByTag = new Map();
  return {
    storage: { sql: createFakeSql() },
    acceptWebSocket(ws, tags = []) {
      ws.__tags = [...tags];
      for (const tag of tags) {
        if (!socketsByTag.has(tag)) {
          socketsByTag.set(tag, new Set());
        }
        socketsByTag.get(tag).add(ws);
      }
      if (!socketsByTag.has("*")) {
        socketsByTag.set("*", new Set());
      }
      socketsByTag.get("*").add(ws);
    },
    getWebSockets(tag) {
      if (!tag) {
        return [...(socketsByTag.get("*") ?? [])];
      }
      return [...(socketsByTag.get(tag) ?? [])];
    }
  };
}

function createFakeSocket(bridgeId) {
  let attachment = null;
  const socket = {
    readyState: 1,
    sent: [],
    __tags: [bridgeId],
    serializeAttachment(value) {
      attachment = value;
    },
    deserializeAttachment() {
      return attachment;
    },
    send(data) {
      socket.sent.push(typeof data === "string" ? JSON.parse(data) : data);
    },
    close() {
      socket.readyState = 3;
    }
  };
  return socket;
}

function createFakeSql() {
  const rows = new Map();
  const byIdempotency = new Map();
  const statusObservations = new Map();

  return {
    exec(query, ...params) {
      const sql = String(query).replace(/\s+/g, " ").trim();

      if (sql.startsWith("CREATE TABLE")) {
        return [];
      }

      if (sql.startsWith("INSERT INTO bridge_status_observations")) {
        statusObservations.set(params[0], { bridge_id: params[0], last_authenticated_at: params[1], protocol_version: params[2], runtime_version: params[3] });
        return [];
      }
      if (sql.startsWith("SELECT * FROM bridge_status_observations")) {
        const row = statusObservations.get(params[0]);
        return row ? [row] : [];
      }
      if (sql.startsWith("INSERT INTO dispatches")) {
        const record = {
          dispatch_id: params[0],
          bridge_id: params[1],
          protocol_version: params[2],
          operation: params[3],
          args_json: params[4],
          idempotency_key: params[5],
          correlation_id: params[6],
          issued_at: params[7],
          expires_at: params[8],
          lifecycle: params[9],
          delivery_connection_id: null,
          terminal_status: null,
          terminal_correlation_id: null,
          terminal_evidence: null,
          terminal_payload_json: null,
          started_at: null,
          completed_at: null,
          bridge_runtime: null,
          bridge_version: null,
          result_class: null
        };
        rows.set(record.dispatch_id, record);
        byIdempotency.set(record.idempotency_key, record.dispatch_id);
        return [];
      }

      if (sql.startsWith("SELECT * FROM dispatches WHERE idempotency_key")) {
        const dispatchId = byIdempotency.get(params[0]);
        return dispatchId ? [rows.get(dispatchId)] : [];
      }

      if (sql.startsWith("SELECT * FROM dispatches WHERE bridge_id")) {
        return [...rows.values()]
          .filter((row) => row.bridge_id === params[0] && row.lifecycle === "queued" && !row.terminal_status)
          .sort((a, b) => a.issued_at.localeCompare(b.issued_at) || a.dispatch_id.localeCompare(b.dispatch_id))
          .slice(0, Number(params[1]));
      }

      if (sql.startsWith("SELECT * FROM dispatches WHERE dispatch_id")) {
        const row = rows.get(params[0]);
        return row ? [row] : [];
      }

      if (sql.includes("delivery_connection_id = ?1") && sql.includes("lifecycle IN")) {
        return [...rows.values()].filter(
          (row) =>
            !row.terminal_status &&
            row.delivery_connection_id === params[0] &&
            (row.lifecycle === "delivered" || row.lifecycle === "started")
        );
      }

      if (sql.startsWith("SELECT * FROM dispatches WHERE terminal_status IS NULL")) {
        return [...rows.values()].filter((row) => !row.terminal_status);
      }

      if (sql.startsWith("UPDATE dispatches SET lifecycle = 'delivered'")) {
        const row = rows.get(params[0]);
        if (row && !row.terminal_status) {
          row.lifecycle = "delivered";
          row.delivery_connection_id = params[1];
        }
        return [];
      }

      if (sql.startsWith("UPDATE dispatches SET lifecycle = 'terminal'")) {
        const row = rows.get(params[0]);
        if (row && !row.terminal_status) {
          row.lifecycle = "terminal";
          row.terminal_status = params[1];
          row.terminal_correlation_id = params[2];
          row.terminal_evidence = params[3];
          row.terminal_payload_json = params[4];
          row.started_at = params[5];
          row.completed_at = params[6];
          row.bridge_runtime = params[7];
          row.bridge_version = params[8];
          row.result_class = params[9];
        }
        return [];
      }

      throw new Error(`Unsupported fake SQL: ${sql}`);
    }
  };
}

function buildDispatch(overrides = {}) {
  const now = Date.now();
  return {
    protocolVersion: "1.0",
    bridgeId: "ldw01-bridge",
    dispatchId: crypto.randomUUID(),
    operation: "browser.list_tabs",
    idempotencyKey: "idem-1",
    correlationId: "corr-1",
    issuedAt: new Date(now - 5_000).toISOString(),
    expiresAt: new Date(now + 120_000).toISOString(),
    args: {},
    ...overrides
  };
}

function sendWithToken(env, token, path, method, body, extraHeaders = {}) {
  return relayWorker.fetch(
    new Request(`https://relay.example${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        ...extraHeaders
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }),
    env
  );
}
