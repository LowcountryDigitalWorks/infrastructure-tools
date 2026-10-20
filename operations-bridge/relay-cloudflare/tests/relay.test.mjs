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

test("terminal enum/payload bounds and lost correlation never PASS", () => {
  const row = {
    dispatch_id: crypto.randomUUID(),
    idempotency_key: "idem-term",
    correlation_id: "corr-term",
    delivery_connection_id: "conn-1",
    operation: "browser.list_tabs",
    expires_at: new Date(Date.now() + 60_000).toISOString()
  };

  const unsupported = finalizeTerminal(
    row,
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "SUCCESS",
      evidence: "unsupported",
      payload: { ready: "true" }
    },
    new Date().toISOString()
  );
  assert.equal(unsupported.terminalStatus, "FAILED");
  assert.deepEqual(unsupported.payload, {});

  const bounded = finalizeTerminal(
    row,
    "conn-1",
    {
      correlationId: "corr-term",
      idempotencyKey: "idem-term",
      status: "BLOCKED",
      evidence: "x".repeat(600),
      payload: { a: "1", b: "2", huge: "y".repeat(400) },
      bridgeRuntime: "ldw-operations-bridge",
      bridgeVersion: "1.0.0",
      startedAt: new Date().toISOString()
    },
    new Date().toISOString()
  );
  assert.equal(bounded.terminalStatus, "BLOCKED");
  assert.ok(bounded.evidence.length <= 512);
  assert.ok(bounded.payload.huge.length <= 256);
  assert.equal(bounded.bridgeRuntime, "ldw-operations-bridge");
  assert.equal(bounded.operation, "browser.list_tabs");
  assert.equal(bounded.resultClass, "BLOCKED");
  assert.ok(bounded.startedAt);

  const lost = finalizeTerminal(
    row,
    "conn-wrong",
    {
      correlationId: "corr-wrong",
      idempotencyKey: "idem-term",
      status: "PASS",
      evidence: "forged",
      payload: { ready: "true" }
    },
    new Date().toISOString()
  );
  assert.equal(lost.terminalStatus, "AMBIGUOUS");
  assert.equal(lost.correlationId, "corr-term");
  assert.deepEqual(lost.payload, {});
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

test("connect endpoint enforces WebSocket upgrade and bridge role", async () => {
  const env = buildEnv();
  const site = await sendWithToken(env, env.SITE_DISPATCH_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET");
  assert.equal(site.status, 403);

  const bridge = await sendWithToken(env, env.BRIDGE_CLIENT_TOKEN, "/relay/connect?bridgeId=ldw01-bridge", "GET");
  assert.equal(bridge.status, 426);
});

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
  socket.serializeAttachment({ bridgeId, connectionId: crypto.randomUUID() });
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

  return {
    exec(query, ...params) {
      const sql = String(query).replace(/\s+/g, " ").trim();

      if (sql.startsWith("CREATE TABLE")) {
        return [];
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

function sendWithToken(env, token, path, method, body) {
  return relayWorker.fetch(
    new Request(`https://relay.example${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }),
    env
  );
}
