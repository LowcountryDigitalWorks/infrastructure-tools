const RELAY_PATHS = {
  dispatch: "/relay/dispatch",
  connect: "/relay/connect",
  terminal: "/relay/terminal",
  syntheticConnect: "/relay/synthetic/connect"
};

export default {
  async fetch(request, env) {
    if (!isAuthorized(request, env)) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const url = new URL(request.url);
    if (url.pathname === RELAY_PATHS.dispatch && request.method === "POST") {
      const body = await readJson(request);
      if (!body || typeof body.bridgeId !== "string" || body.bridgeId.length === 0) {
        return jsonResponse({ error: "bridgeId is required." }, 400);
      }

      const response = await forwardToBridgeObject(env, body.bridgeId, "/dispatch", request.method, body);
      return response;
    }

    if (url.pathname === RELAY_PATHS.connect && request.method === "GET") {
      const bridgeId = url.searchParams.get("bridgeId");
      const connectionId = url.searchParams.get("connectionId");
      if (!bridgeId || !connectionId) {
        return jsonResponse({ error: "bridgeId and connectionId are required." }, 400);
      }

      const forwardPath = `/connect?bridgeId=${encodeURIComponent(bridgeId)}&connectionId=${encodeURIComponent(connectionId)}`;
      return forwardToBridgeObject(env, bridgeId, forwardPath, request.method, null, request);
    }

    if (url.pathname === RELAY_PATHS.syntheticConnect && request.method === "POST") {
      const body = await readJson(request);
      if (!body || typeof body.bridgeId !== "string" || typeof body.connectionId !== "string") {
        return jsonResponse({ error: "bridgeId and connectionId are required." }, 400);
      }

      return forwardToBridgeObject(env, body.bridgeId, "/synthetic/connect", "POST", body);
    }

    if (url.pathname === RELAY_PATHS.terminal && request.method === "POST") {
      const body = await readJson(request);
      if (!body || typeof body.bridgeId !== "string" || typeof body.connectionId !== "string") {
        return jsonResponse({ error: "bridgeId and connectionId are required." }, 400);
      }

      const headers = new Headers({ "content-type": "application/json", "x-bridge-connection-id": body.connectionId });
      return forwardToBridgeObject(env, body.bridgeId, "/synthetic/terminal", "POST", body, undefined, headers);
    }

    if (url.pathname.startsWith("/relay/dispatch/") && request.method === "GET") {
      const dispatchId = url.pathname.slice("/relay/dispatch/".length);
      const bridgeId = url.searchParams.get("bridgeId");
      if (!dispatchId || !bridgeId) {
        return jsonResponse({ error: "dispatchId path and bridgeId query are required." }, 400);
      }

      return forwardToBridgeObject(env, bridgeId, `/dispatch/${encodeURIComponent(dispatchId)}`, "GET", null);
    }

    return jsonResponse({ error: "Not found" }, 404);
  }
};

export class BridgeRelayDurableObject {
  constructor(state) {
    this.state = state;
    this.repository = createRepository(state);
    this.connections = new Map();
    this.repository.initialize();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/dispatch" && request.method === "POST") {
      const body = await readJson(request);
      const accepted = this.repository.acceptDispatch(body, new Date().toISOString());
      if (!accepted.ok) {
        return jsonResponse({ error: accepted.error }, 400);
      }

      const selectedConnectionId = this.selectConnectionId(accepted.record.bridge_id);
      if (selectedConnectionId) {
        this.repository.markDelivered(accepted.record.dispatch_id, selectedConnectionId, new Date().toISOString());
      }

      return jsonResponse(
        {
          state: accepted.state,
          dispatchId: accepted.record.dispatch_id,
          correlationId: accepted.record.correlation_id,
          deliveryConnectionId: selectedConnectionId
        },
        200
      );
    }

    if (url.pathname === "/synthetic/connect" && request.method === "POST") {
      const body = await readJson(request);
      if (!body || typeof body.bridgeId !== "string" || typeof body.connectionId !== "string") {
        return jsonResponse({ error: "bridgeId and connectionId are required." }, 400);
      }

      this.connections.set(body.connectionId, { bridgeId: body.bridgeId });
      return jsonResponse({ state: "connected", connectionId: body.connectionId }, 200);
    }

    if (url.pathname === "/connect" && request.method === "GET") {
      return this.handleWebSocketConnect(request, url);
    }

    if (url.pathname === "/synthetic/terminal" && request.method === "POST") {
      const connectionId = request.headers.get("x-bridge-connection-id");
      if (!connectionId) {
        return jsonResponse({ error: "x-bridge-connection-id is required." }, 400);
      }

      const body = await readJson(request);
      const completed = this.repository.completeFromClient(connectionId, body, new Date().toISOString());
      if (!completed.ok) {
        const status = completed.error === "not-found" ? 404 : 409;
        return jsonResponse({ error: completed.error }, status);
      }

      return jsonResponse({ state: "terminal", result: completed.result }, 200);
    }

    if (url.pathname.startsWith("/dispatch/") && request.method === "GET") {
      const dispatchId = decodeURIComponent(url.pathname.slice("/dispatch/".length));
      const record = this.repository.getDispatch(dispatchId);
      if (!record) {
        return jsonResponse({ error: "not-found" }, 404);
      }

      return jsonResponse(record, 200);
    }

    return jsonResponse({ error: "Not found" }, 404);
  }

  handleWebSocketConnect(request, url) {
    const upgrade = request.headers.get("Upgrade");
    if (!upgrade || !upgrade.toLowerCase().includes("websocket")) {
      return jsonResponse({ error: "WebSocket upgrade required." }, 426);
    }

    if (typeof WebSocketPair === "undefined") {
      return jsonResponse({ error: "WebSocket runtime unavailable in this environment." }, 501);
    }

    const bridgeId = url.searchParams.get("bridgeId");
    const connectionId = url.searchParams.get("connectionId");
    if (!bridgeId || !connectionId) {
      return jsonResponse({ error: "bridgeId and connectionId are required." }, 400);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    this.connections.set(connectionId, { bridgeId, socket: server });
    server.addEventListener("message", (event) => {
      const payload = safeParseJson(event.data);
      if (!payload || payload.type !== "terminal") {
        return;
      }

      this.repository.completeFromClient(connectionId, payload, new Date().toISOString());
    });
    server.addEventListener("close", () => {
      this.connections.delete(connectionId);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  selectConnectionId(bridgeId) {
    for (const [connectionId, connection] of this.connections.entries()) {
      if (connection.bridgeId === bridgeId) {
        return connectionId;
      }
    }

    return null;
  }
}

function createRepository(state) {
  const sql = state?.storage?.sql;
  if (sql && typeof sql.exec === "function") {
    return new SqliteRelayRepository(sql);
  }

  return new InMemoryRelayRepository();
}

class SqliteRelayRepository {
  constructor(sql) {
    this.sql = sql;
  }

  initialize() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS dispatches (
        dispatch_id TEXT PRIMARY KEY,
        bridge_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        correlation_id TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        lifecycle TEXT NOT NULL,
        delivery_connection_id TEXT,
        terminal_status TEXT,
        terminal_correlation_id TEXT,
        terminal_evidence TEXT,
        terminal_payload_json TEXT,
        completed_at TEXT
      );
    `);
  }

  acceptDispatch(payload, nowIso) {
    const normalized = normalizeDispatchPayload(payload);
    if (!normalized.ok) {
      return normalized;
    }

    const existing = this.first(
      this.sql.exec("SELECT * FROM dispatches WHERE idempotency_key = ?1", normalized.record.idempotency_key)
    );
    if (existing) {
      return { ok: true, state: "duplicate", record: existing };
    }

    this.sql.exec(
      `INSERT INTO dispatches
       (dispatch_id, bridge_id, idempotency_key, correlation_id, issued_at, expires_at, lifecycle)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      normalized.record.dispatch_id,
      normalized.record.bridge_id,
      normalized.record.idempotency_key,
      normalized.record.correlation_id,
      normalized.record.issued_at,
      normalized.record.expires_at,
      "queued"
    );

    return { ok: true, state: "accepted", record: normalized.record };
  }

  markDelivered(dispatchId, connectionId) {
    this.sql.exec(
      `UPDATE dispatches
       SET lifecycle = 'delivered', delivery_connection_id = ?2
       WHERE dispatch_id = ?1 AND terminal_status IS NULL`,
      dispatchId,
      connectionId
    );
  }

  completeFromClient(connectionId, payload, nowIso) {
    const dispatchId = payload?.dispatchId;
    if (typeof dispatchId !== "string" || dispatchId.length === 0) {
      return { ok: false, error: "invalid-dispatch-id" };
    }

    const row = this.first(this.sql.exec("SELECT * FROM dispatches WHERE dispatch_id = ?1", dispatchId));
    if (!row) {
      return { ok: false, error: "not-found" };
    }

    if (row.terminal_status) {
      return { ok: false, error: "already-terminal" };
    }

    const result = finalizeTerminal(row, connectionId, payload, nowIso);
    this.sql.exec(
      `UPDATE dispatches
       SET lifecycle = 'terminal',
           terminal_status = ?2,
           terminal_correlation_id = ?3,
           terminal_evidence = ?4,
           terminal_payload_json = ?5,
           completed_at = ?6
       WHERE dispatch_id = ?1`,
      dispatchId,
      result.terminalStatus,
      result.correlationId,
      result.evidence,
      JSON.stringify(result.payload),
      nowIso
    );

    return { ok: true, result };
  }

  getDispatch(dispatchId) {
    return this.first(this.sql.exec("SELECT * FROM dispatches WHERE dispatch_id = ?1", dispatchId)) || null;
  }

  first(iterable) {
    for (const row of iterable) {
      return row;
    }

    return null;
  }
}

class InMemoryRelayRepository {
  constructor() {
    this.dispatches = new Map();
    this.idempotency = new Map();
  }

  initialize() {}

  acceptDispatch(payload) {
    const normalized = normalizeDispatchPayload(payload);
    if (!normalized.ok) {
      return normalized;
    }

    const existingDispatchId = this.idempotency.get(normalized.record.idempotency_key);
    if (existingDispatchId) {
      return { ok: true, state: "duplicate", record: this.dispatches.get(existingDispatchId) };
    }

    this.dispatches.set(normalized.record.dispatch_id, { ...normalized.record });
    this.idempotency.set(normalized.record.idempotency_key, normalized.record.dispatch_id);
    return { ok: true, state: "accepted", record: normalized.record };
  }

  markDelivered(dispatchId, connectionId) {
    const row = this.dispatches.get(dispatchId);
    if (!row || row.terminal_status) {
      return;
    }

    row.lifecycle = "delivered";
    row.delivery_connection_id = connectionId;
  }

  completeFromClient(connectionId, payload, nowIso) {
    const dispatchId = payload?.dispatchId;
    if (typeof dispatchId !== "string" || dispatchId.length === 0) {
      return { ok: false, error: "invalid-dispatch-id" };
    }

    const row = this.dispatches.get(dispatchId);
    if (!row) {
      return { ok: false, error: "not-found" };
    }

    if (row.terminal_status) {
      return { ok: false, error: "already-terminal" };
    }

    const result = finalizeTerminal(row, connectionId, payload, nowIso);
    row.lifecycle = "terminal";
    row.terminal_status = result.terminalStatus;
    row.terminal_correlation_id = result.correlationId;
    row.terminal_evidence = result.evidence;
    row.terminal_payload_json = JSON.stringify(result.payload);
    row.completed_at = nowIso;
    return { ok: true, result };
  }

  getDispatch(dispatchId) {
    return this.dispatches.get(dispatchId) ?? null;
  }
}

function normalizeDispatchPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "invalid-dispatch-payload" };
  }

  if (typeof payload.dispatchId !== "string" ||
      typeof payload.bridgeId !== "string" ||
      typeof payload.idempotencyKey !== "string" ||
      typeof payload.correlationId !== "string" ||
      typeof payload.issuedAt !== "string" ||
      typeof payload.expiresAt !== "string") {
    return { ok: false, error: "invalid-dispatch-envelope" };
  }

  return {
    ok: true,
    record: {
      dispatch_id: payload.dispatchId,
      bridge_id: payload.bridgeId,
      idempotency_key: payload.idempotencyKey,
      correlation_id: payload.correlationId,
      issued_at: payload.issuedAt,
      expires_at: payload.expiresAt,
      lifecycle: "queued",
      delivery_connection_id: null,
      terminal_status: null,
      terminal_correlation_id: null,
      terminal_evidence: null,
      terminal_payload_json: null,
      completed_at: null
    }
  };
}

function finalizeTerminal(row, connectionId, payload, nowIso) {
  let terminalStatus = typeof payload?.status === "string" ? payload.status : "FAILED";
  let evidence = typeof payload?.evidence === "string" ? payload.evidence : "Client terminal message.";
  let resultPayload = payload?.payload && typeof payload.payload === "object" ? payload.payload : {};

  if (row.delivery_connection_id !== connectionId || row.correlation_id !== payload?.correlationId) {
    terminalStatus = "AMBIGUOUS";
    evidence = "Lost correlation or connection identity mismatch.";
    resultPayload = {};
  }

  if (terminalStatus === "PASS" && Date.parse(nowIso) > Date.parse(row.expires_at)) {
    terminalStatus = "STALE";
    evidence = "Result arrived after expiry.";
    resultPayload = {};
  }

  return {
    dispatchId: row.dispatch_id,
    idempotencyKey: row.idempotency_key,
    correlationId: row.correlation_id,
    terminalStatus,
    completedAt: nowIso,
    evidence,
    payload: resultPayload
  };
}

async function forwardToBridgeObject(env, bridgeId, path, method, body, sourceRequest, overrideHeaders) {
  if (!env?.BRIDGE_RELAY || typeof env.BRIDGE_RELAY.idFromName !== "function" || typeof env.BRIDGE_RELAY.get !== "function") {
    return jsonResponse({ error: "Durable Object binding BRIDGE_RELAY is missing." }, 500);
  }

  const id = env.BRIDGE_RELAY.idFromName(bridgeId);
  const stub = env.BRIDGE_RELAY.get(id);
  const headers = overrideHeaders ?? sourceRequest?.headers ?? new Headers({ "content-type": "application/json" });
  const init = { method, headers };
  if (body !== null && body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const request = new Request(`https://relay.internal${path}`, init);
  return stub.fetch(request);
}

function isAuthorized(request, env) {
  if (!env || typeof env.BRIDGE_SHARED_TOKEN !== "string" || env.BRIDGE_SHARED_TOKEN.length === 0) {
    return false;
  }

  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return false;
  }

  const supplied = authHeader.slice("Bearer ".length);
  return supplied === env.BRIDGE_SHARED_TOKEN;
}

function jsonResponse(payload, status) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function safeParseJson(value) {
  if (typeof value !== "string") {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}
