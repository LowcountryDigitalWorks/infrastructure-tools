const RELAY_PATHS = {
  dispatch: "/relay/dispatch",
  connect: "/relay/connect"
};

const PROTOCOL_VERSION = "1.0";
const BRIDGE_RUNTIME = "ldw-operations-bridge";
const BRIDGE_RUNTIME_VERSION = "1.0.0";
const MAX_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_EVIDENCE_LENGTH = 512;
const MAX_PAYLOAD_ENTRIES = 32;
const MAX_PAYLOAD_VALUE_LENGTH = 256;
const MAX_ARG_ENTRIES = 16;
const MAX_ARG_VALUE_LENGTH = 256;
const MAX_BRIDGE_RUNTIME_LENGTH = 64;
const MAX_BRIDGE_VERSION_LENGTH = 32;

const ALLOWED_OPERATIONS = new Set(["browser.health", "browser.list_tabs", "browser.read_tab"]);
const ALLOWED_TERMINAL_STATUSES = new Set(["PASS", "BLOCKED", "FAILED", "STALE", "AMBIGUOUS"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const HIBERNATION_RUNTIME_CONTRACT = Object.freeze({
  acceptWebSocket: "state.acceptWebSocket",
  getWebSockets: "state.getWebSockets",
  serializeAttachment: "WebSocket.serializeAttachment",
  deserializeAttachment: "WebSocket.deserializeAttachment",
  webSocketMessage: "DurableObject.webSocketMessage",
  webSocketClose: "DurableObject.webSocketClose"
});

export default {
  async fetch(request, env) {
    const role = resolveCallerRole(request, env);
    if (!role) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const url = new URL(request.url);
    if (url.pathname === RELAY_PATHS.dispatch && request.method === "POST") {
      if (role !== "site") {
        return jsonResponse({ error: "Site role required for dispatch." }, 403);
      }

      const body = await readJson(request);
      const boundBridgeId = requireConfiguredBridgeId(env);
      if (!boundBridgeId.ok) {
        return jsonResponse({ error: boundBridgeId.error }, 500);
      }

      if (!body || typeof body.bridgeId !== "string" || body.bridgeId !== boundBridgeId.bridgeId) {
        return jsonResponse({ error: "bridgeId must match the server-bound bridge identity." }, 400);
      }

      return forwardToBridgeObject(env, boundBridgeId.bridgeId, "/dispatch", request.method, body);
    }

    if (url.pathname === RELAY_PATHS.connect && request.method === "GET") {
      if (role !== "bridge") {
        return jsonResponse({ error: "Bridge role required for connect." }, 403);
      }

      const boundBridgeId = requireConfiguredBridgeId(env);
      if (!boundBridgeId.ok) {
        return jsonResponse({ error: boundBridgeId.error }, 500);
      }

      const requestedBridgeId = url.searchParams.get("bridgeId");
      if (requestedBridgeId && requestedBridgeId !== boundBridgeId.bridgeId) {
        return jsonResponse({ error: "bridgeId does not match authenticated bridge identity." }, 403);
      }

      const forwardPath = `/connect?bridgeId=${encodeURIComponent(boundBridgeId.bridgeId)}`;
      return forwardToBridgeObject(env, boundBridgeId.bridgeId, forwardPath, request.method, null, request);
    }

    if (url.pathname.startsWith("/relay/dispatch/") && request.method === "GET") {
      if (role !== "site") {
        return jsonResponse({ error: "Site role required for dispatch status." }, 403);
      }

      const dispatchId = url.pathname.slice("/relay/dispatch/".length);
      const boundBridgeId = requireConfiguredBridgeId(env);
      if (!boundBridgeId.ok) {
        return jsonResponse({ error: boundBridgeId.error }, 500);
      }

      if (!dispatchId) {
        return jsonResponse({ error: "dispatchId path is required." }, 400);
      }

      return forwardToBridgeObject(
        env,
        boundBridgeId.bridgeId,
        `/dispatch/${encodeURIComponent(dispatchId)}`,
        "GET",
        null
      );
    }

    // Explicitly closed: Site cannot submit terminal results; Bridge cannot dispatch via HTTP.
    if (url.pathname === "/relay/terminal") {
      return jsonResponse({ error: "Terminal submission is bridge-WebSocket only." }, 405);
    }

    return jsonResponse({ error: "Not found" }, 404);
  }
};

export class BridgeRelayDurableObject {
  constructor(state) {
    this.state = state;
    this.repository = createRepository(state);
    if (typeof state?.blockConcurrencyWhile === "function") {
      state.blockConcurrencyWhile(() => {
        this.repository.initialize();
        return Promise.resolve();
      });
    } else {
      this.repository.initialize();
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/dispatch" && request.method === "POST") {
      const body = await readJson(request);
      const nowIso = new Date().toISOString();
      this.repository.resolveNonterminal(nowIso);
      const accepted = this.repository.acceptDispatch(body, nowIso);
      if (!accepted.ok) {
        return jsonResponse({ error: accepted.error }, 400);
      }

      if (accepted.state === "duplicate") {
        return jsonResponse(sanitizeSiteDispatchResponse(accepted), 200);
      }

      const selected = this.selectBridgeSocket(accepted.record.bridge_id);
      if (!selected) {
        return jsonResponse(
          {
            state: accepted.state,
            dispatchId: accepted.record.dispatch_id,
            correlationId: accepted.record.correlation_id,
            delivery: "pending"
          },
          200
        );
      }

      const envelope = buildDeliveryEnvelope(accepted.record);
      try {
        selected.socket.send(JSON.stringify(envelope));
      } catch {
        return jsonResponse(
          {
            state: accepted.state,
            dispatchId: accepted.record.dispatch_id,
            correlationId: accepted.record.correlation_id,
            delivery: "send_failed"
          },
          200
        );
      }

      this.repository.markDelivered(
        accepted.record.dispatch_id,
        selected.connectionId,
        new Date().toISOString()
      );

      return jsonResponse(
        {
          state: "delivered",
          dispatchId: accepted.record.dispatch_id,
          correlationId: accepted.record.correlation_id,
          delivery: "sent"
        },
        200
      );
    }

    if (url.pathname === "/connect" && request.method === "GET") {
      return this.handleWebSocketConnect(request, url);
    }

    if (url.pathname.startsWith("/dispatch/") && request.method === "GET") {
      const dispatchId = decodeURIComponent(url.pathname.slice("/dispatch/".length));
      this.repository.resolveNonterminal(new Date().toISOString());
      const record = this.repository.getDispatch(dispatchId);
      if (!record) {
        return jsonResponse({ error: "not-found" }, 404);
      }

      return jsonResponse(sanitizeSiteDispatchRecord(record), 200);
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
    if (!bridgeId) {
      return jsonResponse({ error: "bridgeId is required." }, 400);
    }

    if (typeof this.state?.acceptWebSocket !== "function") {
      return jsonResponse({ error: "Durable Object hibernation acceptWebSocket API unavailable." }, 501);
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const connectionId = crypto.randomUUID();

    // Hibernation path: attach via acceptWebSocket + attachment (not the non-hibernating accept API).
    this.state.acceptWebSocket(server, [bridgeId]);
    server.serializeAttachment({ bridgeId, connectionId });

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    const attachment = safeDeserializeAttachment(ws);
    if (!attachment?.connectionId || !attachment?.bridgeId) {
      return;
    }

    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    const payload = safeParseJson(text);
    if (!payload || payload.type !== "terminal") {
      return;
    }

    // Exact bridge identity and connection id are bound server-side from the hibernated socket.
    this.repository.completeFromClient(attachment.connectionId, payload, new Date().toISOString());
  }

  async webSocketClose(ws, code, reason) {
    const attachment = safeDeserializeAttachment(ws);
    if (attachment?.connectionId) {
      this.repository.resolveConnectionLoss(attachment.connectionId, new Date().toISOString());
    }

    try {
      ws.close(code, reason);
    } catch {
      // already closing/closed
    }
  }

  async webSocketError(ws) {
    const attachment = safeDeserializeAttachment(ws);
    if (attachment?.connectionId) {
      this.repository.resolveConnectionLoss(attachment.connectionId, new Date().toISOString());
    }

    try {
      ws.close(1011, "error");
    } catch {
      // already closing/closed
    }
  }

  selectBridgeSocket(bridgeId) {
    if (typeof this.state?.getWebSockets !== "function") {
      return null;
    }

    const sockets = this.state.getWebSockets(bridgeId);
    for (const socket of sockets) {
      const attachment = safeDeserializeAttachment(socket);
      if (!attachment || attachment.bridgeId !== bridgeId || typeof attachment.connectionId !== "string") {
        continue;
      }

      if (typeof socket.readyState === "number" && socket.readyState !== 1) {
        continue;
      }

      if (typeof socket.send !== "function") {
        continue;
      }

      return { socket, connectionId: attachment.connectionId };
    }

    return null;
  }
}

export function createRepository(state) {
  const sql = state?.storage?.sql;
  if (sql && typeof sql.exec === "function") {
    return new SqliteRelayRepository(sql);
  }

  return new InMemoryRelayRepository();
}

export class SqliteRelayRepository {
  constructor(sql) {
    this.sql = sql;
  }

  initialize() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS dispatches (
        dispatch_id TEXT PRIMARY KEY,
        bridge_id TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        operation TEXT NOT NULL,
        args_json TEXT NOT NULL,
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
        started_at TEXT,
        completed_at TEXT,
        bridge_runtime TEXT,
        bridge_version TEXT,
        result_class TEXT
      );
    `);
  }

  acceptDispatch(payload, nowIso) {
    const normalized = normalizeDispatchPayload(payload, nowIso);
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
       (dispatch_id, bridge_id, protocol_version, operation, args_json, idempotency_key, correlation_id,
        issued_at, expires_at, lifecycle)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
      normalized.record.dispatch_id,
      normalized.record.bridge_id,
      normalized.record.protocol_version,
      normalized.record.operation,
      normalized.record.args_json,
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

    if (typeof payload?.idempotencyKey !== "string" || payload.idempotencyKey.length === 0) {
      return { ok: false, error: "missing-idempotency-key" };
    }

    if (payload.idempotencyKey !== row.idempotency_key) {
      return { ok: false, error: "idempotency-mismatch" };
    }

    const result = finalizeTerminal(row, connectionId, payload, nowIso);
    this.applyTerminal(dispatchId, result);
    return { ok: true, result };
  }

  resolveNonterminal(nowIso) {
    const rows = [...this.sql.exec("SELECT * FROM dispatches WHERE terminal_status IS NULL")];
    let updated = 0;
    for (const row of rows) {
      const resolution = buildExpiryResolution(row, nowIso);
      if (!resolution) {
        continue;
      }

      this.applyTerminal(row.dispatch_id, resolution);
      updated += 1;
    }

    return updated;
  }

  resolveConnectionLoss(connectionId, nowIso) {
    if (typeof connectionId !== "string" || connectionId.length === 0) {
      return 0;
    }

    const rows = [
      ...this.sql.exec(
        `SELECT * FROM dispatches
         WHERE terminal_status IS NULL
           AND delivery_connection_id = ?1
           AND lifecycle IN ('delivered', 'started')`,
        connectionId
      )
    ];
    let updated = 0;
    for (const row of rows) {
      this.applyTerminal(
        row.dispatch_id,
        buildResolvedTerminal(
          row,
          "AMBIGUOUS",
          "Bridge connection lost after delivery before terminal return.",
          nowIso,
          row.started_at || nowIso
        )
      );
      updated += 1;
    }

    return updated;
  }

  getDispatch(dispatchId) {
    return this.first(this.sql.exec("SELECT * FROM dispatches WHERE dispatch_id = ?1", dispatchId)) || null;
  }

  applyTerminal(dispatchId, result) {
    this.sql.exec(
      `UPDATE dispatches
       SET lifecycle = 'terminal',
           terminal_status = ?2,
           terminal_correlation_id = ?3,
           terminal_evidence = ?4,
           terminal_payload_json = ?5,
           started_at = ?6,
           completed_at = ?7,
           bridge_runtime = ?8,
           bridge_version = ?9,
           result_class = ?10
       WHERE dispatch_id = ?1 AND terminal_status IS NULL`,
      dispatchId,
      result.terminalStatus,
      result.correlationId,
      result.evidence,
      JSON.stringify(result.payload),
      result.startedAt,
      result.completedAt,
      result.bridgeRuntime,
      result.bridgeVersion,
      result.resultClass
    );
  }

  first(iterable) {
    for (const row of iterable) {
      return row;
    }

    return null;
  }
}

export class InMemoryRelayRepository {
  constructor() {
    this.dispatches = new Map();
    this.idempotency = new Map();
  }

  initialize() {}

  acceptDispatch(payload, nowIso) {
    const normalized = normalizeDispatchPayload(payload, nowIso);
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

    if (typeof payload?.idempotencyKey !== "string" || payload.idempotencyKey.length === 0) {
      return { ok: false, error: "missing-idempotency-key" };
    }

    if (payload.idempotencyKey !== row.idempotency_key) {
      return { ok: false, error: "idempotency-mismatch" };
    }

    const result = finalizeTerminal(row, connectionId, payload, nowIso);
    applyInMemoryTerminal(row, result);
    return { ok: true, result };
  }

  resolveNonterminal(nowIso) {
    let updated = 0;
    for (const row of this.dispatches.values()) {
      if (row.terminal_status) {
        continue;
      }

      const resolution = buildExpiryResolution(row, nowIso);
      if (!resolution) {
        continue;
      }

      applyInMemoryTerminal(row, resolution);
      updated += 1;
    }

    return updated;
  }

  resolveConnectionLoss(connectionId, nowIso) {
    if (typeof connectionId !== "string" || connectionId.length === 0) {
      return 0;
    }

    let updated = 0;
    for (const row of this.dispatches.values()) {
      if (row.terminal_status || row.delivery_connection_id !== connectionId) {
        continue;
      }

      if (row.lifecycle !== "delivered" && row.lifecycle !== "started") {
        continue;
      }

      applyInMemoryTerminal(
        row,
        buildResolvedTerminal(
          row,
          "AMBIGUOUS",
          "Bridge connection lost after delivery before terminal return.",
          nowIso,
          row.started_at || nowIso
        )
      );
      updated += 1;
    }

    return updated;
  }

  getDispatch(dispatchId) {
    return this.dispatches.get(dispatchId) ?? null;
  }
}

export function normalizeDispatchPayload(payload, nowIso) {
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "invalid-dispatch-payload" };
  }

  if (typeof payload.protocolVersion !== "string" ||
      typeof payload.dispatchId !== "string" ||
      typeof payload.bridgeId !== "string" ||
      typeof payload.operation !== "string" ||
      typeof payload.idempotencyKey !== "string" ||
      typeof payload.correlationId !== "string" ||
      typeof payload.issuedAt !== "string" ||
      typeof payload.expiresAt !== "string") {
    return { ok: false, error: "invalid-dispatch-envelope" };
  }

  if (payload.protocolVersion !== PROTOCOL_VERSION) {
    return { ok: false, error: "unknown-protocol" };
  }

  if (!UUID_RE.test(payload.dispatchId)) {
    return { ok: false, error: "invalid-dispatch-id" };
  }

  if (!ALLOWED_OPERATIONS.has(payload.operation)) {
    return { ok: false, error: "unknown-operation" };
  }

  if (typeof payload.bridgeId !== "string" || payload.bridgeId.length === 0) {
    return { ok: false, error: "unknown-bridge" };
  }

  const issuedAtMs = Date.parse(payload.issuedAt);
  const expiresAtMs = Date.parse(payload.expiresAt);
  const nowMs = Date.parse(nowIso);
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs)) {
    return { ok: false, error: "invalid-timestamps" };
  }

  if (expiresAtMs <= issuedAtMs ||
      expiresAtMs - issuedAtMs > MAX_TTL_MS ||
      nowMs > expiresAtMs ||
      nowMs < issuedAtMs - MAX_CLOCK_SKEW_MS) {
    return { ok: false, error: "stale-or-expired" };
  }

  const args = normalizeArgs(payload.args);
  if (!args.ok) {
    return args;
  }

  return {
    ok: true,
    record: {
      dispatch_id: payload.dispatchId,
      bridge_id: payload.bridgeId,
      protocol_version: payload.protocolVersion,
      operation: payload.operation,
      args_json: JSON.stringify(args.value),
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
      started_at: null,
      completed_at: null,
      bridge_runtime: null,
      bridge_version: null,
      result_class: null
    }
  };
}

export function finalizeTerminal(row, connectionId, payload, nowIso) {
  let terminalStatus = typeof payload?.status === "string" ? payload.status : "FAILED";
  let evidence = typeof payload?.evidence === "string" ? payload.evidence : "Client terminal message.";
  let resultPayload = normalizeTerminalPayload(payload?.payload);

  if (!ALLOWED_TERMINAL_STATUSES.has(terminalStatus)) {
    terminalStatus = "FAILED";
    evidence = "Unsupported terminal status.";
    resultPayload = {};
  }

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

  const startedAt = normalizeIsoTimestamp(payload?.startedAt) || nowIso;
  const bridgeRuntime = boundBridgeRuntime(payload?.bridgeRuntime);
  const bridgeVersion = boundBridgeVersion(payload?.bridgeVersion);
  const operation = typeof row.operation === "string" ? row.operation : "unknown";

  return {
    dispatchId: row.dispatch_id,
    idempotencyKey: row.idempotency_key,
    correlationId: row.correlation_id,
    bridgeRuntime,
    bridgeVersion,
    operation,
    resultClass: terminalStatus,
    terminalStatus,
    startedAt,
    completedAt: nowIso,
    evidence: boundEvidence(evidence),
    payload: resultPayload
  };
}

function buildExpiryResolution(row, nowIso) {
  const expiresAtMs = Date.parse(row.expires_at);
  const nowMs = Date.parse(nowIso);
  if (!Number.isFinite(expiresAtMs) || !Number.isFinite(nowMs) || nowMs <= expiresAtMs) {
    return null;
  }

  if (row.lifecycle === "started" || row.started_at) {
    return buildResolvedTerminal(
      row,
      "AMBIGUOUS",
      "Connection dropped before correlated terminal result.",
      nowIso,
      row.started_at || nowIso
    );
  }

  if (row.lifecycle === "delivered") {
    return buildResolvedTerminal(
      row,
      "AMBIGUOUS",
      "Dispatch expired after delivery without terminal return.",
      nowIso,
      row.started_at || nowIso
    );
  }

  return buildResolvedTerminal(
    row,
    "STALE",
    "Dispatch expired before execution start.",
    nowIso,
    nowIso
  );
}

function buildResolvedTerminal(row, terminalStatus, evidence, nowIso, startedAt) {
  return {
    dispatchId: row.dispatch_id,
    idempotencyKey: row.idempotency_key,
    correlationId: row.correlation_id,
    bridgeRuntime: BRIDGE_RUNTIME,
    bridgeVersion: BRIDGE_RUNTIME_VERSION,
    operation: typeof row.operation === "string" ? row.operation : "unknown",
    resultClass: terminalStatus,
    terminalStatus,
    startedAt,
    completedAt: nowIso,
    evidence: boundEvidence(evidence),
    payload: {}
  };
}

function applyInMemoryTerminal(row, result) {
  row.lifecycle = "terminal";
  row.terminal_status = result.terminalStatus;
  row.terminal_correlation_id = result.correlationId;
  row.terminal_evidence = result.evidence;
  row.terminal_payload_json = JSON.stringify(result.payload);
  row.started_at = result.startedAt;
  row.completed_at = result.completedAt;
  row.bridge_runtime = result.bridgeRuntime;
  row.bridge_version = result.bridgeVersion;
  row.result_class = result.resultClass;
}

function buildDeliveryEnvelope(record) {
  let args = {};
  try {
    args = JSON.parse(record.args_json || "{}");
  } catch {
    args = {};
  }

  return {
    type: "dispatch",
    protocolVersion: record.protocol_version,
    dispatchId: record.dispatch_id,
    bridgeId: record.bridge_id,
    operation: record.operation,
    issuedAt: record.issued_at,
    expiresAt: record.expires_at,
    idempotencyKey: record.idempotency_key,
    correlationId: record.correlation_id,
    args
  };
}

function sanitizeSiteDispatchResponse(accepted) {
  return {
    state: accepted.state,
    dispatchId: accepted.record.dispatch_id,
    correlationId: accepted.record.correlation_id,
    delivery: accepted.record.lifecycle === "delivered" ? "sent" : accepted.record.lifecycle
  };
}

function sanitizeSiteDispatchRecord(record) {
  return {
    dispatch_id: record.dispatch_id,
    bridge_id: record.bridge_id,
    protocol_version: record.protocol_version,
    operation: record.operation,
    args_json: record.args_json,
    idempotency_key: record.idempotency_key,
    correlation_id: record.correlation_id,
    issued_at: record.issued_at,
    expires_at: record.expires_at,
    lifecycle: record.lifecycle,
    terminal_status: record.terminal_status,
    terminal_correlation_id: record.terminal_correlation_id,
    terminal_evidence: record.terminal_evidence,
    terminal_payload_json: record.terminal_payload_json,
    started_at: record.started_at,
    completed_at: record.completed_at,
    bridge_runtime: record.bridge_runtime,
    bridge_version: record.bridge_version,
    result_class: record.result_class
    // delivery_connection_id intentionally omitted from Site-facing views
  };
}

function normalizeArgs(args) {
  if (args === undefined || args === null) {
    return { ok: true, value: {} };
  }

  if (typeof args !== "object" || Array.isArray(args)) {
    return { ok: false, error: "invalid-args" };
  }

  const entries = Object.entries(args);
  if (entries.length > MAX_ARG_ENTRIES) {
    return { ok: false, error: "args-overflow" };
  }

  const normalized = {};
  for (const [key, value] of entries) {
    if (typeof key !== "string" || key.length === 0 || typeof value !== "string") {
      return { ok: false, error: "invalid-args" };
    }

    if (value.length > MAX_ARG_VALUE_LENGTH) {
      return { ok: false, error: "arg-value-too-long" };
    }

    normalized[key] = value;
  }

  return { ok: true, value: normalized };
}

function normalizeTerminalPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {};
  }

  const result = {};
  for (const [key, value] of Object.entries(payload)) {
    if (Object.keys(result).length >= MAX_PAYLOAD_ENTRIES) {
      break;
    }

    if (typeof key !== "string" || key.length === 0) {
      continue;
    }

    const text = typeof value === "string" ? value : String(value);
    result[key] = text.length > MAX_PAYLOAD_VALUE_LENGTH ? text.slice(0, MAX_PAYLOAD_VALUE_LENGTH) : text;
  }

  return result;
}

function boundEvidence(evidence) {
  const value = typeof evidence === "string" && evidence.trim().length > 0 ? evidence.trim() : "No evidence provided.";
  return value.length > MAX_EVIDENCE_LENGTH ? value.slice(0, MAX_EVIDENCE_LENGTH) : value;
}

function boundBridgeRuntime(runtime) {
  const value = typeof runtime === "string" && runtime.trim().length > 0 ? runtime.trim() : BRIDGE_RUNTIME;
  return value.length > MAX_BRIDGE_RUNTIME_LENGTH ? value.slice(0, MAX_BRIDGE_RUNTIME_LENGTH) : value;
}

function boundBridgeVersion(version) {
  const value = typeof version === "string" && version.trim().length > 0 ? version.trim() : BRIDGE_RUNTIME_VERSION;
  return value.length > MAX_BRIDGE_VERSION_LENGTH ? value.slice(0, MAX_BRIDGE_VERSION_LENGTH) : value;
}

function normalizeIsoTimestamp(value) {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }

  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function safeDeserializeAttachment(ws) {
  if (!ws || typeof ws.deserializeAttachment !== "function") {
    return null;
  }

  try {
    return ws.deserializeAttachment();
  } catch {
    return null;
  }
}

async function forwardToBridgeObject(env, bridgeId, path, method, body, sourceRequest) {
  if (!env?.BRIDGE_RELAY || typeof env.BRIDGE_RELAY.idFromName !== "function" || typeof env.BRIDGE_RELAY.get !== "function") {
    return jsonResponse({ error: "Durable Object binding BRIDGE_RELAY is missing." }, 500);
  }

  const id = env.BRIDGE_RELAY.idFromName(bridgeId);
  const stub = env.BRIDGE_RELAY.get(id);
  const headers = sourceRequest?.headers ?? new Headers({ "content-type": "application/json" });
  const init = { method, headers };
  if (body !== null && body !== undefined) {
    init.body = JSON.stringify(body);
  }

  const request = new Request(`https://relay.internal${path}`, init);
  return stub.fetch(request);
}

function resolveCallerRole(request, env) {
  const siteToken = typeof env?.SITE_DISPATCH_TOKEN === "string" ? env.SITE_DISPATCH_TOKEN : "";
  const bridgeToken = typeof env?.BRIDGE_CLIENT_TOKEN === "string" ? env.BRIDGE_CLIENT_TOKEN : "";
  if (!siteToken || !bridgeToken || siteToken === bridgeToken) {
    return null;
  }

  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  const supplied = authHeader.slice("Bearer ".length);
  if (supplied === siteToken) {
    return "site";
  }

  if (supplied === bridgeToken) {
    return "bridge";
  }

  return null;
}

function requireConfiguredBridgeId(env) {
  if (!env || typeof env.BRIDGE_ID !== "string" || env.BRIDGE_ID.length === 0) {
    return { ok: false, error: "BRIDGE_ID is not configured." };
  }

  return { ok: true, bridgeId: env.BRIDGE_ID };
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
