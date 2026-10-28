import relayWorker, {
  BridgeRelayDurableObject as BaseBridgeRelayDurableObject,
  InMemoryRelayRepository,
  SqliteRelayRepository
} from "./relay.js";

export { BaseBridgeRelayDurableObject as BridgeRelayDurableObject };

const PROTOCOL_VERSION = "1.0";
const LDW01_BRIDGE_ID = "ldw01-bridge";
const DRAGONFLY_BRIDGE_ID = "dragonfly-redrix-01";
const DRAGONFLY_DISPATCH_PATH = "/relay/dragonfly/dispatch";
const DRAGONFLY_DISPATCH_RESULT_PREFIX = "/relay/dragonfly/dispatch/";
const MAX_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const DRAGONFLY_ALLOWED_OPERATIONS = new Set([
  "dragonfly.runner.status",
  "dragonfly.runner.start",
  "dragonfly.runner.drain"
]);

export const DRAGONFLY_RELAY_CONTRACT = Object.freeze({
  bridgeId: DRAGONFLY_BRIDGE_ID,
  dispatchPath: DRAGONFLY_DISPATCH_PATH,
  operations: Object.freeze([...DRAGONFLY_ALLOWED_OPERATIONS])
});

export default {
  async fetch(request, env) {
    const tokens = resolveTokenConfiguration(env);
    if (tokens.dragonflyCollision) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const url = new URL(request.url);
    const bearer = readBearer(request.headers);
    const requestedBridgeId = url.pathname === "/relay/connect" ? readSingleBridgeId(url) : null;

    if (requestedBridgeId === DRAGONFLY_BRIDGE_ID) {
      if (!tokens.baseValid) {
        return jsonResponse({ error: "Unauthorized" }, 401);
      }
      if (!tokens.dragonflyToken) {
        return jsonResponse({ error: "Dragonfly bridge identity is not configured." }, 503);
      }
      if (bearer !== tokens.dragonflyToken) {
        return jsonResponse({ error: "Bridge role required for Dragonfly connect." }, 403);
      }
      if (request.method !== "GET" || !hasOnlyBridgeIdQuery(url, DRAGONFLY_BRIDGE_ID)) {
        return jsonResponse({ error: "Dragonfly bridge identity must be exact." }, 400);
      }

      return forwardToDragonflyObject(
        env,
        `/connect?bridgeId=${encodeURIComponent(DRAGONFLY_BRIDGE_ID)}`,
        "GET",
        null,
        request
      );
    }

    if (tokens.dragonflyToken && bearer === tokens.dragonflyToken) {
      return jsonResponse({ error: "Dragonfly bridge credential is scoped to its exact connect identity." }, 403);
    }

    if (url.pathname === DRAGONFLY_DISPATCH_PATH && request.method === "POST") {
      if (!tokens.baseValid || bearer !== tokens.siteToken) {
        return jsonResponse({ error: "Site role required for Dragonfly dispatch." }, 403);
      }
      if (!tokens.dragonflyToken) {
        return jsonResponse({ error: "Dragonfly bridge identity is not configured." }, 503);
      }

      const body = await readJson(request);
      const routeCheck = validateDragonflyRouteEnvelope(body);
      if (!routeCheck.ok) {
        return jsonResponse({ error: routeCheck.error }, 400);
      }

      return forwardToDragonflyObject(env, "/dispatch", "POST", body);
    }

    if (url.pathname.startsWith(DRAGONFLY_DISPATCH_RESULT_PREFIX) && request.method === "GET") {
      if (!tokens.baseValid || bearer !== tokens.siteToken) {
        return jsonResponse({ error: "Site role required for Dragonfly dispatch status." }, 403);
      }
      if (!tokens.dragonflyToken) {
        return jsonResponse({ error: "Dragonfly bridge identity is not configured." }, 503);
      }

      const dispatchId = url.pathname.slice(DRAGONFLY_DISPATCH_RESULT_PREFIX.length);
      if (!UUID_RE.test(dispatchId) || [...url.searchParams.keys()].length !== 0) {
        return jsonResponse({ error: "Invalid Dragonfly dispatch id." }, 400);
      }

      return forwardToDragonflyObject(
        env,
        `/dispatch/${encodeURIComponent(dispatchId)}`,
        "GET",
        null
      );
    }

    if (url.pathname.startsWith("/relay/dragonfly/")) {
      return jsonResponse({ error: "Not found" }, 404);
    }

    return relayWorker.fetch(request, env);
  }
};

export class DragonflyBridgeRelayDurableObject {
  constructor(state) {
    this.inner = new BaseBridgeRelayDurableObject(state);
    installDragonflyDispatchNormalizer(this.inner.repository);
  }

  fetch(request) {
    return this.inner.fetch(request);
  }

  webSocketMessage(ws, message) {
    return this.inner.webSocketMessage(ws, message);
  }

  webSocketClose(ws, code, reason, wasClean) {
    return this.inner.webSocketClose(ws, code, reason, wasClean);
  }

  webSocketError(ws, error) {
    return this.inner.webSocketError(ws, error);
  }
}

export function normalizeDragonflyDispatchPayload(payload, nowIso) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
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

  if (payload.bridgeId !== DRAGONFLY_BRIDGE_ID) {
    return { ok: false, error: "unknown-bridge" };
  }

  if (!DRAGONFLY_ALLOWED_OPERATIONS.has(payload.operation)) {
    return { ok: false, error: "unknown-operation" };
  }

  if (!isExactEmptyArgs(payload.args)) {
    return { ok: false, error: "invalid-operation-args" };
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

  return {
    ok: true,
    record: {
      dispatch_id: payload.dispatchId,
      bridge_id: DRAGONFLY_BRIDGE_ID,
      protocol_version: PROTOCOL_VERSION,
      operation: payload.operation,
      args_json: "{}",
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

function installDragonflyDispatchNormalizer(repository) {
  if (repository instanceof SqliteRelayRepository) {
    repository.acceptDispatch = function acceptDragonflySqliteDispatch(payload, nowIso) {
      const normalized = normalizeDragonflyDispatchPayload(payload, nowIso);
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
    };
    return;
  }

  if (repository instanceof InMemoryRelayRepository) {
    repository.acceptDispatch = function acceptDragonflyInMemoryDispatch(payload, nowIso) {
      const normalized = normalizeDragonflyDispatchPayload(payload, nowIso);
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
    };
    return;
  }

  throw new Error("Unsupported relay repository implementation.");
}

function validateDragonflyRouteEnvelope(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: "invalid-dispatch-payload" };
  }
  if (body.bridgeId !== DRAGONFLY_BRIDGE_ID) {
    return { ok: false, error: "bridgeId must match the Dragonfly relay identity." };
  }
  if (!DRAGONFLY_ALLOWED_OPERATIONS.has(body.operation)) {
    return { ok: false, error: "operation is not allowed for the Dragonfly relay identity." };
  }
  if (!isExactEmptyArgs(body.args)) {
    return { ok: false, error: "Dragonfly operations require exact empty args." };
  }
  return { ok: true };
}

function isExactEmptyArgs(args) {
  return typeof args === "object" && args !== null && !Array.isArray(args) && Object.keys(args).length === 0;
}

function resolveTokenConfiguration(env) {
  const siteToken = typeof env?.SITE_DISPATCH_TOKEN === "string" ? env.SITE_DISPATCH_TOKEN : "";
  const ldw01Token = typeof env?.BRIDGE_CLIENT_TOKEN === "string" ? env.BRIDGE_CLIENT_TOKEN : "";
  const dragonflyToken = typeof env?.DRAGONFLY_BRIDGE_CLIENT_TOKEN === "string" ? env.DRAGONFLY_BRIDGE_CLIENT_TOKEN : "";
  const baseValid = Boolean(siteToken && ldw01Token && siteToken !== ldw01Token);
  const dragonflyCollision = Boolean(
    dragonflyToken && (dragonflyToken === siteToken || dragonflyToken === ldw01Token)
  );
  return { siteToken, ldw01Token, dragonflyToken, baseValid, dragonflyCollision };
}

function readBearer(headers) {
  const authHeader = headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return "";
  }
  return authHeader.slice("Bearer ".length);
}

function readSingleBridgeId(url) {
  const values = url.searchParams.getAll("bridgeId");
  if (values.length !== 1) {
    return null;
  }
  return values[0];
}

function hasOnlyBridgeIdQuery(url, expectedBridgeId) {
  const keys = [...url.searchParams.keys()];
  return keys.length === 1 && keys[0] === "bridgeId" && readSingleBridgeId(url) === expectedBridgeId;
}

async function forwardToDragonflyObject(env, path, method, body, sourceRequest) {
  const binding = env?.DRAGONFLY_BRIDGE_RELAY;
  if (!binding || typeof binding.idFromName !== "function" || typeof binding.get !== "function") {
    return jsonResponse({ error: "Durable Object binding DRAGONFLY_BRIDGE_RELAY is missing." }, 500);
  }

  const id = binding.idFromName(DRAGONFLY_BRIDGE_ID);
  const stub = binding.get(id);
  const headers = new Headers();
  if (sourceRequest) {
    for (const name of ["Upgrade", "X-LDW-Protocol-Version", "X-LDW-Bridge-Runtime", "X-LDW-Bridge-Version"]) {
      const value = sourceRequest.headers.get(name);
      if (value) {
        headers.set(name, value);
      }
    }
  } else {
    headers.set("content-type", "application/json");
  }

  const init = { method, headers };
  if (body !== null && body !== undefined) {
    init.body = JSON.stringify(body);
  }

  return stub.fetch(new Request(`https://relay.internal${path}`, init));
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function jsonResponse(payload, status) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}
