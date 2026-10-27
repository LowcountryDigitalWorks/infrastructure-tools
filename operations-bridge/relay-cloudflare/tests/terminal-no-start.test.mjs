import test from "node:test";
import assert from "node:assert/strict";
import {
  finalizeTerminal,
  InMemoryRelayRepository
} from "../src/relay.js";

const nowIso = "2026-10-27T20:00:10.000Z";
const startedAt = "2026-10-27T20:00:05.000Z";

function row() {
  return {
    dispatch_id: "12345678-1234-4234-9234-123456789abc",
    bridge_id: "ldw01-bridge",
    protocol_version: "1.0",
    operation: "browser.health",
    args_json: "{}",
    idempotency_key: "idem-no-start",
    correlation_id: "corr-no-start",
    issued_at: "2026-10-27T20:00:00.000Z",
    expires_at: "2026-10-27T20:04:00.000Z",
    lifecycle: "delivered",
    delivery_connection_id: "conn-1",
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
}

function payload(status, start = null) {
  return {
    type: "terminal",
    dispatchId: row().dispatch_id,
    idempotencyKey: row().idempotency_key,
    correlationId: row().correlation_id,
    bridgeRuntime: "ldw-operations-bridge",
    bridgeVersion: "1.0.0",
    operation: "browser.health",
    resultClass: status,
    status,
    startedAt: start,
    completedAt: nowIso,
    evidence: "synthetic terminal",
    payload: {}
  };
}

for (const status of ["BLOCKED", "STALE"]) {
  test(`no-start ${status} terminal is accepted without inventing execution start`, () => {
    const finalized = finalizeTerminal(row(), "conn-1", payload(status, null), nowIso);
    assert.equal(finalized.ok, true);
    assert.equal(finalized.result.terminalStatus, status);
    assert.equal(finalized.result.startedAt, null);
    assert.equal(finalized.result.bridgeRuntime, "ldw-operations-bridge");
    assert.equal(finalized.result.bridgeVersion, "1.0.0");
  });
}

test("no-start PASS terminal is rejected", () => {
  assert.deepEqual(
    finalizeTerminal(row(), "conn-1", payload("PASS", null), nowIso),
    { ok: false, error: "missing-started-at" }
  );
});

test("normal started PASS terminal remains accepted", () => {
  const finalized = finalizeTerminal(row(), "conn-1", payload("PASS", startedAt), nowIso);
  assert.equal(finalized.ok, true);
  assert.equal(finalized.result.terminalStatus, "PASS");
  assert.equal(finalized.result.startedAt, startedAt);
});

test("no-start terminal cannot bypass connection/correlation provenance", () => {
  const wrongConnection = finalizeTerminal(row(), "conn-other", payload("BLOCKED", null), nowIso);
  assert.deepEqual(wrongConnection, { ok: false, error: "missing-started-at" });

  const wrongCorrelationPayload = payload("STALE", null);
  wrongCorrelationPayload.correlationId = "corr-other";
  const wrongCorrelation = finalizeTerminal(row(), "conn-1", wrongCorrelationPayload, nowIso);
  assert.deepEqual(wrongCorrelation, { ok: false, error: "missing-started-at" });
});

test("no-start terminal still requires observed runtime and version", () => {
  const missingRuntime = payload("BLOCKED", null);
  missingRuntime.bridgeRuntime = null;
  assert.deepEqual(
    finalizeTerminal(row(), "conn-1", missingRuntime, nowIso),
    { ok: false, error: "missing-bridge-runtime" }
  );

  const missingVersion = payload("STALE", null);
  missingVersion.bridgeVersion = null;
  assert.deepEqual(
    finalizeTerminal(row(), "conn-1", missingVersion, nowIso),
    { ok: false, error: "missing-bridge-version" }
  );
});

test("repository preserves null started_at and exact idempotency boundary", () => {
  const repository = new InMemoryRelayRepository();
  repository.initialize();

  const dispatch = {
    protocolVersion: "1.0",
    dispatchId: row().dispatch_id,
    bridgeId: "ldw01-bridge",
    operation: "browser.health",
    issuedAt: "2026-10-27T20:00:00.000Z",
    expiresAt: "2026-10-27T20:04:00.000Z",
    idempotencyKey: row().idempotency_key,
    correlationId: row().correlation_id,
    args: {}
  };

  assert.equal(repository.acceptDispatch(dispatch, "2026-10-27T20:00:01.000Z").ok, true);
  repository.markDelivered(dispatch.dispatchId, "conn-1");

  const wrongIdempotency = payload("BLOCKED", null);
  wrongIdempotency.idempotencyKey = "wrong-idempotency";
  assert.deepEqual(
    repository.completeFromClient("conn-1", wrongIdempotency, nowIso),
    { ok: false, error: "idempotency-mismatch" }
  );
  assert.equal(repository.getDispatch(dispatch.dispatchId).terminal_status, null);

  const completed = repository.completeFromClient("conn-1", payload("BLOCKED", null), nowIso);
  assert.equal(completed.ok, true);
  const stored = repository.getDispatch(dispatch.dispatchId);
  assert.equal(stored.terminal_status, "BLOCKED");
  assert.equal(stored.started_at, null);
  assert.equal(stored.result_class, "BLOCKED");
});
