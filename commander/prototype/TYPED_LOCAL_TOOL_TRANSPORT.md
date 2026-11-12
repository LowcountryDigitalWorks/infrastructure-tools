# Typed local tool transport (Commander #209 Gate B→E preflight)

**SOURCE ONLY / DRAFT** — not a ChatGPT connector, MCP public listener or admin broker.

## Purpose

Move beyond `model_tool_transport_proof.py` fixed `MODEL_OUTPUT_BLOCKED` projection for **untrusted** model payloads while keeping default-deny at the model boundary. Trusted work uses an in-process **loopback harness** with a closed tool catalog.

## Trusted path

1. Owner constructs `LocalToolLoopbackHarness` locally with disposable Ed25519 issuer key, fixed `OwnerPolicy`, and fixture root.
2. Harness issues grant via `SessionIssuer` (never from tool arguments).
3. `TypedLocalToolDispatcher` maps tools: `hosts_list`, `session_open`, `session_close`, `fs_read`, `fs_write`, `run_fixed_canary`, `process_read`.
4. Identity fields (`operator`, `host`, `grant`, shell/path) in tool arguments → `IDENTITY_INJECTION_REFUSED`.
5. File/process operations delegate to existing `LocalUserModeProbe` (+ optional `HostSessionJournal` binding).

## Untrusted path

- `model_tool_result` / `model_typed_tool_call` → fixed blocked projection unchanged.
- No model-supplied principal, signed approval text or arbitrary command strings.

## Not implemented (honest blockers)

- Gate C–F protected owner enrollment, FULL_ADMIN reach, public network transport, ChatGPT plugin install, UAC/root/Hyper-V, Admin Broker (#52) changes.
- `process_read` returns bounded preview of last fixed canary only (not arbitrary process tree).

## Proof

```bash
python -m pip install -r commander/prototype/requirements.txt
python -m unittest discover -s commander/prototype -p 'test_*.py' -v
python -c "from commander.prototype.local_tool_loopback_harness import run_typed_local_canary; import json; print(json.dumps(run_typed_local_canary()))"
```

(Disposable keys/fixtures only; run from repo root with `PYTHONPATH` or as module path used in CI.)
