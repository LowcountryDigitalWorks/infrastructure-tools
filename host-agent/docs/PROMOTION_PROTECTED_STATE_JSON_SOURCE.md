# ADMIN-BROKER-PROMOTION-001 — protected-state JSON **proposal / source-only**

Owning authority: `infrastructure-tools#186`, accepted Gate A revision 2; parent `#52`, consumer `#139`. **Draft implementation contribution by GM Status08; not integrated or accepted.**

## Narrow purpose

`PromotionProtectedStateJson.Parse(byte[]?)` is a **pure, closed-schema, non-authorizing** decoder for a *synthetic representation* of the future `%ProgramData%/LDW/PrivilegedControl/state/promotion-control.json` contents.

The caller supplies bytes; therefore these bytes are **untrusted**. Parsing cannot prove protected location, ACL/owner/reparse, authenticated file read, source acceptance, 165-W authority, timestamp freshness, atomicity, administrator identity, or any right to promote a package. A successful schema decode is only `DATA_ONLY_PARSED_NOT_AUTHORIZED`; the separate pure two-snapshot comparison returns only `DATA_ONLY_STATE_STABLE_NOT_AUTHORIZED` when unchanged and enabled. Neither result grants privilege. Errors return `BLOCKED` without raw JSON or exception content. This parser must never become an authentication predicate or a generic owner-writable config loader.

## Proposed v1 JSON (not an accepted installed format)

Exactly seven case-sensitive fields:

- `schema_version`: integer `1`.
- `promotion_enabled`: actual JSON boolean; not a string.
- `control_generation`: positive signed Int64; security writer must enforce strictly increasing generations and durable persistence.
- `reason_code`: closed enum `NONE`, `INCIDENT_DISABLED`, `RECOVERY_HOLD`. `NONE` is valid only with `promotion_enabled=true`; disabled state requires a hold reason.
- `active_generation`: nonnegative signed Int64 strictly below Int64.MaxValue, so next-generation arithmetic cannot overflow in existing data preflight.
- `active_digest_sha256`: exactly 64 lower-case hexadecimal characters corresponding to a separately trusted active package.
- `last_change_id`: canonical lowercase nonzero GUID, issued by the separate *protected* state writer for correlation/readback; parsing alone does not authenticate it.

JSON objects may use ordinary property order and whitespace. Field names are compared *after JSON unescaping*, so semantically equivalent escaped keys are accepted: this is NOT an assertion of canonical byte-for-byte JSON encoding. A future trusted reader must independently bind accepted raw bytes and protected-file provenance. This schema rejects missing, duplicate, extra or differently cased decoded fields; type confusion; noncanonical numeric forms including -0, exponents, fractional values and leading zeros for generations; comments, trailing commas, UTF-8 BOM, malformed UTF-8, nonobject roots, noncanonical digest/ID, unknown state reasons, impossible generations and inputs over 4,096 bytes (exactly 4,096 is permitted when valid JSON). A private input snapshot is made before UTF-8/JSON parsing to avoid changing caller bytes between the two checks. The chosen schema/closed reason enum is a **candidate subject to #186 owner and independent review**, not an instruction to change accepted deployed state silently. Existing accepted V1 runtime remains untouched.

## Integration still required

The future reviewed, fixed, protected administrator launcher must independently:

1. Attest the fixed `%ProgramData%/LDW/PrivilegedControl/state` directory, parent ownership, ACL write/delete/replace permissions, reparse ancestry, and protected source/launcher identity **before reading** state.
2. Read bounded bytes under a race-safe held protected handle; reject absent/corrupt/moved state; never fall back to caller bytes. Enforce stable signed/typed publisher and package identities.
3. Compare the exact initial and immediately-before-atomic-swap protected state, including `last_change_id`, `control_generation`, `active_generation` and `active_digest_sha256` under the accepted #186 race/concurrency contract. The pure `PromotionProtectedStateJson.CheckStable(initial, beforeSwap)` models that comparison and includes the change ID that the *older* `PromotionProtectedState` record does not carry. Both outputs are DATA_ONLY and the future fixed privileged launcher still must keep protected handles/locks and independently re-read immediately before the swap; this helper cannot close a host TOCTOU race. Missing/corrupt/disabled state fails closed.
4. Independently authenticate the fixed 165-W GitHub server-returned Bot/ledger objects, exact reviewed package/catalog/CI/IR, protected stage and rollback before any promotion. A matching local JSON or hash is **not** authority.
5. Implement separate fixed emergency disable/recovery that does not depend on compromised 165-W and retains the explicit owner security decision for re-enable. Preserve narrow closed operation catalog, no arbitrary command/powershell/file/URL/environment surface.
6. Complete independent source review, guarded merge, protected owner-machine installed readback and fresh #139 A4/REDRIX/#10/provisioning gates before the single already-approved secretless JIT canary.

`PromotionDataPreflight.Check` already consumes the decoded `PromotionProtectedState` shape as *synthetic caller inputs* and returns `BLOCKED` for disabled/inconsistent state; its legacy state equality does NOT bind `last_change_id` by itself. This proposal adds an explicit pure stable-readback helper to compare that ID before any future privileged integration. **Deferred mandatory acceptance evidence:** independently accepted consumed authorization numeric/node ID, canonical authorization-content digest, bot login/id, creation timestamp, predecessor/active generation and digest must be persisted by the future stable protected launcher and proven crash/replay-safe per #186 Gate A L1/L2. The parser does not persist any state or authorization, implement recovery or wire into any privileged task.

## Synthetic tests

`PromotionProtectedStateJsonTests` runs through the existing .NET 10 Admin Broker test project via a module initializer with deterministic positive-data, emergency/recovery disabled-state, change-ID drift, stable readback, caller-byte snapshot, numeric encoding, boundary/BOM, and malformed/adversarial cases; **no** file, network, Windows API, installed broker, GitHub App, credential, runner, host or UAC invoked.

One can build/test from an exact disposable source checkout using:

```powershell
dotnet run --project host-agent/tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj --configuration Release --nologo
```

The broader existing Admin Broker test executable has a separately observed baseline `System.IO.IOException` on LDW01 even before this contribution. A new protected-state assertion marker does not mean the whole local suite succeeded unless the final process exit is actually zero; use exact-head hosted Host Agent validation and independent test triage.

**No extra spend. No host or provider changes. No new elevated operation. No direct GitHub runner/JIT.**
