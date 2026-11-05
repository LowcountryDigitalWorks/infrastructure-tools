# ADMIN-BROKER-PROMOTION-001 — protected-state JSON **proposal / source-only**

Owning authority: `infrastructure-tools#186`, accepted Gate A revision 2; parent `#52`, consumer `#139`. **Draft implementation contribution by GM Status08; not integrated or accepted.**

## Narrow purpose

`PromotionProtectedStateJson.Parse(byte[]?)` is a **pure, closed-schema, non-authorizing** decoder for a *synthetic representation* of the future `%ProgramData%/LDW/PrivilegedControl/state/promotion-control.json` contents.

The caller supplies bytes; therefore these bytes are **untrusted**. Parsing cannot prove protected location, ACL/owner/reparse, authenticated file read, source acceptance, 165-W authority, timestamp freshness, atomicity, administrator identity, or any right to promote a package. The only positive classification is `DATA_ONLY_PARSED_NOT_AUTHORIZED`. Errors return `BLOCKED` without raw JSON or exception content. This parser must never become an authentication predicate or a generic owner-writable config loader.

## Proposed v1 JSON (not an accepted installed format)

Exactly seven case-sensitive fields:

- `schema_version`: integer `1`.
- `promotion_enabled`: actual JSON boolean; not a string.
- `control_generation`: positive signed Int64; security writer must enforce strictly increasing generations and durable persistence.
- `reason_code`: closed enum `NONE`, `INCIDENT_DISABLED`, `RECOVERY_HOLD`. `NONE` is valid only with `promotion_enabled=true`; disabled state requires a hold reason.
- `active_generation`: nonnegative signed Int64 strictly below Int64.MaxValue, so next-generation arithmetic cannot overflow in existing data preflight.
- `active_digest_sha256`: exactly 64 lower-case hexadecimal characters corresponding to a separately trusted active package.
- `last_change_id`: canonical lowercase nonzero GUID, issued by the separate *protected* state writer for correlation/readback; parsing alone does not authenticate it.

JSON objects may use ordinary property order and whitespace, but reject missing, duplicate, extra or differently cased fields, type confusion, comments, trailing commas, malformed UTF-8, nonobject roots, noncanonical digest/ID, unknown state reasons, impossible generations and inputs over 4,096 bytes. The chosen schema/closed reason enum is a **candidate subject to #186 owner and independent review**, not an instruction to change accepted deployed state silently. Existing accepted V1 runtime remains untouched.

## Integration still required

The future reviewed, fixed, protected administrator launcher must independently:

1. Attest the fixed `%ProgramData%/LDW/PrivilegedControl/state` directory, parent ownership, ACL write/delete/replace permissions, reparse ancestry, and protected source/launcher identity **before reading** state.
2. Read bounded bytes under a race-safe held protected handle; reject absent/corrupt/moved state; never fall back to caller bytes. Enforce stable signed/typed publisher and package identities.
3. Compare the exact initial and immediately-before-atomic-swap protected state, including `last_change_id`, `control_generation`, `active_generation` and `active_digest_sha256` under the accepted #186 race/concurrency contract. Missing/corrupt/disabled state fails closed.
4. Independently authenticate the fixed 165-W GitHub server-returned Bot/ledger objects, exact reviewed package/catalog/CI/IR, protected stage and rollback before any promotion. A matching local JSON or hash is **not** authority.
5. Implement separate fixed emergency disable/recovery that does not depend on compromised 165-W and retains the explicit owner security decision for re-enable. Preserve narrow closed operation catalog, no arbitrary command/powershell/file/URL/environment surface.
6. Complete independent source review, guarded merge, protected owner-machine installed readback and fresh #139 A4/REDRIX/#10/provisioning gates before the single already-approved secretless JIT canary.

`PromotionDataPreflight.Check` already consumes the decoded `PromotionProtectedState` shape as *synthetic caller inputs* and returns `BLOCKED` for disabled/inconsistent state. This contribution does not call that function in production or wire anything into the existing privileged task.

## Synthetic tests

`PromotionProtectedStateJsonTests` runs through the existing .NET 10 Admin Broker test project via a module initializer with deterministic positive-data, disabled-state and malformed/adversarial cases; **no** file, network, Windows API, installed broker, GitHub App, credential, runner, host or UAC invoked.

One can build/test from an exact disposable source checkout using:

```powershell
dotnet run --project host-agent/tests/LDW.AdminBroker.Tests/LDW.AdminBroker.Tests.csproj --configuration Release --nologo
```

The broader existing Admin Broker test executable has a separately observed baseline `System.IO.IOException` on LDW01 even before this contribution. A new protected-state assertion marker does not mean the whole local suite succeeded unless the final process exit is actually zero; use exact-head hosted Host Agent validation and independent test triage.

**No extra spend. No host or provider changes. No new elevated operation. No direct GitHub runner/JIT.**
