# Admin broker source candidate

Status: initial contract and local secret-storage primitives for `LowcountryDigitalWorks/infrastructure-tools#52`. This is not a deployable or running broker.

## Implemented in this change

- Versioned request schema for the six operation names in #52. Unknown operations, properties, duplicate properties, mismatched fixed targets, oversized requests, and incorrectly typed inputs are rejected.
- Explicit owner SID matching policy that rejects broad Windows principals. Mutating Bot IDs, reviewed Host Agent component IDs, and reviewed release IDs must match machine-local allowlists supplied by a future host.
- Bounded audit-result record schema that permits only operation/target identifiers, outcome, a short result code, request ID, and completion time.
- A fixed-identity `CORSAIR_NEON_DATABASE_URL` vault that uses Windows current-user DPAPI, writes only ciphertext to a local file, supports presence/readback/removal, and accepts the value as a `SecureString` API input.
- Deterministic contract tests for all six operation schemas, unrecognized operations/fields, target mismatch, caller mismatch, allowlist mismatch, bounded audit records, and synthetic DPAPI store/readback/remove.

## Not implemented or proven by this candidate

- No listener, caller transport, dispatcher, operation handler, durable audit sink, replay protection, interactive local secret entry UI, or secret-to-child-process launcher exists yet.
- Codync bot CRUD has not been connected to the loopback API or proven against a disposable bot.
- Host Agent status/restart/repair is not connected to the existing Host Agent runtime or proven against any component.
- Secret storage is proven only with a synthetic value in the current Windows user's DPAPI context. Corsair/Neon connectivity, process-environment handoff, command-line/stdout/stderr/log exclusion, and rotation are unverified.
- No broker, helper, service, scheduled task, startup entry, or secret has been installed or created on LDW01.

This candidate must not be described as satisfying the #52 implementation or acceptance criteria until each missing transport/operation path is implemented, tested, and independently reviewed. Standing installation remains a separate gate and was not performed here.

## Contract test

From the repository root:

```powershell
dotnet run --project host-agent/tests/LDW.HostAgent.AdminBroker.Tests/LDW.HostAgent.AdminBroker.Tests.csproj -c Release
```
