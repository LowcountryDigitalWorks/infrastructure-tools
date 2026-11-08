# OfficePC HOST2 read-only inventory (Issue #86)

**Status:** SOURCE-ONLY DRAFT. Phase-1 measurement helper for when OfficePC is legitimately available to the owner for local read-only observation.

This is **not** host onboarding, enrollment, JIT admission, or LDW01/REDRIX evidence. Do **not** run this script on LDW01 and treat the output as OfficePC facts.

## Disposition

- `classification`: `INVENTORY_ONLY_NOT_ADMISSION`
- `disposition`: `INVENTORY_BLOCKED` until OfficePC enrollment and normal-use baseline are separately accepted (#86, business-operations resilience gates).
- `jit_authorized`, `officepc_enrolled`, `normal_use_baseline_verified`: always **false** in this source revision.
- `host_reserve_mib`: always **null** (no 6144 MiB or other reserve inherited from LDW01).
- `runtime_blocked`: **true** — no automated admission or runner actions from this artifact.

## Invocation (owner-local, when device is available)

From a **non-elevated** owner PowerShell session **on OfficePC** (not via remote desktop products as a measurement prerequisite), using the owner’s normal script execution policy (RemoteSigned or equivalent site policy — **do not** use `ExecutionPolicy Bypass`):

```powershell
# Pin exact infrastructure-tools commit after independent review merges this path.
powershell -NoProfile -File .\host-inventory\Get-OfficePcInventory.ps1 -SampleCount 3 -IntervalSeconds 1 -Output Json
```

Allowed parameters (fixed bounds only):

| Parameter | Range |
|-----------|--------|
| `-SampleCount` | 3–6 |
| `-IntervalSeconds` | 1–5 |
| `-Output` | `Json` only |

No installation, no elevation required for the script as authored, no network, no GitHub tokens, no registry mutation.

## Evidence retained

Save stdout JSON to a private operator location; attach SHA-256 of exact `Get-OfficePcInventory.ps1` blob and git HEAD to HW & VM ORCH07 / issue #86. Do not commit customer or host-private inventory to this public repository.

## Synthetic contract tests (CI-author / developer laptop)

```powershell
powershell -NoProfile -File .\host-inventory\tests\Test-OfficePcInventoryContracts.ps1
```

On PowerShell 7 (when installed), repeat the same command under `pwsh` for version coverage.

Tests use injected snapshots only; they do not call live CIM on the runner or developer host.

## Boundaries

- Does not modify Hyper-V, power policy, runners, or organization settings.
- Does not output serial numbers, MAC/IP, usernames, domain, HWIDs, private paths, or environment secrets.
- Missing or untrusted WMI/CIM data surfaces as **null** / **UNKNOWN** / **UNVERIFIED**, not fabricated zero.
- Distinct from `dragonfly-jit/` REDRIX capacity work (#96 / #192) and from `host-agent/` / `ci-dispatch/` deploy paths.

## Independent review

Merge only after influence-clean **H0/M0** source review on the exact PR HEAD. This README does not authorize owner execution before that review unless HW & VM ORCH07 explicitly directs a pinned readback.
