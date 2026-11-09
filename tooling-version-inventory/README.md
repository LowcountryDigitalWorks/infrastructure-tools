# LDW tooling version inventory (Issue #282)

**Status:** SOURCE-ONLY DRAFT (`TOOL-VERSION-SENSOR-001`). Bounded one-shot local read for Watch release delta (#647); not Host Agent deployment (#554), not a daemon, not release-feed fetch.

## Purpose

Normal-user **offline** inventory for a **fixed allowlist** of owner tooling:

| `app_id` | Fixed probe (current user only) | Process image (running hint) |
|----------|----------------------------------|------------------------------|
| `orca` | `%LOCALAPPDATA%\Programs\orca\Orca.exe` | `Orca` |
| `codync` | `%LOCALAPPDATA%\Programs\codync-desktop\Codync.exe` | `Codync` |
| `cursor` | `%LOCALAPPDATA%\Programs\cursor\Cursor.exe` | `Cursor` |

No wildcard Program Files scan, no arbitrary paths, no elevation, no network, no app launch, no command-line capture.

## Output

Sanitized JSON (`schema_version` `ldw.tooling_version_inventory.v1`):

- `observed_at` (UTC)
- `classification`: `TOOL_VERSION_INVENTORY_ONLY`
- `disposition`: `INVENTORY_EVIDENCE_ONLY` (does not prove updater completion or Watch materiality)
- `apps[]`: `app_id`, `install_state` (`found` / `not_found` / `unverified` / `error`), PE versions when found, `authenticode_state`, `trusted_publisher_policy` (`PINNED_SIGNER_MATCH` / `EXPECTED_UNSIGNED` / `UNVERIFIED` only — no certificate subject, thumbprint, or path), `running_state` (`observed_name_in_owner_session` / `not_observed_in_owner_session` / `unknown`), `running_scope` (always `invoking_process_session` in v1 — invoking host process session only, not independent owner-desktop proof), `updater_state` (`in_progress_evidence` / `unknown` only; absent markers never prove idle)

Running-state notes: process-name hits never prove an authenticated app identity (binary path/exe is not correlated in v1). Positive `observed_name_in_owner_session` means at least one matching process **name** in the **invoking** session when that session is interactive (`SessionId &gt; 0`), not proof the owner desktop app is running elsewhere. When the sensor runs from session 0 or a non-interactive host context, `running_state` is `unknown` rather than `not_observed_in_owner_session`, because absence in the invoker's session cannot disprove owner-desktop GUI processes.

## Invocation (owner LDW01, post-review only unless ORCH directs pinned readback)

```powershell
powershell -NoProfile -File .\tooling-version-inventory\Get-LdwToolVersionInventory.ps1
powershell -NoProfile -File .\tooling-version-inventory\Get-LdwToolVersionInventory.ps1 -AppId orca
```

Allowed `-AppId`: `orca`, `codync`, `cursor`, or omit for all (fixed set only). No other parameters.

## Tests

```powershell
powershell -NoProfile -File .\tooling-version-inventory\tests\Test-LdwToolVersionInventoryContracts.ps1
```

Synthetic fixtures only on CI/author host; deterministic; no live machine requirement.

## Trust boundaries

- Authenticode `Valid` alone never implies vendor trust. Orca/Cursor require **reviewed pinned signer thumbprints** in source; any other signer remains `UNVERIFIED`.
- Install probe refuses reparse/symlink hops under the fixed current-user install tree (`INSTALL_IDENTITY_REFUSED`).

## Boundaries

- Does not read credentials, config, plugins, updater JSON bodies, or terminal/session content.
- Does not mutate install trees, publishers, or running processes.
- `unknown` is explicit when running/updater evidence is ambiguous (e.g. Codync host workers).
- Independent exact-head review + mandatory security scan before merge; no auto-deploy.
