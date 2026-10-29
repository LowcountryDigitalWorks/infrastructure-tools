# Dragonfly JIT canary integration

Issue: `#132` (`DRAGONFLY-JIT-CANARY-001`). This slice is source-only until independent exact-head review and a later explicit one-canary runtime gate.

## Authority split

LDW01 / `#10` remains the only GitHub queue, exact-job re-read, selection, registration, provider-monitoring, and cleanup authority. REDRIX never receives a PAT, GitHub App/OAuth credential, `gh` session, queue poller, or workflow selector. The short-lived one-job bootstrap is generated on LDW01 only after exact queued-job re-read, carried only in `opaque_bootstrap`, and streamed over the accepted `#115` forced-command private SSH transport. `#98` Operations Bridge credentials are never accepted as JIT/bootstrap authority.

## Closed canary profile

Repository `LowcountryDigitalWorks/infrastructure-tools`; workflow `.github/workflows/dragonfly-jit-canary.yml`; event `workflow_dispatch`; job `dragonfly-canary`; static labels `self-hosted`, `Linux`, `X64`, `dragonfly`, `jit`, `ldw-ephemeral`, `synthetic-only`; dynamic label `dragonfly-run-<run_id>`; capsule TTL 240 seconds. The workflow has one intended job, no deploy/publish/write action, and no repository/environment/organization secret reference.

The run-scoped label is required in both the queued job and generated ephemeral runner registration so a runner minted for one run cannot match a different queued canary.

## REDRIX executor boundary

`canary_executor.py` runs only after the fixed SSH sentinel, closed handoff validation, TTL/job/head/label revalidation, and durable one-time replay claim. It then requires local `AVAILABLE` state, reuses the pinned Dragonfly base/admission/guest lock, and creates one owned disposable guest. Plaintext host-side `user-data` is deleted immediately after NoCloud seed creation. After guest exit, seed, overlay, pidfile, manifest, and run directory are removed via the accepted owned cleanup path and host state returns to `STOPPED`.

The guest disables SSH, carries no inherited authorized keys, blocks inbound traffic and private/metadata address space, downloads one pinned Actions runner archive by HTTPS, verifies its SHA-256, starts one non-root ephemeral listener, and powers off when that listener exits.

## Failure and rollback

Invalid/expired/forged/replayed capsules fail before executor launch. Host-not-available/admission/tool failures launch no guest. A post-create failure terminates an owned QEMU process before cleanup. Confirmed cleanup returns `STOPPED`; uncertain cleanup leaves `HOLD` and forbids blind retry. Provider-side registration cleanup remains LDW01/#10 responsibility using the exact returned runner ID/name; REDRIX never deletes GitHub registrations itself.

Source acceptance does not authorize a live bootstrap, REDRIX runner registration, QEMU canary, workflow routing change, recurrence, private/customer/regulated workload, or spend.
