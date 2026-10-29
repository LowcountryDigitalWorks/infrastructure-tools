# Dragonfly JIT canary integration

Issue: `#132` (`DRAGONFLY-JIT-CANARY-001`). This slice is source-only until independent exact-head review and a later explicit one-canary runtime gate.

## Authority split

LDW01 / `#10` remains the only GitHub queue, exact-job re-read, selection, registration, provider-monitoring, and cleanup authority. REDRIX never receives a PAT, GitHub App/OAuth credential, `gh` session, queue poller, or workflow selector. The short-lived one-job bootstrap is generated on LDW01 only after exact queued-job re-read, carried only in `opaque_bootstrap`, and streamed over the accepted `#115` forced-command private SSH transport. `#98` Operations Bridge credentials are never accepted as JIT/bootstrap authority.

## Closed canary profile

Repository `LowcountryDigitalWorks/infrastructure-tools`; workflow `.github/workflows/dragonfly-jit-canary.yml`; event `workflow_dispatch`; job `dragonfly-canary`; static labels `self-hosted`, `Linux`, `X64`, `dragonfly`, `jit`, `ldw-ephemeral`, `synthetic-only`; dynamic labels `dragonfly-run-<run_id>` and `dragonfly-attempt-<attempt>`; capsule TTL 240 seconds. The workflow has one intended job, no deploy/publish/write action, no checkout, and no repository/environment/organization secret reference.

Both dynamic labels are required in the queued job and generated ephemeral runner registration. The run label prevents a runner minted for one run from matching another run, while the attempt label prevents a runner minted for one retry/attempt from matching another attempt of the same run.

## REDRIX executor boundary

`canary_executor.py` runs only after the fixed SSH sentinel, closed handoff validation, TTL/job/head/label revalidation, and durable one-time replay claim. It then requires local `AVAILABLE` state, reuses the pinned Dragonfly base/admission/guest lock, and creates one owned disposable guest. Plaintext host-side `user-data` is deleted immediately after NoCloud seed creation. After guest exit, seed, overlay, pidfile, manifest, and run directory are removed via the accepted owned cleanup path and host state returns to `STOPPED`.

The guest disables SSH, carries no inherited authorized keys, blocks inbound traffic and private/metadata address space, downloads one pinned Actions runner archive by HTTPS, verifies its SHA-256, starts one non-root ephemeral listener, and powers off when that listener exits.

GitHub's runner accepts JIT startup material through the runner `run` command's `--jitconfig` argument. This candidate therefore guarantees that the bootstrap is absent from LDW01/SSH/REDRIX-host argv, environment, durable logs, claim state, and sanitized evidence; the upstream-required argument exists only inside the disposable guest. That bounded exception is accepted only for this secretless/no-checkout canary candidate. It is not authority for private, candidate-code, customer, regulated, or stronger-security workloads.

The REDRIX result `guest_qemu_exit=PASS` means only that the disposable QEMU process exited cleanly; it does not assert that the GitHub workflow succeeded. Provider-positive assignment/start/terminal success remains authoritative only from LDW01/#10 GitHub reads.

## Failure and rollback

Invalid/expired/forged/replayed capsules fail before executor launch. Host-not-available/admission/tool failures launch no guest. A post-create failure attempts to terminate the owned QEMU process; destructive owned-run cleanup requires confirmed death. Confirmed cleanup returns `STOPPED`; uncertain termination retains the run directory, overlay, manifest and PID evidence in `HOLD`. Under the guest lock, only manifest-validated exact owned `user-data` and `seed.img` regular files are unlinked. The pinned controller accepts an intentionally absent seed during later manifest validation/recovery. Linux unlink removes the host pathname while QEMU may retain an open FD; it does not revoke guest memory/open files, remove the overlay, stop a process, or prove `STOPPED`. Unsafe ownership or unlink failure remains `HOLD` with sanitized reason `CANARY_SENSITIVE_CLEANUP_UNCERTAIN`; it never triggers broader cleanup.

LDW01/#10 remains provider cleanup authority. The existing protected dispatcher-root uncertainty marker gates both registration-POST uncertainty and final runner cleanup. Schema 2 records only phase, exact run/attempt/job/head/name, optional known runner ID and timestamp; legacy schema 1 registration markers remain reconcilable. Final cleanup writes the gate before DELETE/absence proof and clears it only after exact absence is proved. Any failure leaves the gate: ordinary Once refuses `DRAGONFLY_CANARY_RECONCILIATION_REQUIRED` before provider calls even if inventory later looks empty. Only explicit bounded reconciliation under the dispatcher lock may prove exact deletion/absence and clear it; a different runner ID/name/label identity is refused. A primary transport/provider error remains controlling if cleanup also fails, with sanitized cleanup uncertainty attached separately; upstream bodies and bootstrap values are not returned. Transport rejects the actual bootstrap value in either stdout or stderr, including failed-exit responses. REDRIX never deletes GitHub registrations itself.

Source acceptance does not authorize a live bootstrap, REDRIX runner registration, QEMU canary, workflow routing change, recurrence, private/customer/regulated workload, or spend.
