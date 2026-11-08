# CI7 PR777 recovery decision contract

Status: **DESIGN ONLY / NOT AUTHORIZATION / NOT A RECOVERY.**

This note freezes a fail-closed decision table for infrastructure-tools #264. It does not change `ci-runner/Invoke-IsolatedRunner.ps1`, the dispatcher, a protected install, a runner, a VM, a disk, a seed, or a GitHub workflow. No live `Recover`, `Cleanup`, `Discover`, `Once`, cancel, or delete is allowed by this document.

Parent issues: #10 and #92. Owning issue: #264. Deployed immutable release under discussion: `4129a3b87b0fbea95d40265fae1ec327d205660e`. The original nested exception remains `UNKNOWN_PRIMARY`. Controller locks and the volatile provider job assignment are still unverified. One later read-only correlation, recorded on #264 in comment `6720217512`, matched the local `RunnerId` and name hash to the unique provider `ci7` registration, confirmed exactly eight expected PR777 labels, and showed that one registration offline and nonbusy. Identifiers from that read stay private. That observation does not authorize cleanup.

## Incident that must not be cancelled

Business-operations run `42462196528` attempt 1, job `128673684689`, remains the queued unassigned job for open PR #777 at frozen head `eb84ba430a358f2776ef92f1a751e38d7a92d50e`. It is not proved stale. It is not a job PASS.

The deployed `Mode Cleanup` path (`Invoke-IsolatedRunner.ps1` lines 149–180 at that release) and the failure catch (lines 274–292) cancel a workflow whose job is not `completed`. That includes this still-valid queued job. That cancellation is **disallowed** for this incident. A stopped guest plus an owned manifest is not permission to delete the guest or to remove its runner registration.

## Three separately gated operations

These are not one cleanup:

1. **Provider-run cancellation.** Allowed only after the pull request head has changed or the pull request has closed, and only under an exact accepted cancellation policy. A job `completed` state is terminal. It is not itself a stale-cancellation proof. Do not call Cancel on a completed job. A terminal status is not a security PASS.
2. **Exact JIT runner deregistration.** A separate later gate. The observed offline nonbusy registration is not permission to delete it. Do not print or persist registration secrets.
3. **Local guest removal.** Exact owned VM, one attached disk, and one seed, identified by VMId, Notes, and the run directory. A future accepted source change may remove only that tuple. It must not cancel the provider run and must not deregister the runner.

This design authorizes none of the three.

## Closed reason codes

Primary and secondary codes are a closed set. Persist the code only. Do not persist raw stdout, stderr, exception text, tokens, or paths outside the owned run record.

Primary, exactly one:

- `UNKNOWN_PRIMARY` — current incident. Do not upgrade this to a more specific code.
- `GUEST_STOPPED_BEFORE_JOB_COMPLETION` — candidate shape only. Not proved for this incident.
- `BOUNDED_JOB_TIMEOUT`
- `BOOTSTRAP_FAILURE_REPORTED`
- `UNEXPECTED_JOB_ASSIGNMENT`
- `JOB_RUNNER_EVIDENCE_MISMATCH`
- `INTENDED_JOB_FAILED`
- `PROVIDER_READ_FAILED`

Secondary, exactly one:

- `NONE`
- `CLEANUP_UNCERTAIN_MANIFEST_RETAINED` — last proved evidence line for this incident.
- `CLEANUP_CANCEL_REFUSED` — future code refused to cancel because the job was still valid.
- `LOCAL_RESOURCE_REMOVAL_FAILED`
- `RUNNER_REMOVAL_UNCERTAIN`
- `PROVIDER_OUTAGE`

`CLEANUP_UNCERTAIN_MANIFEST_RETAINED` does not mean the guest is safe to delete and does not mean the job failed.

## Inputs the table requires

Every input is exact. Age alone is not staleness. A caller-chosen run or job id is not evidence.

- Local phase: `Running`, any other recorded phase, or missing.
- Last evidence line: `cleanup-failed` or not.
- Guest power: `Off`, `Running`, missing, or mismatched VMId.
- Owned tuple: exactly one `ci7-<32hex>` VM, one VHD, one DVD, Notes `CI-RUNNER-EPHEMERAL-001:<runId>`, paths equal to that run's `state.json`.
- Provider: run id, attempt, job id, status, conclusion, assignment, and the open PR head.
- Runner: registration id, name, labels, and busy. `OFFLINE_NONBUSY_EXACT` only when a fresh read shows one matching registration, the expected label set, and not busy. Otherwise `UNVERIFIED`. Do not copy those identifiers into this contract.
- Locks: this run's `controller.lock`, and the controller global lock. Held by this owner, held by a peer, or uncertain. A runner read does not prove either lock.
- Provider race: two fresh reads of the same job. If they disagree, or either read fails, the result is `HOLD`.
- Supersession proof: positive only when the pull request head has changed or the pull request is closed, and an exact accepted cancellation policy names that change. Job `completed` is not supersession. Otherwise `NOT_PROVED`.
- Cancellation policy: `NOT_APPROVED` unless a later owner and security decision names this run.

## Decision table

| # | Phase | Guest | Owned tuple | Job | PR head | Runner | Lock | Stale proof | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `Running` | `Off` | exact | queued, unassigned, this attempt | current open head | offline, nonbusy, exact registration | not re-proved | not proved | `HOLD_PRESERVE_JOB` |
| 1 | `Running` | `Off` | exact | queued or unassigned | current | any, including idle | this owner | not proved | `HOLD_PRESERVE_JOB` |
| 2 | `Running` | `Running` | exact | queued or in progress | current | busy or unverified | this owner or uncertain | not proved | `HOLD` |
| 3 | any | any | mismatch of VMId, Notes, disk, seed, or run directory | any | any | any | any | any | `HOLD` |
| 4 | any | any | exact | API outage, missing job, or race between reads | any | any | any | any | `HOLD` |
| 5 | any | any | exact | assigned or in progress | current or moved | busy | peer or global lock held | any | `HOLD` |
| 6 | `cleanup-failed` recorded | `Off` | exact | queued, this attempt | current | unverified or present | uncertain | not proved | `HOLD_PRESERVE_JOB` |
| 7 | any | `Off` | exact | completed | any | absent | free | not a cancellation proof | `HOLD`; do not call Cancel; local removal and runner deregistration stay separate later gates |
| 8 | any | `Off` | exact | queued | head moved or PR closed | absent | free | proved only with that PR change and an accepted policy | `HOLD` until that later cancellation gate; do not treat completion as this proof |
| 9 | any | missing and disk missing | already absent | any | any | any | free | any | `HOLD` if job still queued; do not call cancel to "finish" idempotency |
| 10 | any other combination | | | | | | | | `HOLD` |

Row 0 is this incident. `Cleanup` and the failure catch are the wrong tools for row 0 because both cancel a non-completed job.

## What each result means

- `HOLD` — read again later. No provider write, no Hyper-V change, no runner delete, no lock write.
- `HOLD_PRESERVE_JOB` — same as `HOLD`, plus the queued job must remain. Local residue also stays. Repeating the decision is idempotent: the same evidence yields the same hold.
- A later `LOCAL_CLEANUP_CANDIDATE` is not a result of this contract. It would require a reviewed source change that deletes only the proved VM, disk, and seed and does not call cancel.
- A later `CANCEL_CANDIDATE` is not a result of this contract. It would require a separate owner cancellation decision after the pull request head changes or the pull request closes, under an exact accepted policy. Job completion is not that decision. Do not call Cancel on a completed job. It must not run in the same step as disk removal or runner deregistration.

`INTERRUPTED_CLEANUP=PASS` from today's script is not a success result for a still-queued job.

## Idempotency

- Re-reading row 0 does not cancel, delete, or deregister.
- A second `Cleanup` against this run is not idempotent. The script treats a non-completed job as something to cancel.
- If resources are already gone and the job is still queued, the only idempotent result is another hold. Do not cancel to make the controller exit 0.
- Provider assignment can change between two reads. If the two reads disagree, the result is row 4 `HOLD`.

## Downstream slices

These slices are not authorized by this pull request.

1. Source only, after this design is reviewed: in `Invoke-IsolatedRunner.ps1`, split exact local VM, disk, and seed removal from `Invoke-Ci7Api .../cancel` in both `Mode Cleanup` and the failure catch. Default for a queued current job is `CLEANUP_CANCEL_REFUSED`. Keep `PHYSICAL` paths and #10 gates unchanged.
2. Tests only, same later change: a queued current job is not cancelled; a completed job is not cancelled and is not a PASS; cancellation is tested only for a changed or closed pull request under an accepted policy; mismatched VMId, Notes, disk, or seed holds; runner missing, busy, or wrong label holds; peer lock and global lock hold; a provider read race holds; partial delete holds and keeps the manifest; repeated decision stays hold. No secret or raw stderr in fixtures.
3. Persist one primary and one secondary code from the lists above. Do not reconstruct the original exception from discarded child stdout.
4. Gates for that later source pull request: exact-head CI7 and Host Agent tests, isolated Secret Scan, CodeQL, and an influence-clean H0/M0 review. Then a protected install of a named release, readback, and rollback. Not an ambient checkout.
5. Only after those gates, and still not by this document: one owner-controlled transaction for the proved owned tuple, with a fresh provider read before any cancellation question. `Discover` and `Once` stay a separate later decision for the oldest still-valid queued job.

## Non-authorization

This pull request performs no mutation. It does not authorize Recover, Cleanup, Cancel, Once, runner deregistration, disk removal, or a second controller. The original exception remains `UNKNOWN_PRIMARY`. Controller locks and the live provider assignment remain unverified. The observed offline nonbusy registration does not change row 0: it stays `HOLD_PRESERVE_JOB` because the deployed cleanup path would cancel a still-valid queued job.


## Proposed independent policy reconciliation for PR #267 (NOT acceptance)

The independently reviewed implementation PR #267 (head `32b8138b80b436823c3c301779821f39fb12563b`) currently has `CHANGES_REQUIRED H1/M2`. Its protection against cancellation is meaningful, but its completed-job path deletes the local VM/media before separately authorizing either local deletion or JIT runner deregistration. This is a **new recovery policy**, not a harmless source refactor. The following is a **candidate contract for independent review**, not authority to execute, install, or merge.

**P0 — no-destructive refusal.** Source changes may replace the deployed behavior that cancels valid queued jobs with a fail-closed refusal before **any** provider, VM, disk, seed, or runner mutation. Today's PR777 run `42462196528`/job `128673684689` remains `HOLD_PRESERVE_JOB`. Preserve exact state and failure evidence, no synthetic success, no second `Once`, and never cancel to make recovery appear complete.

**P1 — completed does not authorize cleanup.** Two provider reads reporting `completed` plus a terminal conclusion are eligibility *evidence only*, not permission to remove local resources or deregister a runner. Until an independently selected and accepted closed local-only operation exists, even a completed job with exact ownership returns `HOLD`. This corrects PR #267's disputed implicit completed-job cleanup.

**P2 — split three separately authorized operations.** A future `LOCAL_GUEST_REMOVE` may remove only the exact owned VM/VHD/DVD and must never cancel the GitHub run or remove its runner. A future `EXACT_RUNNER_DEREGISTER` needs independently accepted runner-identity/labels/busy checks and must not delete media or cancel the workflow. `EXACT_PROVIDER_CANCEL` is distinct, requiring positive PR-head change or closure plus an explicitly accepted run-specific cancellation policy; it never targets an already completed job. Do not automatically chain these three operations.

**P3 — identity and ownership before any future write.** Before *proposing* a local-only action, bind live PR head and attempt plus job `id`, `run_id`, `run_attempt`, `head_sha`, `name`, `runner_id`, `runner_name`, `status`, and `conclusion` across two complete reads. Missing, changed or unassigned completed-job runner identity => HOLD. Match the assigned runner ID/name to the protected state; match one GitHub registration with **exactly eight distinct expected labels** (no extras or duplicates) and `busy=false`. Match VMId and Notes, exactly one disk and DVD with state-bound paths and reparse-safe owned root. Prove both the per-run lock and global controller lock belong to the executing owner, not just that they happen to exist.

**P4 — race and credentials.** Immediately before any separately authorized operation, refresh provider job, PR head, runner registration and lock ownership. If the attempt, assignment, PR head, runner labels/busy state or lock changes, HOLD. Two consecutive REST reads are not an atomic provider lock. Persist only closed classifications, never raw token, runner credential, stdout, stderr, arbitrary exception, private path or customer data.

### Authorized source-only sequence under this *proposed* contract

1. First separate the **queue-preservation hotfix** from recovery: reject queued and unapproved completed jobs **without destructive effects** in both `Mode Cleanup` and failure catch. Add tests for zero provider/VM/runner writes on every refused state. Do not grant new cleanup rights.
2. Add the missing exact eight-label and job-assignment checks to the bounded preflight/unit tests. Test queued, completed-without-local-approval, changed attempt/PR head, absent/changed job runner assignment, duplicate/extra/missing labels, provider outage, ambiguous controller locks, VMId/Notes/media mismatch and partial provenance; all remain HOLD before any write.
3. Freeze a combined six-file controller candidate only after independent source acceptance. Do not edit the accepted `Dispatch.psm1` snapshot allowlist or `Test-ControllerSnapshots.ps1` to make a candidate authorize itself. #269 and #186 D0 must independently select an issuer, generation and protected first-install/rollback path.
4. Require mandatory **actual** Secret Scan, CodeQL, Windows/CI7 validation, influence-clean H0/M0 on the exact final candidate, and host-controlled immutable package installation/readback before considering a separately reviewed local cleanup transaction. Retry/download failures are not security PASS.

**No decision to authorize:** This addendum does not approve any of the three operations, controller promotion, change in protected host, current incident cleanup, cancellation, runner deregistration, or credential work. All present incident states still HOLD.
