# CI7 PR777 recovery decision contract

Status: **DESIGN ONLY / NOT AUTHORIZATION / NOT A RECOVERY.**

This note freezes a fail-closed decision table for infrastructure-tools #264. It does not change `ci-runner/Invoke-IsolatedRunner.ps1`, the dispatcher, a protected install, a runner, a VM, a disk, a seed, or a GitHub workflow. No live `Recover`, `Cleanup`, `Discover`, `Once`, cancel, or delete is allowed by this document.

Parent issues: #10 and #92. Owning issue: #264. Deployed immutable release under discussion: `4129a3b87b0fbea95d40265fae1ec327d205660e`. The original nested exception is **unknown**. Exact GitHub runner registration, labels, and busy state are **unverified**.

## Incident that must not be cancelled

Business-operations run `42462196528` attempt 1, job `128673684689`, remains the queued unassigned job for open PR #777 at frozen head `eb84ba430a358f2776ef92f1a751e38d7a92d50e`. It is not proved stale. It is not a job PASS.

The deployed `Mode Cleanup` path (`Invoke-IsolatedRunner.ps1` lines 149–180 at that release) and the failure catch (lines 274–292) cancel a workflow whose job is not `completed`. That includes this still-valid queued job. That cancellation is **disallowed** for this incident. A stopped guest plus an owned manifest is not permission to delete the guest or to remove its runner registration.

## Separation

Two actions stay separate:

1. **Local residue.** Exact owned guest, one attached disk, and one seed, identified by VMId, Notes, and the run directory. A future accepted source change may remove only that tuple. It must not cancel the provider run.
2. **Provider cancellation.** A future accepted policy may cancel a run only after a fresh proof that the job is not the current valid job. Missing, queued, or unassigned is not that proof. Runner deletion and credential material follow the same gate and are not a side effect of local disk cleanup.

This design does not authorize either action.

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
- Runner: registration id, name, labels, busy. `UNVERIFIED` if the read cannot show them.
- Locks: this run's `controller.lock`, and the controller global lock. Held by this owner, held by a peer, or uncertain.
- Stale proof: positive only when the job is completed or the PR head has moved away from the head that queued this attempt. Otherwise `NOT_PROVED`.
- Cancellation policy: `NOT_APPROVED` unless a later owner and security decision names this run.

## Decision table

| # | Phase | Guest | Owned tuple | Job | PR head | Runner | Lock | Stale proof | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `Running` | `Off` | exact | queued, unassigned, this attempt | current open head | unverified | not re-proved | not proved | `HOLD_PRESERVE_JOB` |
| 1 | `Running` | `Off` | exact | queued or unassigned | current | any, including idle | this owner | not proved | `HOLD_PRESERVE_JOB` |
| 2 | `Running` | `Running` | exact | queued or in progress | current | busy or unverified | this owner or uncertain | not proved | `HOLD` |
| 3 | any | any | mismatch of VMId, Notes, disk, seed, or run directory | any | any | any | any | any | `HOLD` |
| 4 | any | any | exact | API outage, missing job, or race between reads | any | any | any | any | `HOLD` |
| 5 | any | any | exact | assigned or in progress | current or moved | busy | peer or global lock held | any | `HOLD` |
| 6 | `cleanup-failed` recorded | `Off` | exact | queued, this attempt | current | unverified or present | uncertain | not proved | `HOLD_PRESERVE_JOB` |
| 7 | any | `Off` | exact | completed | any | absent | free | proved by completion | `HOLD` until a later accepted local-cleanup slice |
| 8 | any | `Off` | exact | queued | head moved or PR closed | absent | free | proved by supersession | `HOLD` until a later accepted cancellation slice |
| 9 | any | missing and disk missing | already absent | any | any | any | free | any | `HOLD` if job still queued; do not call cancel to "finish" idempotency |
| 10 | any other combination | | | | | | | | `HOLD` |

Row 0 is this incident. `Cleanup` and the failure catch are the wrong tools for row 0 because both cancel a non-completed job.

## What each result means

- `HOLD` — read again later. No provider write, no Hyper-V change, no runner delete, no lock write.
- `HOLD_PRESERVE_JOB` — same as `HOLD`, plus the queued job must remain. Local residue also stays. Repeating the decision is idempotent: the same evidence yields the same hold.
- A later `LOCAL_CLEANUP_CANDIDATE` is not a result of this contract. It would require a reviewed source change that deletes only the proved VM, disk, and seed and does not call cancel.
- A later `CANCEL_CANDIDATE` is not a result of this contract. It would require a separate owner cancellation decision after positive stale proof. It must not run in the same step as an uncertain disk delete.

`INTERRUPTED_CLEANUP=PASS` from today's script is not a success result for a still-queued job.

## Idempotency

- Re-reading row 0 does not cancel, delete, or deregister.
- A second `Cleanup` against this run is not idempotent. The script treats a non-completed job as something to cancel.
- If resources are already gone and the job is still queued, the only idempotent result is another hold. Do not cancel to make the controller exit 0.
- Provider assignment can change between two reads. If the two reads disagree, the result is row 4 `HOLD`.

## Downstream slices

These slices are not authorized by this pull request.

1. Source only, after this design is reviewed: in `Invoke-IsolatedRunner.ps1`, split exact local VM, disk, and seed removal from `Invoke-Ci7Api .../cancel` in both `Mode Cleanup` and the failure catch. Default for a queued current job is `CLEANUP_CANCEL_REFUSED`. Keep `PHYSICAL` paths and #10 gates unchanged.
2. Tests only, same later change: queued current job is not cancelled; proved completed or superseded job is the only cancel fixture; mismatched VMId, Notes, disk, or seed holds; runner missing, busy, or wrong label holds; peer lock and global lock hold; provider outage holds; partial delete holds and keeps the manifest; repeated decision stays hold. No secret or raw stderr in fixtures.
3. Persist one primary and one secondary code from the lists above. Do not reconstruct the original exception from discarded child stdout.
4. Gates for that later source pull request: exact-head CI7 and Host Agent tests, isolated Secret Scan, CodeQL, and an influence-clean H0/M0 review. Then a protected install of a named release, readback, and rollback. Not an ambient checkout.
5. Only after those gates, and still not by this document: one owner-controlled transaction for the proved owned tuple, with a fresh provider read before any cancellation question. `Discover` and `Once` stay a separate later decision for the oldest still-valid queued job.

## Non-authorization

This pull request performs no mutation. It does not authorize Recover, Cleanup, Cancel, Once, runner removal, disk removal, or a second controller. The original exception remains `UNKNOWN_PRIMARY`. Runner registration remains unverified. Row 0 stays `HOLD_PRESERVE_JOB`.
