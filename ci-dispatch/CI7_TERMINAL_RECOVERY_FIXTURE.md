# CI7 terminal-cancelled incident recovery — non-executing fixture

**Owning authority:** infrastructure-tools [#264](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/264), [#269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269), #10, plus accepted existing [CI7_PR777_RECOVERY_DECISION_CONTRACT.md](CI7_PR777_RECOVERY_DECISION_CONTRACT.md). **Status:** source-only diagnostic design, no live recovery authority. Incremental cost $0/included.

## Why

Original exact [GitHub run 42462196528](https://github.com/LowcountryDigitalWorks/business-operations/actions/runs/42462196528), job 128673684689, attempt 1, original PR777 head eb84ba430a358f2776ef92f1a751e38d7a92d50e, is now **completed/cancelled**. The unique LDW01 CI7 VM remains **Off** while exact protected state says **Running** and last evidence entry is **cleanup-failed**. The state-bound positive runner ID was absent from only the inspected **first page** of repository runner registrations. That does not prove comprehensive registration absence.

The latest bounded LDW01 read-only check found one regular per-run controller.lock **file**, one regular global control.lock **file**, and a matching historical immutable protected bundle manifest for commit 4129a3b87b0fbea95d40265fae1ec327d205660e (recorded SHA256 b9f5c910067e3cfa76b0ca0645c505c4a5b9c5e526c62ed4e5c6c9ce43a86c19). These file artifacts **do not prove exclusive lock ownership, attested active release generation, or an untamperable parent ACL**. See #264 comment 6865378951 for authoritative time-scoped evidence; this document is a source contract, not a duplicate runtime ledger.

## Fixture: synthetic input only

ci7_recovery_hold_fixture.py is **pure in-memory Python**. It has no CLI, I/O, GitHub calls, lock/file operations, Hyper-V/runner lifecycle methods or privilege. It accepts a closed exact-shape **synthetic, untrusted** evidence envelope to exercise the decision table. The code does not read or attest real device/provider data. It returns **HOLD_NO_ACTION** for every case, even when all hypothetical inputs are positive.

The source only adds this fixture, an independent 15-test standard-library unittest module, and a targeted invocation in existing CI control-plane validation. It **does not** modify the accepted controller's six ci-runner runtime files, Dispatch.psm1 snapshot allowlist, protected bundle publisher, verifier record, source code of PR267/PR268, or any deployed software.

Every result hard-codes the following flags to false:

- owner_approved_cleanup_authorized
- controller_release_authorized
- provider_cancel_authorized
- runner_deregister_authorized
- local_guest_remove_authorized
- jit_dispatch_authorized
- mutations_performed

Strict input validation rejects boolean/integer smuggling, unknown fields or scope, mismatched original provider identity, changing job attempt, impossible typed state or an unauthorized claim. It refuses even a valid queued/running/waiting job, terminal conclusion other than cancelled, local tuple mismatch, incomplete runner inventory/pagination, positive runner registration, unproven exclusive current controller lock handles, historical hash without active-generation identity, unsafe inherited parent ACL, or missing independent review and exact-transaction owner approval.

No input claims are promoted to trusted authority by this program. The first diagnostic HOLD on today's known facts is **HOLD_RUNNER_REGISTRATION_NOT_EXHAUSTIVE**; the subsequent still-unproven lock ownership, active generation, inherited ACL, and exact approved local-only recovery are independent holds, not waived by that first result.

## Actual critical-path order — no physical action yet

1. **Complete provider coverage:** authenticated exact runner-registration enumeration across all required pages/scope, and two same-generation reads of run/job/attempt/PR head. Never infer missing registration from one page, stale GitHub comments or age.
2. **Trust the operator:** independently verify actual exclusive controller lock handles/quiescence and the active protected version/generation. Lock files existing are insufficient. LDW ProgramData parent ACL inherited broad write remains under #186.
3. **Establish immutable source acceptance:** design/independently review #269 six-file exact controller candidate and new protected issuer, with authenticity, anti-rollback, operator authority, rollback and physical readback. No arbitrary source hash or owner-writable Git checkout can become privileged merely by being named; preserve existing ACCEPTED_CONTROLLER_CHANGED refusals.
4. **Split operations:** exact local guest/media removal, runner deregistration and provider cancellation are three **separate** explicit, reviewed transactions. Do not use legacy Cleanup/Recover that could cancel still-valid provider work. Source PR267/268 remain unaccepted and draft pending source trust and release gates.
5. **Protected real operation:** only if all independent security, provenance, owner, current provider, locks and full-resource identity gates pass, perform **one** bounded owner-controlled immutable release transaction and verify zero leftover owned artifacts. Never run it from this fixture or on the basis of synthetic facts.

## Validation

Run on a synthetic-only checkout (or automatically via existing CI control-plane validation):

    python -m unittest discover -s ci-dispatch/tests -p test_ci7_recovery_hold_fixture.py -v

15 unit tests assert refusal of queued/current work, terminal-but-not-cancelled outcomes, wrong provider identity, broken local VM/disk/seed tuple, incomplete/paginated runner inventory, present runner, fake lock ownership, historical manifest without active generation/parent ACL trust, unapproved operations, schema type smuggling, secret non-reflection, replay idempotency, and a fully positive synthetic envelope that **still cannot authorize any operation**.

Require independent author-excluded exact-head H0/M0 review plus hosted CI control-plane, Secret Scan and CodeQL SUCCESS before any guarded **source-only** merge. No source-only acceptance authorizes protected installation, VM cleanup, runner registration, provider cancellation, memory gate changes, REDRIX Gate B or incremental spend.
