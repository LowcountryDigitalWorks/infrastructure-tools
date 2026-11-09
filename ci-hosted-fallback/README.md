# ci-hosted-fallback

Source-only, fail-closed eligibility planner for **owner-approved included-only** GitHub-hosted fallback under [business-operations #552](https://github.com/LowcountryDigitalWorks/business-operations/issues/552) comment `6731519036`, with provider-positive billing evidence in comment `6731618313`.

This module **does not** dispatch, cancel, rerun, or modify workflows, runners, billing, or branch protection. It returns `execute: false` always.

## Trusted provenance boundary

Cost and billing fields are accepted only as **TRUSTED_ORCHESTRATOR_ATTESTATION** when
`billing_evidence_source` is exactly `GITHUB_ORG_ADMIN_READ` (authenticated admin read, not model output).

- **No model-writable tools** may populate billing attestation fields.
- Caller/model-supplied `billing_read_status=OK` or invented `included_compute_remaining_usd` values are **rejected** without trusted provenance.
- **No runtime admission** from this planner alone; a trusted upstream adapter must supply closed DTO values.

`provider_readback.py` is the host-side **GET-only** GitHub read adapter (fixed org `LowcountryDigitalWorks`, fixed BO docs-validation tuple). It uses the host `gh` binary without `shell=True`, redacts failures to fixed `readback_code` values, and never returns tokens, env paths, or raw API bodies. Runtime orchestrators must set `trusted_caller=LDW_HOST_GH_ADAPTER`; models must not populate billing fields.

## Scope

- Closed DTO: **exact key set only** (schema `1.1`); no extra fields (including free-text overrides).
- Workload class **`SECRETLESS_DETERMINISTIC_VALIDATION` only**
- One bound **workflow + profile + repository** triple (not independent allowlist unions)
- Positive PR/run/job IDs, `run_attempt >= 1`, 40-char lowercase non-zero `head_sha`
- Exact `bool` types for flag fields
- Protected Betterleaks / secret-scan / WQT / Royal / JIT workflows remain **HOLD_PROTECTED_WORKFLOW**

## Cost / budget planning (plan-only)

Two trusted plan routes (never `execute: true`):

1. **`HOSTED_CLEAN_ELIGIBLE`** — trusted admin read, `billing_read_status=OK`, finite `included_compute_remaining_usd >= bounded_required_cost`, with `0 < bounded_required_cost <= 2` USD.
2. **`HOSTED_CLEAN_PLAN_BUDGET_CAPPED`** — trusted admin read documents organization Actions **`$0` budget with `prevent_further_usage=true`** (provider hard stop). May apply when included remaining is unknown; **does not** prove private included minutes remain or that dispatch will succeed; only that PAYG overage should be hard-stopped per owner-verified org settings ([#552 comment 6731618313](https://github.com/LowcountryDigitalWorks/business-operations/issues/552#issuecomment-6731618313)).

Otherwise `HOLD_BILLING_UNKNOWN` / `HOLD_UNTRUSTED_BILLING` / `HOLD_BILLING_INSUFFICIENT`.

## Tests

```bash
python -m unittest discover -s ci-hosted-fallback -p 'test_*.py' -v
```

## Relationship to ci-dispatch

Disjoint from `ci-dispatch/` and `.github/workflows/`. Protected BO PR775/777 `LDW secret scan` jobs **must not** be planned for hosted fallback by this module.
