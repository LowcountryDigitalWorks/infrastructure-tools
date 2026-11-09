# ci-hosted-fallback

Source-only, fail-closed eligibility planner for **owner-approved included-only** GitHub-hosted fallback under [business-operations #552](https://github.com/LowcountryDigitalWorks/business-operations/issues/552) comment `6731519036`.

This module **does not** dispatch, cancel, rerun, or modify workflows, runners, billing, or branch protection. It returns `execute: false` always.

## Scope

- Workload class **`SECRETLESS_DETERMINISTIC_VALIDATION` only**
- Closed input DTO (no arbitrary URL, path, callback, or token fields)
- Source allowlisted workflow/profile/repository identities only
- Exact PR/run/job correlation and live queued attempt required
- Private capacity must be provider-positive blocked with **no** runner assigned and **no** duplicate active local/JIT job
- Data classification **`CLEAN_SECRETLESS`** only
- Standard hosted labels: `ubuntu-latest`, `windows-latest`
- Billing read **`OK`** with `included_compute_remaining >= bounded_required_cost` and `overage_allowed: false`
- Billing **`UNKNOWN`** or **`403`** ⇒ `HOLD_BILLING_UNKNOWN`

Never eligible: Betterleaks, isolated secret-scan, WQT, Royal, JIT validation, or other protected workflows (#10 / #92 / #264 residues).

Included compute headroom must come from an **authenticated GitHub billing read** supplied in the DTO; this planner does not call GitHub and does not assume static minute allowances.

## API

```python
from plan_fallback import plan_fallback

decision = plan_fallback(closed_request_dict)
# decision["execute"] is always False
# decision["recommended_route"] is HOSTED_CLEAN_ELIGIBLE or HOLD_*
```

## Tests

```bash
python -m unittest discover -s ci-hosted-fallback -p 'test_*.py' -v
```

## Relationship to ci-dispatch

Disjoint from `ci-dispatch/` and `.github/workflows/`. No runtime rollout in this PR. After independent review/merge, owning #552 lanes may admit **individual proven secretless deterministic workflows** to a separate hosted path under explicit gates.
