# REDRIX GitHub workflow-source evidence read adapter — source-only

Status: **DRAFT / DATA_ONLY / NO PROTECTED ISSUER / NO LIVE JIT**.

Governing issue [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), previous accepted DATA_ONLY source fixture PR #318, proposed non-authorizing A4 RFC PR #315, Windows #186/#269, held CI7 recovery #264. This file is not an authorization or privileged deployment plan.

## Why this exists

An approved JIT run requires an independently protected workflow source commit, ref and blob, not a caller \`HeadSha\` equal to a queued GitHub run's SHA. Current production \`ci-dispatch/Invoke-DragonflyCanaryProduction.ps1\` accepts the caller SHA; current accepted \`Dispatch.psm1:Invoke-Ci10Read\` allows \`actions/\` and \`contents/\` only, and **does not** permit \`git/ref/\`. Changing that protected read allowlist, or making an arbitrary writable caller generate a new approved source pin, is not authorized by this PR.

This additive Python collector consumes only normalized GitHub REST GET shapes via a test-supplied callback. It emits no credentials, payload, decoded workflow content, network, writes or shell. It reads **exactly four** fixed path kinds per snapshot, twice: \`git/ref/heads/main\`; the one workflow file contents at an exact 40-hex commit; exact one run ID; and exact attempt-scoped jobs. Inputs are bounded numeric run/attempt/job IDs. The branch is fixed \`refs/heads/main\` for the synthetic fixture; **this is not an accepted runtime dispatch ref or release pin**.

The contents read independently recomputes Git's 40-hex blob SHA1 over the returned base64 bytes and checks the declared size/blob ID, rather than merely trusting a contents response's \`sha\`. Candidate provenance is still untrusted; ref resolution and run/job payloads are **not attested as authenticated** by the injected reader. The collector delegates tuple identity and drift checks to the merged \`tools/dragonfly_workflow_source_admission.py\`. Positive result remains \`SOURCE_TUPLE_CONSISTENT_DATA_ONLY\` with \`jit_authorized=false\`, \`provider_write_authorized=false\`. Incomplete/unknown/provider errors return closed HOLD without echoing raw inputs or exceptions.

Official endpoint semantics: [Git references GET](https://docs.github.com/en/rest/git/refs), [repository contents GET](https://docs.github.com/en/rest/repos/contents), [workflow dispatch branch/ref semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

## Do not use for live admission

This does **not** provide signed immutable LDW01 issuer generation, trusted provider read binding, authenticated accounts/permissions, a truly atomic ref+run view, accepted read allowlist expansion, integration with production JIT POST, protected release publication, sudo/root diagnostics, or CI7 VM cleanup. In particular \`SOURCE_TUPLE_CONSISTENT_DATA_ONLY\` must not be treated as approval to create credentials.

## Next implementation gate

After independent source acceptance of this fixture and separate explicit owner/product/security selection of the precise RFC risk scope:

1. Independently reviewed LDW01 protected trusted issuer contract pins exact approved commit, workflow blob and ref to an immutable release generation. Retain source author separation, refusal on unavailable active generation, no self-signed caller input.
2. A distinct, bounded provider-only GET adapter for the missing \`git/ref\` route and exact Contents/run/attempt/job responses, under the accepted protected Windows trust boundary. No broad API paths or management tokens on REDRIX.
3. Reviewed controller change must fail **before any** \`generate-jitconfig\` POST if issuer, provider readback, ref movement, job/head/labels or generation identity is missing/changed. Remove caller \`HeadSha\` authority; preserve job locks, #10 invariants and #96 10,240 MiB reserve.
4. Exact-head hosted security and independent H0/M0, protected issuer promotion/installer owner gate #186/#269, real readback, and only then already conditionally authorized one-shot secretless Gate B with provider-positive success/full teardown.

No new spend, provider mutation, QEMU/VM/runner, privileged host action, API credentials or memory-policy change.
