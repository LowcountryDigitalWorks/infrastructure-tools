# REDRIX workflow source: non-authorizing tuple correlation fixture

**State: SOURCE-ONLY / DATA_ONLY / NO PROTECTED INSTALL / NO JIT POST / NO GATE B.**

Owner: [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139); governing proposed (not approved) [owner-trusted A4 RFC](REDRIX_OWNER_TRUSTED_A4_RFC.md). Separate Windows trust sources: #186, #269 and CI7 incident #264.

## Gap and scope

The accepted production controller accepts a caller-provided HeadSha and checks it against GitHub's reported run/job head. Agreement does **not** prove the workflow came from a separately reviewed and protected LDW01 issuer generation. GitHub dispatch accepts branch or tag refs, whose targets may move. Do not mint any JIT configuration while that source binding is missing.

This fixture implements the **data correlation and refusal portion only**, using in-memory normalized mock/provider-like snapshots. It does not read GitHub, verify credentials, authenticate provider responses, attest the immutable issuer, bind a protected generation to code, instrument the controller, or call a provider. Even its fully consistent synthetic positive result is **SOURCE_TUPLE_CONSISTENT_DATA_ONLY** with both \`jit_authorized=false\` and \`provider_write_authorized=false\`. It must not be imported into production as a passing security gate or treated as evidence that any physical machine or GitHub job is ready.

The candidate release record is deliberately an untrusted test argument, **not** proof of a real signed/pinned LDW01 release. Caller-supplied expected SHA is ignored for trust. There are no hardcoded current SHA values, approved future tags, or mutable acceptance manifests.

## Correlated identities

Input fixtures provide one proposed release generation with exact repository, source commit SHA, branch ref, workflow path/blob SHA and profile. Two independent snapshots of each ref target, workflow blob-at-commit, queued run identity and queued job identity are compared. The closed validator requires the fixed REDRIX synthetic workflow/profile, same approved SHA in ref, blob and run/job, exact nine labels, no assigned runner, and no movement between observations. Missing fields, wrong ref type, altered workflow at same path, forged head, unexpected labels, nonqueued state or changing run/job all HOLD.

The snapshot-pair comparison remains a **simulation**; a live issuer must guarantee the read origin and freshness itself, not trust caller-supplied JSON. This source neither changes the accepted 10,240 MiB Crostini gate nor claims A4/CI7 trust.

## Remaining independently gated implementation

1. Exact owning security/product acceptance of the RFC's narrow owner-trusted threat model. Compromised unrestricted-sudo user remains outside independent A4 attestation.
2. Separate immutable reviewed LDW01 source generation and protected issuer under #186/#269; pin approved workflow commit, branch/tag ref, blob, issuer and active generation. No caller-controlled manifest or self-promotion.
3. Provider-authenticated read of ref resolution and workflow blob at the approved commit, plus exact run/attempt/job/labels, and a **fresh immediately pre-mint** recheck. Reject any TOCTOU movement before generating credentials. Independently review tests for read errors, provider outages and release-generation drift.
4. Only after accepted source and protected installation, integrate an actual **fail-before-POST** check into the reviewed controller, verify it cannot be bypassed via the legacy caller-supplied HeadSha path, and rerun exact-head hosted/independent security validation.
5. Retain separate #96 memory, #139 A4 and one-shot owner-authorized Gate B, #10 controller/lock/queue, #264 cleanup gates and full teardown evidence. Nothing in this fixture consumes authorization.

Run offline regression:

\`\`\`sh
python3 -m unittest discover -s tests/dragonfly-canary-publication -p 'test_workflow_source_admission.py' -v
\`\`\`

The existing Dragonfly source-validation workflow includes the tests/dragonfly-canary-publication path and full unittest discovery. No production workflow or controller file is changed.
