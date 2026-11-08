# Admin Broker reviewed-operation promotion: trust-root decision gate

**Status:** DRAFT architecture candidate; **NO PROMOTION AUTHORITY**.
**Owner:** [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), with [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52), [#176](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/176), [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), and [#185](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/185).
**Purpose:** isolate the smallest independently reviewable trust decision before writing any privileged `DRAGONFLY_V2_PUBLISH_REVIEWED` operation or protected promotion code.
**Cash/data boundary:** $0 incremental; no new secret, owner credential, customer data, system mutation, or provider write in this document.

## Current evidence and non-authority

1. The deployed V1 Admin Broker has one closed privileged operation, `ELEVATED_IDENTITY_PROOF`. The [#176 first live proof](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/176#issuecomment-6571074628) was accepted; [#52's newer correction](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52#issuecomment-6717819365) supersedes its older issue-body claim that proof is pending. The no-trigger protected task does not expose an arbitrary shell, installer or permission to add new operations.
2. [PR #235](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/235), [PR #239](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/239), and [PR #242](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/242) provide source-only protected-state/data-shape/negative-test foundations; `PromotionClosedOperationRequest.Validate` remains `DATA_ONLY_REQUEST_SHAPE_NOT_AUTHORIZED`.
3. [#186's November 8 challenge](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6718875792) returned **CHANGES_REQUIRED** for the authorization architecture. One read-only GitHub REST check observed `performed_via_github_app` metadata, including app ID `1144995` and slug `chatgpt-codex-connector`, on an existing app-authored comment. Presence of metadata does **not** prove authorization, irreversibility, independent acceptance, or issuer compromise resistance.
4. The owner has approved exactly one separate protected V2 publication and one secretless REDRIX Gate B canary in #139. Those approvals do **not** waive this trust gate, physical A4/process visibility, the REDRIX installed 2 GiB guest + 8 GiB reserve, #10 exact-job admission, or post-run cleanup. Neither approved action is consumed by this draft.
5. The proposed closed V2 operator is **publication only**, never elevated GitHub CLI/JIT mint, SSH, guest launch, or a generic script executor. Later Gate B must use its separately reviewed normal-user PowerShell 7 / trusted #10 path.

Live repository, device, provider, checks and review records override these historical observations.

## Trust boundaries and threat model

The normal-user owner session, its writable checkout, tools, environment/PATH, shell aliases, pipe client, request body, Codync/ChatGPT control channel and mutable Git refs are **untrusted inputs to privileged execution**. A valid hash of caller-selected bytes is *integrity evidence*, not authorization. A visible assistant review summary, a PR title, a commit reference selected by the caller, or an app-authored GitHub comment alone is not a protected trust root.

Adversaries to address before implementation:

- Malicious/compromised normal-user process fabricates request ID, replays prior receipts, races helpers, injects arguments/paths/environment, swaps a checkout, replaces a binary alias, or edits symlink/reparse ancestry.
- Compromised or coerced ChatGPT connector/issuer or GitHub account emits an app-authored but unauthorized ledger record; a model-generated assertion of independent review is not verification.
- A stale/edited/deleted GitHub issue comment, moved branch/head, force-push, recreated artifact, changed workflow/check, or later rejected package is presented as current authorization.
- GitHub/network becomes unavailable, contradictory, rate-limited or partitioned during authorization or update.
- Concurrent promotions, partial filesystem writes, crash after acceptance, conflicting generation, rollback to vulnerable package, or incomplete readback leave privilege policy ambiguous.
- Publicly signed code or GitHub-signed metadata is not necessarily eligible to run elevated; code signing proves a publisher identity, not a reviewed LDW operation.

Protected SYSTEM/Administrators-only roots, closed current registry, immutable installed worker, existing no-trigger task, fixed request ID and durable results remain the security boundary; never admit a new operation from a normal-user writable source.

## Candidate A: pinned GitHub App-authored, fixed-issue generation ledger

**Potential advantage:** the fixed repository is currently PUBLIC. A protected verifier could use an anonymous HTTPS GitHub REST GET to the exact pinned GitHub host, repository and issue/comment endpoint, without a bearer token or new secret, and validate server-returned metadata against an independently accepted issuer policy. TLS authenticates the GitHub server endpoint; it does **not** authenticate the API caller, authorize the comment contents, or prove independent issuer decision-making.

**Preconditions, all presently UNPROVEN:**

1. Establish that a *separately controlled* authority makes the allow/deny decision before the App can issue a promotion record. A normal user or model that can ask the same App to write an arbitrary "approved" comment must not be able to self-authorize promotion.
2. Pin the HTTPS host, fixed repository, issue, server-returned comment ID, GitHub App ID `1144995`, appropriate author/installation scope, immutable created/update evidence, canonical record schema, allowed closed operation ID, active generation and predecessor. Use the protected verifier's own fail-closed **server-authenticated TLS** GET against that exact public GitHub REST endpoint; validate response schema and exact returned App fields rather than relying on model or GitHub MCP summaries (which omit App metadata). Reject redirects to a new origin, TLS failure, missing/malformed/unexpected fields, rate limits, provider unavailability or contradictory evidence. The anonymous GET supplies **public source evidence only**, not authority for a privileged decision.
3. Check accepted exact package commit/tree/per-file digests, independent influence-clean review and exact-head mandatory security tests *as verified by the privileged policy*, not caller-provided assertion. Review and code author identity separation must be material.
4. Require protected local high-water generation, durable request nonce/replay ledger, atomic promotion, exact readback and controlled rollback semantics. Reject modified comments, unknown App/author/issuer, missing provider corroboration, stale generation and any repository or ledger mismatch.
5. Treat anonymous HTTPS GET of this public repository as the preferred **zero-new-credential retrieval hypothesis**, not a completed verifier design: demonstrate TLS trust, exact fixed endpoint, independently retrieved issuer/record evidence, freshness, protected monotonic state and complete denial cases. Never trust owner-supplied HTTP bytes, tokens or local Git worktrees. If the repository/required data becomes private, a bearer token is genuinely required, or TLS/provider trust cannot be established, stop with **BLOCKED / NEW_AUTH_OR_TRUST_GATE**; neither an ambient credential nor a local Git checkout is a substitute.
6. Threat-test issuer compromise and emergency revoke/disable. One observed `performed_via_github_app` field is insufficient to complete items 1–6.

**Disposition:** CONDITIONAL / **NOT SELECTED**. Do not encode App ID as a magic authorization switch. The controlling open question is separation of issuer decision from the caller/agent channel.

## Candidate B: signed closed catalog or reviewed Actions attestation

**These are two distinct alternatives, not a combined mechanism.** A pinned offline verification key could validate a **signed closed-operation catalog** authorized by its separately controlled signer. By contrast, GitHub Actions OIDC/artifact attestation could establish **specified workflow/build provenance** under an accepted issuer and predicate, but not by itself authorize privileged operation semantics or prove independent review.

**Preconditions:** D0 must choose **one** B alternative. For the signed-catalog path, freeze signer identity, pinned verification public key, independently controlled private-key custody, revocation/rotation, generation anti-rollback and exact closed operation allowlist. For the Actions-attestation path, freeze exact issuer/workflow/repository/ref and build predicate, signing/verification chain, artifact digest and review evidence validation, entitlement and retention assumptions, replay/rollback refusal and revocation. Both require a protected first-install trust anchor and explicit independently verified acceptance of exact fixed operation semantics; neither may be a generic installer or accept caller-chosen manifests.

**Risks:** a signing key or service may be a **new owner approval/security credential**; Actions OIDC/attestations do not inherently establish independent human/agent review or a protected deployed verifier. Do not assume zero-cost availability or private-repo anonymous readback without checking.

**Disposition:** CONDITIONAL / **NOT SELECTED**. Escalate any actual new key/service/account/spend approval by exception; no key generation or attestation deployment is authorized by this draft.

## The first-install/bootstrap paradox

The already deployed V1 privileged registry only executes `ELEVATED_IDENTITY_PROOF`. Neither a new data-only request shape nor a GitHub ledger record can introduce a new privileged executable safely. Before a new fixed operation can run, a separately accepted protected promotion primitive or one-time trusted bootstrap must exist. A normal-user write to a protected path, owner-writable script, temporary broad SYSTEM updater or fallback to generic PowerShell is **not** an acceptable workaround.

The implementation design must explicitly identify *who can install the first verified immutable promotion verifier*, how that installer is reviewed/authorized, how the currently installed V1 worker and task/ACL remain unchanged or are transactionally replaced, and how failure reverts to exact V1 without becoming a generic privileged launcher. If an already installed trusted path cannot prove that chain, report `BOOTSTRAP_AUTHORITY_MISSING` rather than pretending a new task operation is live.

## Proposed validation vectors (future Gate A and source-only tests)

| Vector | Required result before privilege |
| --- | --- |
| Genuine server App metadata but issuer decision unverified | `ISSUER_AUTHORITY_UNVERIFIED` / HOLD |
| Wrong App/repo/issue/author/installation or untrusted REST response | HOLD |
| Edited/deleted comment, wrong created/updated, stale generation or predecessor | HOLD |
| App comment cites stale head, bad tree/blob/check, absent clean independent review | HOLD |
| Caller chooses path/ref/URL/SHA/argv/PowerShell/script/manifest | INPUT_REFUSED |
| Dirty or owner-writable Git checkout, unexpected alias, hook, reparse/symlink, changed publisher byte | PROVENANCE_MISMATCH |
| Wrong/expired signature/attestation, missing revocation/issuer proof | HOLD |
| Duplicate/replayed correlation ID or competing promotion | REPLAY_OR_CONCURRENCY_HOLD |
| Crash during staging, rename, readback or rollback | protected journal / HOLD; never silently re-execute |
| Provider timeout, unavailable/ambiguous account, key expiry or metadata mismatch | HOLD; no new privilege |
| Request for `DRAGONFLY_V2_PUBLISH_REVIEWED` before bootstrap | NOT_REGISTERED / no code executed |
| Existing `ELEVATED_IDENTITY_PROOF` after rejected candidate | unchanged; still limited to previously accepted proof |
| V2 publication after future accepted trust chain | exactly one fixed publish operation, V1 unchanged; **not** Gate B |
| A4/host reserve/#10 admission fails after publication | Gate B HOLD; zero runner/JIT/guest launch |

Tests must prove *refusals*, protected state consistency, retained audit/readback and no secret/material leakage. A hosted synthetic Windows task/ACL fixture is not evidence of installation on LDW01.

## Sequenced acceptance gates

- **D0 — authority choice:** independent security/architecture review of Candidate A versus **one explicitly selected B suboption**; freeze exact accepted decision issuer and independence proof, first-install bootstrap, protected read/verification endpoint or signature/workflow predicate, review acceptance, revocation/rollback policy and threat assumptions. For A, distinguish anonymous TLS server authentication from API-user authentication and prove issuer authorization separately. **Current: OPEN / CHANGES_REQUIRED**.
- **D1 — exact closed source:** only after D0, source PR for fixed `DRAGONFLY_V2_PUBLISH_REVIEWED` contract and immutable helper verifier; preserve V1 operation and closed task. Adversarial deterministic tests, mandatory source/security CI, influence-clean independent exact-head review.
- **D2 — protected synthetic promotion:** preapproved isolated Windows fixture, complete denial/atomicity/replay/rollback/receipt, no real host mutation.
- **D3 — LDW01 protected publication:** separate one-time #139 owner-authorized exact package/installed binary/ACL readback, A4 and source head gates; no elevated GitHub CLI.
- **D4 — REDRIX Gate B:** separately perform one manual-only, no-secrets exact-provider JIT canary **only if** all REDRIX #96 capacity/privileged visibility, protected #52/#186, #10 dispatch, #115 transport, and #139 cleanup gates PASS.

D0–D2 are not permission to run D3 or D4. All failure or uncertainty is HOLD, with no automatic privileged retry, runner fallback, memory loosening, host/root action, spend or credential broadening.

## Reviewer decision requested

Return `ACCEPT_ARCHITECTURE`, `CHANGES_REQUIRED` or `BLOCKED_TRUST_ROOT`, with an independent proof of the chosen issuer's decision authority and immutable host-verifiable package chain. In particular, either demonstrate the App issuance separation and authenticated protected readback required by A, or explicitly route the first-install/credential owner gate required by B. Do not claim this draft has selected or implemented either option.
