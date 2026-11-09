# Admin Broker reviewed-operation promotion: trust-root decision gate

**Status:** DRAFT architecture candidate; **NO PROMOTION AUTHORITY**.
**Owner:** [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), with [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52), [#176](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/176), [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), and [#185](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/185).
**Purpose:** isolate the smallest independently reviewable trust decision before writing any privileged `DRAGONFLY_V2_PUBLISH_REVIEWED` operation or protected promotion code.
**Cash/data boundary:** $0 incremental; no new secret, owner credential, customer data, system mutation, or provider write in this document.

## Owner-selected Candidate C: one-time closed-verifier bootstrap

**Owner authorization:** [#186 comment 6734055516](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6734055516) authorizes one out-of-band install of a fixed verifier by Eddie under his existing owner-admin account. The owner explicitly prefers this bounded path over switching accounts or requiring a second GitHub reviewer.

This is a **single-owner trust model**. The environment approval is a deliberate owner acknowledgment, not independent review. If the dedicated `redrix-protected-publish` environment is used, the proposed controls are: Eddie-LowcountryDigitalWorks as the required reviewer; **Prevent self-review off**; administrator bypass disabled; deployment limited to the reviewed `main` branch. This setting does not make the owner an independent reviewer and does not authorize caller-selected bytes.

### Fixed bootstrap and installed invocation contract

The first install is one interactive owner-admin transaction on LDW01, after an exact-source review accepts the implementation and the owner receives its frozen commit, Git tree, bootstrap Git blob SHA-1, and bootstrap file SHA-256. The bootstrap is one self-contained PowerShell file with no module imports, dot-sourcing, child scripts, downloaded code, caller arguments, environment-controlled paths, or network/Git access. The owner downloads that exact file from the reviewed immutable commit, verifies SHA-256 in a normal-user PowerShell session, then uses a fixed documented elevated command that copies only that source file to a protected staging path under the existing %ProgramData%\\LDW root. The elevated command must validate the existing root owner/ACL/reparse ancestry before use, apply SYSTEM + local Administrators-only ACLs to staging, hash the protected copy against the literal reviewed SHA-256, and launch only that protected copy with zero arguments. It must never execute the user-writable download or checkout. If any check is unclear or mismatched, stop before launch. The exact command and expected readbacks must be included in the implementation PR before owner action.

The bootstrap installs a fixed closed verifier/worker and its exact operation registry under the protected %ProgramData%\\LDW root, then atomically switches the existing no-trigger Admin Broker task to the reviewed worker while preserving the accepted ELEVATED_IDENTITY_PROOF behavior. This task is not a poller and has no trigger. The fixed request channel accepts only the enumerated REDRIX publication operation and bounded data fields; it cannot accept a script, executable, path, ref, URL, hash, argument vector, environment, task definition, or caller-selected operation implementation. The existing V1 worker/task state is preserved for transaction rollback until full new-worker/task/readback succeeds; on any pre-commit failure, restore the original task and worker, verify the restored V1 identity, and return HOLD. If rollback cannot be positively verified, disable invocation and HOLD. The transaction has a durable one-time receipt and refuses replay; bootstrap artifacts and staging are retired after successful verification. This installs a fixed capability once; it does not permit later verifier replacement or self-update. Any changed verifier requires a new exact-source review and a separate owner decision.

The elevated publisher must not execute Git, inspect a checkout, fetch GitHub, use SSH, mint JIT credentials, or launch a guest. It consumes only the fixed package staged by the normal-user path, re-hashes the protected copy against literal package pins compiled into the reviewed verifier, validates the complete manifest and file set, and atomically publishes the immutable release beneath %ProgramData%\\LDW\\DragonflyCanaryAdjunct. It records bounded sanitized receipts with verifier/package identities, ACL and task identity, operation ID, and rollback/readback results. The established #115 forced-command transport is a separate normal-user handoff used only after publication to transfer the exact pinned package to REDRIX; verify the exact digest at both ends. It is never called from the elevated verifier, and no GitHub credential enters Crostini or the disposable guest. Any mismatch, stale source, unavailable or ambiguous provider, race, replay, partial write, rollback ambiguity, or incomplete readback returns HOLD.

If a GitHub Environment is later used for the separately scoped manual canary, it is only an owner acknowledgment for jobs that explicitly reference it. Prevent self-review must be off to permit Eddie to approve his own run; administrator bypass must be off. Branch restrictions limit eligible refs but do not bind the environment to a particular workflow file, so the approved workflow must be the only one allowed to reference that environment and this restriction must be reviewed against effective repository/org policy before creation. Do not create the environment until that wiring and the actual workflow/run actor are frozen. Leave copilot untouched.

The installed verifier may publish only the exact fixed REDRIX V2 package needed for the separately authorized one-shot canary. It cannot authorize A4 or bypass the independent #139 gates: current privileged process/FD proof, guest-visible 2 GiB + 8 GiB admission, exact #10 queue/job identity, single-use canary scope, and complete teardown.

This authorization covers **one bootstrap operation only**. It creates no scheduled task, recurrence, standing publisher, self-update path, new PAT/App/OAuth/private key, or reusable install authority. Any changed verifier or package requires a new exact-source review and a separate owner decision. The owner accepts the resulting single-person control risk; this design does not claim protection from compromise of the owner's GitHub/admin account or from a malicious owner action. A separate ChatGPT reviewer may provide author-excluded technical findings, but that review is evidence, not a distinct GitHub identity or approval.

**Status:** owner-selected architecture candidate; **D0 remains OPEN / CHANGES_REQUIRED** until the exact fixed artifact, install path, atomic rollback, and acceptance tests below are specified and independently challenged. This section does not authorize installation, source promotion, environment creation, V2 publication, A4 PASS, or canary dispatch.

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

The already deployed V1 privileged registry only executes `ELEVATED_IDENTITY_PROOF`. Neither a new data-only request shape nor a GitHub ledger record can introduce a new privileged executable safely. The owner has now authorized Candidate C's one-time out-of-band bootstrap, so the *identity of the initial trust authority* is decided: Eddie's owner-admin action. The **technical bootstrap remains unimplemented and unaccepted**.

The D0 design must freeze the identity-pinning method, fixed protected Windows path/ACL, fixed no-argument entrypoint, atomic install/rollback semantics, preserved V1 worker/task behavior, receipt/readback schema, and one-shot use. The D1 source PR must record and test the exact verifier/package bytes and actual commit/tree/blob/SHA-256 identities before any owner bootstrap action. The bootstrap itself must never run from a mutable owner-writable checkout as elevated code. It may not accept caller-selected paths, refs, URLs, hashes, commands, arguments, environments or package locations. A temporary SYSTEM updater, generic privileged installer, new scheduled poller, or generic PowerShell fallback remains rejected.

Until those details have exact source and an author-excluded design/source review, report `BOOTSTRAP_AUTHORITY_NOT_IMPLEMENTED`; the owner authorization alone is not an installed trust root.

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

- **D0 — Candidate C design freeze:** the owner selected a one-time owner-admin bootstrap and same-account owner acknowledgment. Before D1, an author-excluded architecture challenge must accept the exact first-install procedure, the method for pinning immutable package identity, fixed protected path/ACL, atomic replacement and exact rollback/readback, one-shot disable/retirement, and explicit single-owner threat assumptions. Candidate A and Candidate B remain unselected; no GitHub comment, GITHUB_TOKEN, or Actions attestation is an issuer. **Current: OPEN / CHANGES_REQUIRED**.
- **D1 — exact closed source:** only after D0, source PR for fixed `DRAGONFLY_V2_PUBLISH_REVIEWED` contract and immutable helper verifier; preserve V1 operation and closed task. Adversarial deterministic tests, mandatory source/security CI, influence-clean independent exact-head review.
- **D2 — protected synthetic promotion:** preapproved isolated Windows fixture, complete denial/atomicity/replay/rollback/receipt, no real host mutation.
- **D3 — LDW01 protected publication:** separate one-time #139 owner-authorized exact package/installed binary/ACL readback, A4 and source head gates; no elevated GitHub CLI.
- **D4 — REDRIX Gate B:** separately perform one manual-only, no-secrets exact-provider JIT canary **only if** all REDRIX #96 capacity/privileged visibility, protected #52/#186, #10 dispatch, #115 transport, and #139 cleanup gates PASS.

D0–D2 are not permission to run D3 or D4. All failure or uncertainty is HOLD, with no automatic privileged retry, runner fallback, memory loosening, host/root action, spend or credential broadening.

## Reviewer decision requested

Return `ACCEPT_ARCHITECTURE`, `CHANGES_REQUIRED` or `BLOCKED_TRUST_ROOT` for owner-selected Candidate C. Evaluate whether the exact one-time owner-admin bootstrap can create an adequately bounded trust anchor while preserving the existing V1 helper/task and avoiding arbitrary installer inputs, new credentials, recurring authority, and unsafe rollback. Evaluate it under the owner's explicit acceptance of single-person control; do not describe same-account self-approval as independent review or require a second GitHub account. If the design cannot satisfy the stated boundaries, identify the smallest remaining owner/security decision. Do not claim this draft has implemented or installed the verifier.
