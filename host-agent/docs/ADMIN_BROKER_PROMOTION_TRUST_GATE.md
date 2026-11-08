# Admin Broker reviewed-operation promotion: trust-root decision gate

**Status:** DRAFT architecture candidate; **NO PROMOTION AUTHORITY**.
**Owner:** [infrastructure-tools #186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), with [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52), [#176](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/176), [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), and [#185](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/185).
**Purpose:** isolate the smallest independently reviewable trust decision before writing any privileged `DRAGONFLY_V2_PUBLISH_REVIEWED` operation or protected promotion code.
**Cash/data boundary:** $0 incremental; no new secret, owner credential, customer data, system mutation, or provider write in this document.

## Current evidence and non-authority

1. The deployed V1 Admin Broker has one closed privileged operation, `ELEVATED_IDENTITY_PROOF`, with a previously accepted first live proof. The no-trigger protected task does not expose an arbitrary shell, installer or permission to add new operations.
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

**Potential advantage:** existing GitHub connector/app identity might avoid new signing-key custody, expense and accounts. A protected verifier could make its own trusted REST read of fixed repository/issue comment metadata and accepted artifact evidence.

**Preconditions, all presently UNPROVEN:**

1. Establish that a *separately controlled* authority makes the allow/deny decision before the App can issue a promotion record. A normal user or model that can ask the same App to write an arbitrary "approved" comment must not be able to self-authorize promotion.
2. Pin repository, issue, server-returned comment ID, GitHub App ID `1144995`, appropriate author/installation scope, immutable created/update evidence, canonical record schema, allowed closed operation ID, active generation and predecessor; independently verify through authenticated trusted provider response. The GitHub MCP summary alone strips required App metadata.
3. Check accepted exact package commit/tree/per-file digests, independent influence-clean review and exact-head mandatory security tests *as verified by the privileged policy*, not caller-provided assertion. Review and code author identity separation must be material.
4. Require protected local high-water generation, durable request nonce/replay ledger, atomic promotion, exact readback and controlled rollback semantics. Reject modified comments, unknown App/author/issuer, missing provider corroboration, stale generation and any repository or ledger mismatch.
5. Prove how the protected runtime authenticates GitHub readback without receiving normal-user tokens, trusting a caller response or adding a new broad credential. If anonymous/private-repo access cannot satisfy this, mark **BLOCKED**, not "fall back to local git".
6. Threat-test issuer compromise and emergency revoke/disable. One observed `performed_via_github_app` field is insufficient to complete items 1–6.

**Disposition:** CONDITIONAL / **NOT SELECTED**. Do not encode App ID as a magic authorization switch. The controlling open question is separation of issuer decision from the caller/agent channel.

## Candidate B: signed closed catalog or reviewed Actions attestation

**Potential advantage:** a pinned offline verification key in protected code may create a cleaner host-local authorization proof; a reviewed workflow attestation may tie a built artifact to exact accepted source/checks.

**Preconditions:** independently controlled key issuer and custody, verifiable signature chain/revocation/rotation and anti-rollback, strict provenance/build context, artifact retention/access guarantees, supported feature entitlements and a protected first-install trust anchor. No generic package install or caller-chosen manifest. The privileged verifier must validate a fixed closed allowed operation and fixed reviewed bytes, not merely accept any correctly signed payload.

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

- **D0 — authority choice:** independent security/architecture review of Candidate A versus B; document accepted trust issuer, protected first-install bootstrap, provider verification channel, rollback resistance, and threat assumptions. **Current: OPEN / CHANGES_REQUIRED**.
- **D1 — exact closed source:** only after D0, source PR for fixed `DRAGONFLY_V2_PUBLISH_REVIEWED` contract and immutable helper verifier; preserve V1 operation and closed task. Adversarial deterministic tests, mandatory source/security CI, influence-clean independent exact-head review.
- **D2 — protected synthetic promotion:** preapproved isolated Windows fixture, complete denial/atomicity/replay/rollback/receipt, no real host mutation.
- **D3 — LDW01 protected publication:** separate one-time #139 owner-authorized exact package/installed binary/ACL readback, A4 and source head gates; no elevated GitHub CLI.
- **D4 — REDRIX Gate B:** separately perform one manual-only, no-secrets exact-provider JIT canary **only if** all REDRIX #96 capacity/privileged visibility, protected #52/#186, #10 dispatch, #115 transport, and #139 cleanup gates PASS.

D0–D2 are not permission to run D3 or D4. All failure or uncertainty is HOLD, with no automatic privileged retry, runner fallback, memory loosening, host/root action, spend or credential broadening.

## Reviewer decision requested

Return `ACCEPT_ARCHITECTURE`, `CHANGES_REQUIRED` or `BLOCKED_TRUST_ROOT`, with an independent proof of the chosen issuer's decision authority and immutable host-verifiable package chain. In particular, either demonstrate the App issuance separation and authenticated protected readback required by A, or explicitly route the first-install/credential owner gate required by B. Do not claim this draft has selected or implemented either option.
