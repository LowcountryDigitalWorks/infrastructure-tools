# REDRIX / LDW01 — D0 protected workflow-source issuer contract (PROPOSAL)

**Status: DESIGN PROPOSAL / NOT ACCEPTED / NO INSTALL, POST, RUNNER, RECOVERY, OR TRUST-ROOT CHANGE.**

Owner: [REDRIX #139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139). Joint trusted-promotion constraints: [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186) and [#269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269). Preserve [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96) Crostini policy, [#10](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/10) protected dispatcher/locks and [#264](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/264) held CI7 incident. Proposed sudo-compatible A4 RFC from PR #315 remains non-authorizing.

## 1. Why the D0 decision is real

As of Nov 14, 2026, merged source [PR #320](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/320) refuses REDRIX production entry and direct JIT POST with `DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND`. Merged PRs #318/#319 only parse and correlate source evidence; none establish protected authority. Merging source has **not** installed it on LDW01. Previously observed physical V1 broker registry includes `ELEVATED_IDENTITY_PROOF` only. It does not already contain a generic independently protected promotion operation. The parent LDW DACL/first-install transition is also held. Thus a release manifest in a user-controlled Git checkout, a GitHub comment, SHA alone or green CI cannot add a trusted issuer. Any source-only positive result is DATA_ONLY.

The accepted threat model must separately state that local Administrator/SYSTEM compromise defeats a purely local software root. Compromised normal-user processes, repo authors, mutable branch refs and provider replay **are adversarial** for the protected Windows issuer. REDRIX UID1000 retains unrestricted sudo by owner preference; independent malicious-root A4 attestation cannot be claimed from that same UID.

## 2. Decision proposal: initial bootstrap versus ongoing promotion

**D0 (required, explicit separate owner/security gate):** One attended, narrowly scoped first-install transaction for exactly one frozen, independently accepted issuer/verifier release. A pre-existing trusted execution context must authenticate the installer *before* it reads privileged input. If there is no such context now, report `D0_TRUST_ROOT_ABSENT` and request an exact separately reviewed owner-admin bootstrap. **Do not synthesize D0** from a scheduled task, editable source checkout, mutable manifest, prior V1 read-only operation, or ordinary remote management session.

**D1 (only after D0 is accepted and read back):** A protected verifier may accept a future **independently authorized**, cryptographically authenticated exact release descriptor into one atomic monotonic generation. The signer identity, independent approval policy, verification algorithm/public trust anchor, key custody and revocation/rollback rules must be accepted in the D0 transaction. **These are unresolved, not silently selected by this document.** Never treat source author/GitHub Actions runner identity alone as independent reviewer authorization. A bot review in Codync provides source findings; it does not by itself produce a protected cryptographic approval.

**Fast safe fallback:** If a separate signer/trust key is not already available on an approved $0/included basis, keep future promotions owner-attended per exact approved release. Do not invent a signing credential, weaken verifier requirements, create a broad SYSTEM updater or claim unattended upgrades.

## 2a. Reconcile the existing #52 / #186 GitHub App authority candidate

Parent [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52) already records an **unaccepted** Gate A candidate: a protected promoter would validate a fixed-schema GitHub authorization record using the provider's `performed_via_github_app` metadata from the existing ChatGPT GitHub App durable-action channel, plus predecessor/next generation, source commit/tree/blob/hash, catalog digest and expiry. **This proposal is a companion threat/first-install contract, NOT a replacement issuer or a second promotion writer.** Any accepted path must route to the *single* #186 policy and #269 protected release controller.

The field `performed_via_github_app` establishes reported GitHub App action provenance in a GitHub REST object. It does **not by itself** attest distinct human security acceptance, the source author's independence, key custody, protected Windows installation, or authority to run the package. Exact app ID and installation identity, how the action is triggered and by whom, reviewer separation, authenticated fresh GitHub GET origin, anti-replay, revocation, accepted signer/authorization policy, and the first protected verifier must all be explicitly security-reviewed before this becomes D0/D1 trust. If the owner or source author can cause the accepted App to issue a privileged approval without a distinct policy/actor gate, a forged-seeming but genuinely App-authored record remains a self-approval risk. Never infer independent approval from `performed_via_github_app` alone.

**Read-only feasibility observation (not approval):** the first-party GitHub REST GET of [existing source-review comment 6885739055](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/320#issuecomment-6885739055) returned `performed_via_github_app.id=1144995` and slug `chatgpt-codex-connector`, while the comment actor is a normal GitHub `User` with repository `MEMBER` association. This proves the App attribution field is available in a provider response for a known existing write, **not that the actor was a separate independent security reviewer or that the App can bootstrap a protected Windows verifier**. Because the same authorized ChatGPT channel can submit source-author comments, allowlisting this App ID without a distinct accepted promotion-policy actor would be self-approval. No new app, token, comment or privileged action was created by this observation.

**Preferred no-new-spend research gate:** evaluate the already available GitHub App channel *first*, in read-only/provider-metadata mode, against an exact non-executing release descriptor and the #186 trust model. If it can satisfy the independent approval and protected first-install conditions, use that existing channel; otherwise retain `D0_TRUST_ROOT_ABSENT` and the owner-attended exact-action alternative. Do not create a new GitHub App, signer private key, token, approval bot, service, or schedule for this proof. D0's pre-existing protected verifier/bootstrap problem remains even if the App metadata is authentic.

## 3. Exact release record proposed (no current approved values)

A strict v1 release descriptor would bind **all** of:

- Stable GitHub repository owner/name **and repository ID**; reviewed source commit 40-hex and tree 40-hex; immutable content digest; the one exact workflow path and Git blob SHA, plus fixed branch ref `refs/heads/main` and its expected commit. The ref is checked fresh; its string is not authority.
- REDRIX profile exactly `dragonfly-github-canary-v1`; workflow `.github/workflows/dragonfly-jit-canary.yml`; event `workflow_dispatch`; job `dragonfly-canary`; seven fixed labels plus exactly two dynamic run/attempt labels.
- Exact release generation ID and monotonic generation number; exact accepted prior generation; separately signed issuer/verifier and trusted bundle identities; allowlisted fixed operations and arguments; metadata schema and canonical byte representation.
- Exact frozen hashes for any controller/dispatcher/issuer scripts that will run privileged, including the six accepted CI7 controller runtime-file hash policy when it applies. **Do not modify existing historical accepted snapshots in place.**
- Explicit scope of approval: one bounded **secretless** REDRIX Gate B, no standing poller, no arbitrary commands/paths/URLs, no generic file copy, no extra provider writes. Existing conditional owner approval for the one canary is not a blanket release authorization.

Reject unknown, duplicated, missing, mixed-generation, wrong-type or noncanonical fields; conflicting signatures; expired or replayed release; unreviewed signer or verification-key rotation; a changed workflow blob at an unchanged path; branch movement; a caller-provided SHA matching its own invented record; and a provider outage. A future schema and signature format require their own independent review and test vectors; no hardcoded current SHA in this proposal confers authority.

## 4. Protected publisher / pre-mint transaction

1. Under a currently accepted protected Windows identity, acquire the one existing exclusive dispatcher/controller lock and attest that exact installed issuer/verifier code, DACL ancestors, generation and receipt match. If the issuer does not exist, **HOLD**; do not run a mock verifier as SYSTEM.
2. Authenticate the approved release authority independently of the caller, then materialize only exact reviewed content into a protected staging root. Verify source file SHA-256, archive/file path types, no symlink/reparse redirection and exact operation catalog. Caller may request the one operation ID, never choose a repo/ref/hash/executable.
3. Stage one candidate and protected rollback journal. Commit atomically, refuse partial/mixed generation, and read back exact immutable installed bytes/ACL/task/trigger state. Preserve the former accepted generation for **separately authorized**, monotonic/controlled rollback; no writable local rollback bypass.
4. For a single selected queued REDRIX provider job, authenticated narrow GET reads must resolve approved `refs/heads/main` to approved exact commit; verify exact workflow file bytes/blobs at that commit; then exact run/attempt/job, labels, head, event, queue state and absent assignment. Repeat fresh reads **immediately before** JIT token mint under the protected lock. Treat a mismatch/TOCTOU as terminal HOLD. Never reuse the caller `-HeadSha` as source authority.
5. Only after #139 A4 owner-functional vs independent-trust decision, #96 Crostini-visible >=10,240MiB admission, #10 provider/lock/identity, #186/#269 installed release and #264 unrelated CI7 incident gating are satisfied may the existing one-shot, explicitly conditionally approved Gate B proceed, with provider-positive job assignment, terminal outcome and complete teardown.
6. **No widening of API allowlist** until the exact missing Git-ref GET is independently security reviewed. The current `Dispatch.psm1` accepted read allowlist does not permit it. No permission for GitHub token, runner registration, SSH, VM, ACL or new Scheduled Task is conveyed by this design.

## 5. D0 safety and rollback tests required before any physical transaction

- An owner-writable checkout, forged SHA, self-approved comment, or arbitrary manifest **cannot** supply the trust root, verifier binary or signer.
- If trusted signer is absent, the result is `D0_TRUST_ROOT_ABSENT`, not an invented acceptance; if release source changes after review, fail closed.
- Invalid DACL/ancestor or reparse point, insufficient protected lock/owner/quiescence, generation replay, mixed files, power-loss staging or incomplete journal always refuses with recoverable previous generation.
- Missing GitHub provider, wrong ref/blob/run attempt/job/labels, queued-to-running transition, alternate workflow and concurrent dispatch all refuse before `generate-jitconfig`; no credential emitted or copied to logs.
- Direct/alternate provider POST paths and their executable calls are covered by exact controller source tests and security review; the current PR #320 AST test fence covers only its reviewed source shape and is **not** a blanket future-code proof.
- Physical first install, owner UAC, protected signer/key installation, active release promotion and CI7 cleanup each require separate exact authorization and after-readback. Do not change `C:\ProgramData` parent ACL; the LDW-specific parent migration remains independently held.

## 6. Research conclusions and alternatives

- GitHub artifact attestations can help verify a public repository release's build provenance, **but provenance is not an independent security or release approval**. An issuer must enforce its own authorized signing identity/policy and immutable protected trust anchor.
- Windows `CRYPTPROTECT_LOCAL_MACHINE` DPAPI is **not** an acceptable sole issuer authorization barrier: Microsoft documents that any local user can decrypt data protected with machine scope. Store no release authorization on this assumption.
- Neither a self-authored SHA-256/manifest nor an externally generated green CI log independently establishes privileged authority. Under current D0 state, an unattended positive path is **not proven**.
- At $0 incremental spend, prefer a single reviewed attended D0 + minimal protected verifier over new agents, recurring schedulers, hosted databases or paid signing services. This is a design preference, **not approval**.

References: [Microsoft DPAPI machine-scope behavior](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [GitHub artifact attestation limitations](https://docs.github.com/en/actions/concepts/security/artifact-attestations), and [GitHub attestation availability and public/free-plan restriction](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## 7. Freeze/acceptance roadmap

**Gate A — decision:** Independently challenge this threat model and D0/D1 authority split, identify available *pre-existing* protected verifier and actual issuer/signing identity, propose one exact source-and-admin transaction or return `D0_TRUST_ROOT_ABSENT`. Owner/security decides any new key or privilege bootstrap. This document does not select signer credentials.

**Gate B — implementation:** Only on accepted contract, implement one closed-source verifier/publisher/ledger and negative tests on a separate exact candidate, retain all existing accepted snapshot rejections, and obtain hosted exact-head security/IR H0/M0.

**Gate C — physical:** One exact reviewed owner-approved protected D0 installation/ACL/readback transaction; no generic ADMIN SYSTEM shell. Do not assert a protected issuer exists based on source tests.

**Gate D — JIT:** Reviewed authenticated ref/blob/queued-job fresh proof, fail-before-POST, #139 A4 and #96 memory acceptance, one already conditionally authorized manual Gate B and complete cleanup. No unrelated #264 CI7 recovery without separate authorization.

**Decision not yet made:** D0 protected trust root and signer identity are **OPEN**, and no code may upgrade the present hard source HOLD. No new spend, customer/regulated data, secret material, runner/VM/host change or provider write.
