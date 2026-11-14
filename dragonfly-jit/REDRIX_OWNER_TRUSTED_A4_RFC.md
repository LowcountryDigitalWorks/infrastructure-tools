# REDRIX A4: owner-trusted sudo-compatible security design (proposal)

**Status: RFC / SOURCE-ONLY / NOT APPROVED / NO PHYSICAL BOOTSTRAP / NOT A4 PASS / NO JIT AUTHORITY.**
Owners: infrastructure-tools [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96), Windows [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186), controller [#269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269) and recovery [#264](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/264).
Decision source: [#139 owner statement recorded November 14](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6872862938). Owner prefers retaining unrestricted sudo and privileged access; no approval to remove sudo or change ChromeOS boot/firmware. This statement **does not independently approve** the threat-model revision, protected install, Gate B dispatch, or memory-policy changes.

## Why this alternative is necessary

The independently reviewed [#139 H2/M1 verdict](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6867926496) is correct under the existing **adversarial UID1000 coordinator** threat model: if UID1000 has unrestricted NOPASSWD sudo, an attacker controlling UID1000 can become root, replace even root-owned package files, tamper with a replay ledger, and generate fabricated root-origin evidence. Linux UID0, file ownership, an in-process hash, SO_PEERCRED or the pinned #115 SSH host key **cannot** establish an independent root issuer against that attacker.

The owner prefers retaining the general sudo capability. This RFC proposes a **narrower explicitly owner-trusted execution profile for one secretless synthetic canary**, not a claim that unrestricted sudo has become an independent trust boundary. It is a decision to evaluate, not a source change to the protected controller.

### Security domains and assumptions

| Domain | Proposed trust status | Consequence |
| --- | --- | --- |
| Owner-controlled REDRIX ChromeOS + Crostini user and container root, including unrestricted sudo | **Trusted operator for this one synthetic canary only**, if the reviewer and owner explicitly accept this revised profile | Local root evidence is useful functional telemetry, NOT independently attested evidence against a malicious local user |
| LDW01 protected Windows issuer, reviewed release generation, and immutable controller | **Separately trusted only after existing #186/#269 gates pass** | REDRIX cannot self-assert or replace Windows trust, admission or release provenance |
| GitHub provider exact run/attempt/job/runner/labels and terminal outcome | Official authenticated provider confirmation independently read from LDW01 | Proves GitHub runner assignment and workflow result only; does NOT prove guest isolation, filesystem cleanup or kernel FD completeness |
| Short-lived JIT configuration and single-use capsule | Sensitive, tightly bounded execution material | No long-lived runner credential on REDRIX; no log/issue/PR echo; no credential reuse |
| QEMU guest, workflow scripts, repo content, network outputs | **Untrusted workload** | Must be nested/ephemeral, secretless, no checkout, no repository permissions, full cleanup and residue check |
| Independent A4 root issuer against compromised UID1000 | **NOT PROVIDED** while unrestricted sudo persists | Report A4_INDEPENDENT_TRUST_HOLD in all owner-trusted diagnostics; preserve prior H2 finding for this adversary |

This acceptance profile is intentionally limited to a single harmless manually dispatched job with no checkout, no repository/org/environment secrets, no customer/private data and permissions: {}. It does not authorize sensitive secret-scanning or general private CI on a trusted runner, nor standing service/poller execution. Any later broad workload admission needs a new threat model and review.

## Explicit classifications, no accidental gate substitution

1. **INDEPENDENT_A4:** NOT_ATTESTABLE_UNDER_CURRENT_UID1000_SUDO. Never mark PASS from local privileged file or process inspection, even if all /proc descriptors are readable.
2. **OWNER_TRUSTED_A4_FUNCTIONAL_EVIDENCE:** PROPOSED_READ_ONLY_DIAGNOSTIC. The accepted read-only live /proc inspector may eventually be invoked as part of a separately accepted fixed package to demonstrate capability, namespaces, two stable PID/FD snapshots and zero unresolved denials. It must still return DATA_ONLY_NOT_AUTHORIZED and jitAdmissionAuthorized=false until an independently reviewed revised acceptance contract exists.
3. **EXACT_GITHUB_PROVIDER_PROOF:** PENDING. A positive runner_id, exact runner_name and job assignment on the intended provider job, terminal SUCCESS, deregistration and complete host/guest cleanup must be independently read from live sources.
4. **GATE_B:** HOLD / NOT CONSUMED. No source-only result, root observation, owner preference, green GitHub hosted CI, or owner-trusted diagnostic can cause dispatch or mint JIT material.

No existing acceptance parser, source runtime flag, immutable protected release, GitHub workflow, or CI dispatcher is modified by this RFC. The current accepted 2,048 MiB nested guest + 8,192 MiB Crostini-visible reserve = 10,240 MiB memory floor is unchanged. Owner-observed ChromeOS host free RAM is a different ledger.

## Proposed implementation path (all milestones independently gated)

**M0 — RFC and adversarial review.** Accept or reject the narrowed trust assumption using actual #139 H2/M1 findings. A reviewer must explicitly test the counterexample: compromised UID1000 can change root evidence, so any positive owner-trusted readback is functional data only, not independent attestation. Require distinct author-excluded review of the exact changed source candidate, and an owning security/product approval of the precise changed trust model, not a general "sudo is fine" statement.

**M1 — exact source verification, zero physical privilege.** Finish independent exact-head review of draft [PR #313](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/313), verifying descriptor-relative fixed package bytes, FIFO/special refusal, identity drift checks and every authority flag false. Continue closed no-argument launcher/channel source work on a separate PR only after M0 contract freeze. Pin exact source payload/interpreter/runtime dependencies by independently accepted digest, never a caller-supplied manifest, path or mutable checkout. Keep recovery path unchanged.

**M2 — owner-attended bounded root functional diagnostic, not install.** Only after security-accepted source and an exact physical operation authorization, capture the privileged inspector's own CapEff/CapBnd, user/PID/mount namespace equality and actual per-PID/per-FD results. Require two stable snapshots with starttime/pidfd or fail closed on drift; reject partial process visibility, readlink denial, namespace mismatch, and LSM/dumpability uncertainty. Do not modify sudoers, capabilities, ptrace sysctl, SSH, service/scheduler, or launch QEMU to obtain measurements. Do not import or run local mutable checkout code as root; use only reviewed fixed bytes. Sanitize results; no process argv, environment, keys, tokens, run identifiers or private file contents in issues.

**M3 — retain separate LDW01/CI7 holds.** Independently prove #186 protected issuer plus accepted active generation, #269 immutable controller identity and actual controller lock ownership; retain #264 cancelled-job Off VM until an exact safe authorized recovery transaction. A matching VM name and stopped state alone cannot authorize deletion. Use existing #10 sole dispatcher and #115 forced-command transport only; no generic remote root shell.

**M4 — corroborate admission capacity.** Capture actual ChromeOS browser-host five-sample memory and overlapping accepted Crostini guest calibration without changing memory allocation or forcing balloon release. Require a sustained accepted guest-visible 10,240 MiB floor and LDW01 host >=6 GiB at actual preflight; a transient or host-only reading does not qualify. No speculative 2+6 profile.

**M5 — single real secretless canary.** Once all accepted security, source, runtime, host, provider and recovery preconditions are verified, use the already separately approved and unconsumed one protected V2 publication + one exact #10 provider-positive manual Gate B attempt, no retries. Require exact run/attempt/job/head/labels, short-lived JIT only on LDW01, one ephemeral REDRIX nested guest, terminal provider SUCCESS, absent runner registration, wiped overlay/seed/bootstrap/state and no credential residue. If any receipt, cleanup or identity is uncertain, HOLD; do not claim success.

## Review checklist / deliberate failure cases

- [ ] Treat the compromised sudo-capable UID1000 as a *successful attacker* against independent Linux root provenance; no test may report independent A4 PASS in that state.
- [ ] Identify the exact owner-trusted scope and exclude privileged general/private/secret workload admission.
- [ ] Reject self-signed or self-asserted proof, altered checkout, caller-chosen root binary, forged source hash, symlink/mount traversal, mutable replay store and stale or replayed packet.
- [ ] Keep the approved forced-command transport and separate Windows publisher; no REDRIX self-registration or GitHub credential minting.
- [ ] Keep original local/host memory guards, pending CI7 residue and exclusive controller-lock requirement.
- [ ] Require actual immutable source and physical proof readbacks, author-excluded review, and an explicit revised trust-model decision before any privileged runtime claim.
- [ ] Verify source-only green checks cannot activate a runtime flag or privileged install; all failure modes remain HOLD.
- [ ] Prove no paid provider, new persistent runner, new scheduler, destructive recovery or private/site workload.

## Disposition

This RFC is deliberately **non-authorizing**. The current independent A4 H2/M1 finding stands unchanged. Until security and product owners independently accept a revised exact scope, preserve all current A4/JIT holds and report no real JIT success. No sudoers or machine changes are requested by this document. $0/included only.
