# REDRIX D0 — $0 public GitHub attestation design, source-only non-admission

**Status: SOURCE/DESIGN CANDIDATE ONLY. NOT ACTIVE PUBLISHER, TRUST ROOT, ISSUER OR INSTALL AUTHORITY.**

Owner authority: [#186 original A0 source-only freeze](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6889092051) and [Nov18 bounded SYSTEM-task category decision](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186#issuecomment-6999867314). [PR #333 D0 architecture](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/333) and [PR #335 hosted SYSTEM task](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/335) remain independent DRAFT research; [PR #336 read-only Plan](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/336) is now merged to main (squash merge `0dfe17f447c1c231d7481172a22b11a23bf62759`) as source-only D0 preflight code, not an install or trust-root action. None of these installs the protected trusted root.

## Verified capability versus authority

The repository is currently public (authenticated GitHub repository metadata); current [GitHub artifact-attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) makes keyless public-repository attestations available without a code-signing certificate or new paid plan under supported GitHub tiers. The action [actions/attest](https://github.com/actions/attest) can bind the SHA256 digest of an artifact to a GitHub OIDC workflow identity. The exact GitHub v4 tag was independently resolved to commit `1e69f48acb82d1966a394da916b4c1698aa569d6` at design time; the **pin is reviewed source** and must be verified again before any active workflow adoption.

However, **a genuine GitHub workflow signature only proves its source/workflow identity, not whether the source was independently accepted by security, or whether a privileged LDW01 installer should execute it.** A normal GitHub source author may control both the built source and workflow and could produce a completely genuine attestation of a malicious artifact. The host still lacks an independently authenticated bootstrap verifier. Merged PR #336's D0 preflight is not leaf-only: it takes read-only Program Files ancestor DACL snapshots (root, intermediate and leaf) including the relevant DeleteChild mutation right. It remains a point-in-time, non-atomic check that does not close namespace races (rename, preexisting handles or post-check mutation) and is non-authorizing. **No D0 first-install authority follows from this design.**

## Deliberately inert publishing candidate

`REDRIX_D0_PROVENANCE_WORKFLOW_PROPOSAL.yml` lives under `host-agent/deploy/research/`, **not** `.github/workflows/`; GitHub Actions will never activate it from that location. It proposes:
- manual, **zero-input** workflow_dispatch only; explicit repository and exact `refs/heads/main` admission;
- single GitHub-hosted ephemeral runner with no secretless self-hosted fallback;
- fixed known source paths already on main (a **research-only** read-only/mocked probe, NOT a SYSTEM installer or a user-selected package);
- deterministic GNU tar metadata (fixed sort, mtime, owner/group), a fixed output name, and exact checkout HEAD equals the invoking main SHA;
- pinned checkout and attestation actions, no ref-tag-floating `uses`, no user-selected source SHA/path, and upload-artifact with 7-day retention;
- workflow default `permissions: {}`, then only the publishing job `contents: read`, `id-token: write`, `attestations: write`; no `actions: write`, `pull-requests: write`, deployment credential, `workflow_run`/PR trigger, dynamic dispatch or unattended protected task.

Activation is a **separate change/decision**, requiring independently accepted exact workflow blob and destination path, reviewed main-only triggers/permissions and the relevant GitHub repository/environment policy. Merely merging an inert proposal does not publish an attestation. If ever activated, it would be a source **research probe** and would not publish a source-approved SYSTEM task.

**Reproducibility limitation:** the inert GNU-tar/`ubuntu-latest` proposal does **not** guarantee byte-reproducible bundles. Fixed tar metadata and a floating runner image label do not pin the exact toolchain, library or package versions, so identical source can produce different artifact bytes (and a different SHA256) over time. Any activation that relies on a stable artifact digest requires independently reviewed evidence of pinned reproducible package/toolchain versions (or an equivalent byte-reproducible build) plus independent security review. This proposal does not supply that evidence and must not be activated on a reproducibility assumption alone.

## Future read-only verification (not implemented)

From a separately reviewed, trusted, immutable binary path and independently accepted policy/pins, a host verifier could invoke `gh attestation verify` against the exact artifact with **all** appropriate flags:
- `--repo LowcountryDigitalWorks/infrastructure-tools`
- `--source-ref refs/heads/main`
- `--source-digest <independently accepted exact source commit>`
- `--signer-workflow LowcountryDigitalWorks/infrastructure-tools/.github/workflows/redrix-d0-source-provenance.yml`
- `--signer-digest <independently accepted exact workflow digest>`
- `--deny-self-hosted-runners` and `--format json`

The command must exit success and the verifier must independently validate the artifact's actual SHA256 and the provenance certificate's identity fields. [GitHub CLI's current verification reference](https://cli.github.com/manual/gh_attestation_verify) specifically warns that only `verificationResult.signature.certificate` and verified timestamp evidence cannot be manipulated by the source workflow; most `statement.predicate` data is **workflow-controlled** and cannot serve as a protected approval decision. The signed certificate does not establish actual independently accepted code semantics or protected LDW01 task execution.

The current source module `RedrixD0AttestationEvidenceHold.psm1` accepts a **hypothetical**, wholly caller-provided map for **source-test classification only**. It does not invoke a genuine cryptographic verifier, and even exact matching input returns `HOLD_CRYPTOGRAPHIC_AND_INDEPENDENT_ACCEPTANCE_ABSENT`. Its test uses fake test pins and rejects changes in identity, digest shape, source ref, signer workflow and subject. It **MUST NOT** be repurposed as the physical admission verifier. It also does not pretend that a literal-text or syntactic policy check is full AST/YAML semantic proof.

## Required P0 decision and implementation order

1. Review this **source-only** proposal and its synthetic HOLD-only classifier, with exact-head hosted Windows test and author-excluded security review. Keep draft/unmerged unless a distinct approved release gate exists.
2. Independently decide one **approved, immutable first-install source/actor trust root** for the zero-input, owner-authorized SYSTEM task. Pin a trusted Windows executable and verify protected Program Files **whole ancestor chain** (including DeleteChild, rename and preexisting handles), immutable verifier binary, source SHA and signer-workflow generation; merged PR #336's ancestor DACL snapshot includes DeleteChild but is a non-atomic, non-authorizing point-in-time check, so it is insufficient on its own. If this cannot be established, report `D0_TRUST_ROOT_ABSENT`.
3. Only if source policy and verified host root are accepted, author/review/enable a main-only actual provenance publisher for an exact separately accepted **fixed package**, not the present research-only tar.
4. Continue to require distinct physical owner-admin consent for **any** real `%ProgramData%\LDW` parent ACL mutation. SYSTEM-owned journal must exist **at creation** with `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`, same-handle readback, durable PREPARED/COMMITTED and six-child task parity. Task-category permission is NOT ACL permission.
5. CI7 #269/#264 immutable controller and lock/guest removal, REDRIX #139 A4, #96 10,240 MiB guest-visible and provider-success JIT remain separately held. Existing production fail-before-mint source remains unchanged.

No new private key, signer token, provider interaction, OIDC use, attestation publication, app, DNS/email/billing, task creation, executable, protected host access, VM or runner action was made by this proposal. **$0/included only.**
