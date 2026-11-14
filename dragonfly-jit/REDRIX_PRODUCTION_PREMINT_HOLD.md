# REDRIX protected LDW01 JIT source — production pre-mint HOLD

**State: SOURCE CANDIDATE ONLY / DENY BY DEFAULT / NO NEW RUNTIME AUTHORITY.**

Owner [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139); protected trust [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186) / [#269](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/269); queue [#10](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/10); memory [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96); retained CI7 incident [#264](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/264).

## Material new source behavior

Unlike DATA_ONLY response fixtures in merged PRs #318 and #319, this change places **two explicit hard fail-before-provider-write guards in the actual REDRIX Windows production source**:

1. The entrypoint \`ci-dispatch/Invoke-DragonflyCanaryProduction.ps1\` refuses \`DRAGONFLY_CANARY_WORKFLOW_SOURCE_UNBOUND\` **before importing runtime modules or issuing any GitHub GET**, even when a plausible caller \`-HeadSha\` is provided.
2. The in-file \`Invoke-LdwDragonflyCanaryGhWrite\` refuses **every \`POST\`** before creating the \`gh.exe\` process. The exact-match \`DELETE\` cleanup behavior remains unchanged; the source does not mint JIT bootstrap material.

The regression in \`ci-dispatch/tests/Test-DragonflyCanaryProductionScope.ps1\` calls the production entrypoint in isolated PowerShell 7 processes with three forged well-formed synthetic SHAs, requires exit 1 and the exact HOLD classification, and extracts just the writer function from the PowerShell AST to exercise its POST denial without provider access. The existing import visibility and scope checks are retained. Existing hosted Dragonfly source validation executes this test on Windows and Ubuntu. A test passing demonstrates only the *candidate source* is closed, not that any installed protected Windows copy changed.

This refusal intentionally means **no REDRIX Gate B job can start through these candidate source code entrypoints**. The already installed accepted controller and its immutable release bundle remain unchanged by GitHub merge or hosted CI. This source change is *not* a substitute for reviewing whether other launchers/paths can bypass the new entrypoint; future protected release security review must cover the complete executable call graph.

## Why no positive allow-path exists yet

The source-only tuple correlator and simulated provider GET adapter merged from PRs #318/#319 cannot attest a fixed-trust issuer. The CLI's caller-provided \`-HeadSha\` alone is not trustworthy. The accepted \`Dispatch.psm1\` narrow GET allowlist does not currently include Git ref resolution; even positive GitHub read evidence cannot establish a separate protected LDW01 approved generation without #186/#269.

Opening an unreviewed data-only positive path here would create a bypass. Therefore **both guards remain unconditional** until a separately reviewed issuer+generation+provider-authenticated pre-mint integration is ready. Future work must replace these guards as a single source-controlled, independently verified transaction, never by a CLI flag, environment toggle, mutable JSON file, admin self-asserted hash, or operator-command shortcut.

## Roadmap — real trust-path completion

1. Independent exact-head source review of this production-entrypoint HOLD PR, hosted Dragonfly/Security PASS, maintainers check original POST, DELETE and runtime call graph; source-only guarded merge if accepted.
2. Product/security decision specifically accepts or rejects the PR #315 owner-trusted sudo threat-model *scope*. Prior malicious UID1000 H2/M1 finding remains correct for independent root attestation; preserve unrestricted sudo and ChromeOS.
3. Produce reviewed **producer-owned immutable protected LDW01 release/issuer generation** under #186/#269 with exact workflow commit, ref and blob plus active source/runtime identity; no user-chosen SHA or self-promotion.
4. Implement a closed provider-authenticated GitHub GET adapter for approved ref/blob/run/attempt/job, bind to protected generation and prove fresh source validation immediately before JIT POST. Ref movement, provider outage, absent trusted generation, wrong blob/branch/attempt/job or caller-selected SHA must fail **before mint**, preserving lock and cleanup invariants.
5. Independently review full controller call graph and protected source promotion/install (including parent LDW ACL and controller snapshot acceptance). Tests must prove no alternate \`generate-jitconfig\` path, no credential leakage, and exact protected live readback after separate owner-approved physical transaction.
6. Separately satisfy REDRIX #96 guest-visible >=10,240MiB memory guard, #139 actual A4 privilege/FD functional evidence (not independent trust vs sudo-capable UID1000), #10 queue/runner provider identity, and held CI7 incident #264. Only then use existing conditional owner approval for **one** manually selected secretless Gate B, provider-confirmed assignment/success, one-shot teardown and runner deregistration.

## Explicit nonclaims and boundaries

- No protected release publication or physical source deployment. No modification to \`ci-runner/**\` six-file immutable snapshots, protected catalog, Windows ACL/task/service, Linux root/sudoers, SSH/Tailscale, ChromeOS, QEMU/VM, GitHub runner or JIT token, memory reserve, CI7 retained guest or provider workflow.
- No new privileged issuer, no accepted source generation, no production A4 PASS, **no live Gate B**.
- No monetary spend, no PAYG, no API-key tooling, no recurring controller or security waiver.
- Live GitHub/main or host state may change; revalidate prior to any next operation.
