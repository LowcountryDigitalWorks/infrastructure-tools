# REDRIX Gate A4 — proposed privileged process/FD evidence contract

**Status: PROPOSAL / DATA-ONLY / NOT SECURITY-ACCEPTED / NOT RUNTIME AUTHORITY**

Owner: [infrastructure-tools #139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139) and [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96). Independent adversarial feasibility disposition: [#139 comment 6676287868](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6676287868) — CHANGES_REQUIRED (H1/M1). This document is a proposed specification for independent review, **not a permission** to invoke `sudo`, modify kernel or host policy, deploy a helper, bypass remote-tool restrictions, start a JIT job, or treat a synthetic receipt as A4 PASS.

## Why an additional trust boundary is required

The accepted `tools/dragonfly_gate_a4.py` entrypoint requires Linux, effective UID 1000 and home `/home/eddie`. Its pinned `tools/dragonfly_gate_a0.py` dependency scans `/proc`, enumerates same-UID processes, and inspects their `/fd` symlinks to refuse leftover `/dev/kvm` file descriptors. Inaccessible process descriptors are a **HOLD**, not evidence of zero descriptors.

On physical REDRIX (ChromeOS -> Termina -> Crostini Debian 13 `penguin`), the normal-user A4 attempt returned `A4_PROCESS_VISIBILITY_UNCERTAIN`. Normal-user readback found `ptrace_scope=1` and no effective CAP_SYS_PTRACE/CAP_DAC_READ_SEARCH. This supports a real process-inspection limit but does not prove all same-UID descriptors are permanently invisible. Running the unchanged A4 as root is **not** a solution: it would fail the mandatory effective-UID check. Replacing `/proc` FD evidence with `pgrep` or a simple QEMU count would reduce the accepted security property.

Existing accepted local source-CI/KVM smoke and prior #98 synthetic systemd credential tests are separate capabilities. Neither establishes an authorized privileged A4 collector. The total Linux-visible RAM (~29.5 GiB) and current 2,048-MiB guest + 8,192-MiB preserved host-reserve admission are unchanged.

## Proposed minimum design for review (not implemented)

1. **Privilege ownership.** A future **fixed, narrowly scoped, one-shot read-only process/FD inspector** may be invoked only through a separately approved owner-local, authenticated, independently reviewed privilege boundary. No standing service, scheduled task, generic remote shell, caller-selected executable/script/URL/path/ref/arguments, sudoers widening, new token, or ambient PATH command. In particular, the current remote path's privilege refusal may not be circumvented. No accepted existing REDRIX protected inspector is asserted here.
2. **Source/operation identity.** The privilege boundary must verify an immutable, accepted inspector package/entrypoint, exact bytes and trusted ownership/permissions/ancestor chain before execution. All operation selections and file locations are closed in protected source, never supplied by the UID-1000 caller. An untrusted user's JSON, digest, assertion of `euid=0`, PID list or certificate is **data, not privilege attestation**.
3. **Separate user identity.** Preserve the existing UID-1000 A4 package/receipt/SSH/Tailscale/JIT-state/source/owner/mode/no-symlink checks without changing their expected values. The future root-side inspector obtains process evidence independently; it must not run the existing UID-1000 A4 entrypoint as root, impersonate its result, or silently skip a rejected source check. Any future A4 composition change requires independent source/security acceptance and new exact-bound tests.
4. **Authenticated live evidence path.** The binding between a protected inspector and the UID-1000 A4 verification must be a separately reviewed, same-invocation, locally authenticated channel with protected inspector identity and bounded lifetime. Merely passing an owner-writable file, stdout claim, caller-created pipe, forged parent PID, or signed-by-the-caller JSON cannot establish trusted process evidence. The accepted design must spell out which trusted side creates and controls the channel, how the verifier authenticates the producer, how replay is refused, and how failure leaves both sides in HOLD.
5. **Full scope and fail-closed visibility.** The privileged inspector independently enumerates all required processes and accessible `/proc/<pid>/fd` targets, including same-UID/owner-host processes required by the accepted A0 contract. It may broaden to all UIDs as a *stronger* condition if independently accepted, never narrow the existing coverage. An unreadable PID, stat, ownership field, FD, disappearing ambiguous process, or partial enumeration is **HOLD**. No positive conclusion from absence of process name or untrusted caller-provided counts.
6. **Stability and anti-replay.** Bind each observed process to PID **and kernel start-time identity** (or stronger kernel-validated identity); sample around the UID-1000 A4 readback at least twice, recheck process identities/FD coverage and root inspector source, and fail on PID reuse, exit/replacement races, scope drift, new KVM FD, nonzero QEMU/KVM, sequence mismatch or non-monotonic/stale evidence. Two identical caller-provided JSON documents are not two trusted observations.
7. **No lasting authority.** A future authenticated observation would be a necessary A4 subproof, **not** permission to mint GitHub JIT material, register a runner, dispatch a workflow, publish V2, alter SSH/Tailscale, alter ChromeOS, migrate credentials, change kernel ptrace policy, or relax memory reserve. The #52/#186 protected V2 publisher and #10 provider queue/runner authorization remain independent sequential gates.
8. **Data-only until accepted.** Any non-privileged schema/parser or synthetic fixture implementing this proposal must return an explicit `DATA_ONLY_NOT_AUTHORIZED` classification. The only acceptable current production disposition when full inspected-FD evidence is missing is **`A4_PROCESS_VISIBILITY_UNCERTAIN` / HOLD**. A future `A4 PASS` requires exact package/source review, independently accepted authenticated privilege path, current trusted host readback and separate owner/security deployment authority.

## Proposed minimal evidence fields (not an accepted wire format)

A reviewable future schema would bind: protocol version; fixed inspector/source identity; explicit local host identity; a fresh protected operation correlation/nonce; inspection scope and exact UID policy; two independently observed ordered snapshot identifiers with monotonic time bounds; for each observed process PID, kernel start identity, UID and complete descriptor-enumeration result; QEMU process and `/dev/kvm` FD counts; per-process access-completeness markers; validated UID-1000 A4 receipt/source identity; channel-authentication status **measured by the receiver**; and terminal `HOLD` reason classification. Exact sensitive process paths, private SSH endpoints, credentials, arguments and logs must never appear in durable output.

This list is a **design input, not a parser**. No reported `root=true`, `signature=true`, SHA, counter or timestamp should be considered authenticated merely because it appears in a caller-controlled envelope. Where identity, coverage or freshness cannot be proved by an independently protected component, return HOLD.

## Deterministic negative-test and acceptance matrix

| ID | Synthetic condition | Mandatory future result |
| --- | --- | --- |
| A4-FD-01 | No accepted privileged inspector/channel | HOLD; normal-user A4 cannot manufacture trusted evidence |
| A4-FD-02 | Caller supplies arbitrary executable, path, URL, Git ref, PID, FD list or privileges | REFUSE before any privileged operation |
| A4-FD-03 | Root invokes unmodified UID-1000 A4 or user spoofs UID/home | Existing owner identity check refuses; no promotion |
| A4-FD-04 | Caller-supplied, forged, copied or replayed `zero KVM` report | HOLD, not A4 PASS |
| A4-FD-05 | Inspector package, source blob, owner/mode, ancestor, symlink or executable identity drift | HOLD before invocation |
| A4-FD-06 | Missing `/proc` entry, denied `/proc/<pid>/fd`, unreadable `fd` link/stat/UID | HOLD; zero not inferred |
| A4-FD-07 | PID exits, is reused or changes kernel start identity between snapshots | HOLD, not two stable snapshots |
| A4-FD-08 | A process opens or retains `/dev/kvm` or QEMU process exists in either snapshot | HOLD |
| A4-FD-09 | Two snapshots do not bind one current UID-1000 A4 readback | HOLD |
| A4-FD-10 | Host identity/nonce/correlation mismatched, stale, nonmonotonic or duplicated | HOLD |
| A4-FD-11 | Unexpected UID, user-controlled channel, spoofed peer or missing protected producer identity | HOLD |
| A4-FD-12 | Synthetic clean/complete stable zero-process/KVM-FD fixture | **DATA_ONLY_NOT_AUTHORIZED**, never runtime A4 PASS |
| A4-FD-13 | A4 receipt/package/SSH/Tailscale or accepted pinned A0/A4 source fails | HOLD independently of process evidence |
| A4-FD-14 | Inspector reports success but source/provider/V2/queue admission is missing | A4 not promoted to JIT/runner/dispatch authority |
| A4-FD-15 | FD inspector unavailable, timeout, busy, permission or transport error | HOLD; no fallback to `pgrep`, status CLI or weaker check |

Tests must verify **actual denial classifications**, not merely the existence of a test name or assertion of `PASS`. An independent source-security reviewer must decide whether an implementation preserves the existing strict acceptance property before code is merged.

## Ordered gates and safe rollback

1. **This proposal:** influence-clean architecture/security review; revise or reject. No runtime claim.
2. **Bounded source candidate:** reviewed immutable fixed collector, authenticated producer/consumer binding and deterministic fail-closed tests. No system install or privilege yet.
3. **Owner/security runtime decision:** exact protected local operation, current installed bytes and permission/rollback verification; never reuse #98 synthetic sudo authorization as permission for this new operation.
4. **Physical REDRIX evidence:** one owner-local approved read-only privileged inspection paired with untouched UID-1000 A4 receipt; independently reconcile both sides and terminal cleanup. Any ambiguity or failure remains HOLD.
5. **Independent JIT gates:** protected LDW01 V2 publication/readback (#52/#186), #10 exact GitHub queue/runner/SSH/provider admission, accepted memory floor, then at most one previously owner-authorized secretless #139 canary. Runner/JIT teardown must be independently proven.

**Rollback for the current source-only proposal:** close the draft PR without merge; it has no deployed state. A future installed collector must specify separate fixed fail-closed uninstall/restore and no lingering elevated service, credential, task, policy or public listener before permission can be granted.

References: [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96), [#115](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/115), [#10](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/10), [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52), [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186).
