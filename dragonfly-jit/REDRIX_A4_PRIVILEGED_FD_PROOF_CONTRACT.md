# REDRIX Gate A4 — privileged process/FD proof design contract

**Status: PROPOSAL / DESIGN-ONLY / DATA-ONLY / NOT SECURITY-ACCEPTED / NOT RUNTIME AUTHORITY / NO DEPLOYED ROOT HELPER**

Owner: [infrastructure-tools #139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139) and [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96). Supersedes prior proposal text only on merge of a reviewed draft PR; it does **not** authorize privilege, installation, kernel or host policy change, standing services, CI-hosted privileged runners, or treatment of synthetic or parsed JSON as A4 PASS.

**Live design disposition (Nov 7, 2026 ET):** independent read-only challenge `3f12307a-87f0-4dfd-8366-640fc71e0bc7` — **CHANGES_REQUIRED H1/M2/L1**; orchestration record [#139 comment 6704877875](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6704877875). Accepted merged source [#252](https://github.com/LowcountryDigitalWorks/infrastructure-tools/pull/252) (`tools/dragonfly_gate_a4_channel_contract.py`) is a **closed request/response parser only** — strictly `DATA_ONLY_NOT_AUTHORIZED`; it cannot attest a root producer, authenticate a channel, or authorize runtime inspection.

**Pinned production gates (unchanged by this document):** `tools/dragonfly_gate_a0.py` and `tools/dragonfly_gate_a4.py` remain the accepted UID-1000 entrypoints. This contract does not modify their bytes, expectations, or HOLD semantics.

## Source design versus runtime proof

| Layer | What it may establish | What remains **OPEN** until separate acceptance |
| --- | --- | --- |
| **This contract (design)** | Reviewable trust boundaries, failure matrix, sanitized output shape, ordered gates | Any claim that physical REDRIX currently has an accepted privileged inspector |
| **Non-privileged source** (`dragonfly_gate_a4_fd_inspector_core.py`, channel parser, fixtures) | Deterministic `HOLD` / `REFUSE` / `DATA_ONLY_NOT_AUTHORIZED` against synthetic inputs | Root-side collection, live `/proc` completeness, or A4 PASS |
| **Future bounded implementation PR** | Immutable package identity, fail-closed tests, channel binding code **as design** | Host install, sudo, capability grant, or one-shot execution on hardware |
| **Owner/security runtime decision** | — | Exact protected install/rollback, current byte readback, teardown proof |
| **Physical evidence pairing** | — | UID-1000 A4 receipt + privileged readback reconciled under current policy |
| **Downstream JIT** | — | [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52) / [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186) protected V2 publisher, [#10](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/10) GitHub queue/runner admission |

No step above may be skipped by merge order or green CI alone.

## Physical readback context (bounded, not a specification pass)

On physical REDRIX under normal UID 1000, the accepted A4 path has returned **`A4_PROCESS_VISIBILITY_UNCERTAIN`**. Owner-local readback (Nov 2026) observed **three** denied `/proc/<pid>/fd` directory accesses and **seventy-three** `readlink` denials on individual `fd` entries under the same-UID inspection scope. That supports **incomplete enumeration**, not proof that every descriptor is permanently invisible.

**Do not infer causality:** observing `kernel.yama.ptrace_scope=1` (or similar) is **not** proof that `PTRACE_MODE_READ` / fscreds denial was *caused* by Yama alone. Other constraints (dumpability, LSM, mount namespace, capability bounding set in the **target user namespace**, missing `CAP_SYS_PTRACE` effective in that namespace, `/proc` visibility policy) must be measured or attempted readback must fail closed. **No security knob relaxation** is in scope for this design.

## Future Gate A trust architecture (review target, not implemented)

The following is the **minimum** independently reviewable architecture for a **hypothetical** one-shot privileged collector. Nothing here asserts that such a collector exists, is installed, or is callable.

```
  [UID 1000 A4 verifier — existing package, unchanged checks]
            ^
            |  (3) one-shot authenticated channel, same invocation,
            |      created ONLY after (2) passes; receiver-measured
            v
  [Protected fixed launcher — immutable package identity]
            |
            |  (2) verifies bytes/owner/mode/ancestors; refuses
            |      caller-selected command/path/ref
            v
  [Privileged read-only inspector process — separate identity]
            |
            |  (1) proves capability in target user namespace +
            |      successful bounded /proc readback or HOLD
            v
  [Kernel: PID namespace scope, starttime, full FD enumeration]
```

### (1) Capability and actual readback in the target user namespace

A protected inspector **must not** treat effective UID 0, a caller assertion, or root-owned `/proc/<pid>` dentries as proof of complete FD visibility.

Before any positive process/FD claim, the design must require evidence of **all** of the following, measured inside the **same user namespace and PID namespace scope** as the REDRIX workload under review:

- Effective **`CAP_SYS_PTRACE`** (or strictly narrower independently accepted capability set) in that namespace at inspector start, with explicit refusal if ambient/bounding sets or namespace membership differ from the accepted profile.
- Successful application of **`PTRACE_MODE_READ` with fscreds** (or equivalent kernel-validated read path) on each process selected for evidence — not merely the absence of a `ptrace` syscall error on an unrelated probe.
- **`/proc/<pid>/status` dumpability and LSM context** sufficient to explain any denied `fd` readlink: where dumpability is `0` or LSM denies read, the contract classifies **`enumeration_incomplete`** and returns **HOLD**; it does not infer zero KVM FDs.
- **Physical readback success** for every in-scope `fd` entry in both snapshots (below), not extrapolation from partial samples.

Failure of any measurement, ambiguity of namespace membership, or inability to reproduce denial reason without relaxing policy → **HOLD**. Documenting `ptrace_scope` is informational only.

### (2) Fixed immutable package and protected launcher identity

- **One root issuer, one fixed package:** a future Linux implementation must be installed by a separately approved owner-controlled installer into a single fixed absolute protected location (proposed package root `/usr/libexec/ldw-redrix-a4/`). The trusted package consists of the launcher, inspector, and the accepted UID-1000 verifier identity. Each executable/payload digest must be pinned in independently reviewed protected source; a digest supplied by the caller, checkout, environment, or a mutable manifest is not a pin. Until those accepted digests exist, the issuer must refuse every request. This Linux root issuer is a distinct trust domain from the Windows Admin Broker in #186 and inherits none of its authority.
- **Protected ancestry and identity:** before privilege and again at execution, verify the full path from `/` through every ancestor and leaf using descriptor-relative, no-follow traversal. Require root ownership, the independently approved group/mode, regular-file type, expected device/inode and link count, and stable file identity/digest across verification and execution. Reject symlinks, reparse-like indirection, writable ancestors, hard-link surprises, inode/digest drift, and untrusted mount changes. A hash check followed by reopening a pathname is a TOCTOU gap; execute or inspect the already verified object and recheck its identity. Any ambiguity → **HOLD**.
- **Closed invocation:** a fixed launcher accepts no caller-selected executable, script, URL, Git ref, workspace path, interpreter flag, command, argument, or environment override. It must not source shell profiles or use `PATH` dispatch. There is no generic shell or ambient `sudoers` permission; only one exact, no-argument, fixed entrypoint may be considered after separate owner/security acceptance. No alternate entrypoint via remote shell, JIT runner, ChromeOS host agent, or #98 synthetic credential fixture.
- **Separate identity:** the privileged inspector runs outside the UID-1000 A4 process; it must **not** execute unmodified `dragonfly_gate_a4.py` as root or merge its outcome into the UID-1000 receipt.

### (3) Launcher-owned one-shot authenticated channel (post-boundary)

Binding between inspector and UID-1000 verifier is **only** through a channel the **protected launcher** creates **after** package verification and **after** the privilege boundary is entered for that single invocation.

| Mechanism | Design rule |
| --- | --- |
| **`SO_PEERCRED` / `getpeereid`** | Records peer UID/GID/PID at **socket creation or `connect` time**, not proof of which **code image** later wrote bytes. Peer credentials **cannot** alone authenticate the inspector package. |
| **`SCM_CREDENTIALS` / `SCM_RIGHTS`** | Convenient for passing metadata; **not** proof of protected binary provenance. Must not be treated as signing or attestation. |
| **Inherited user-FD spoofing** | A privileged fixed launcher creates a new private channel only after its own accepted package verification and after entering the approved privilege boundary for that invocation. It passes the designated endpoint through a fixed handoff with close-on-exec on every other descriptor; the receiver rejects any preopened/inherited endpoint, duplicate endpoint, unexpected descriptor, or caller-provided `socketpair`. This lifecycle must be enforced by the launcher, not inferred from channel bytes. |
| **Receiver-measured producer identity** | The receiver binds peer credentials (UID/GID/PID) to a live pidfd/starttime and independently measures the peer's executable object, device/inode, exact pinned digest, package ancestry, and relevant namespace identity while the channel is open. It verifies the sender is the accepted issuer/inspector code, not merely UID 0. A peer UID of 0, `SO_PEERCRED`, `SCM_CREDENTIALS`, `SCM_RIGHTS`, a signature field, or a sender assertion alone is insufficient. If the kernel cannot expose or stabilize the identity evidence, **HOLD**. |
| **Freshness and replay** | The privileged launcher generates an unpredictable one-shot nonce after crossing the approved privilege boundary, binds it to a unique invocation/correlation, and enforces a short monotonic TTL, strictly increasing snapshot sequence, and atomic single-consumption record. Repeated nonce, duplicate message, stale/expired request, cross-invocation correlation, or sequence rollback → **HOLD**. Synthetic nonces and in-memory replay fixtures exercise parser behavior only; they never prove entropy, protected storage, channel ownership, or issuer identity. |
| **`root=true` / `signature=true` fields** | JSON or channel metadata carrying these flags without receiver-measured authentication → **HOLD**; never A4 PASS. |

Channel design is **independent** of the merged non-authorizing parser: the parser may classify malformed envelopes; only a future receiver implementation paired with a reviewed runtime may authenticate.

The source-only contract deliberately specifies the trust obligations without shipping a root helper or treating a Python model as the issuer. The channel parser and every synthetic positive response remain **`DATA_ONLY_NOT_AUTHORIZED`**, with `privilegedChannelAuthenticated=false`, `a4Pass=false`, and `runtimeAuthority=false`. No passing offline test can close the separate owner/security gate for exact root installation, issuer and payload pins, channel lifecycle, rollback, capability/LSM policy, or physical full-FD readback.

### (4) Process scope, PID identity, and non-atomic two-snapshot enumeration

Two snapshots are **not** one atomic kernel transaction. The design must fail closed on churn, races, and namespace ambiguity.

- **Scope declaration:** explicitly bind the **user, PID, and mount namespace** for Crostini/Termina REDRIX. The live evidence candidate must read all three namespace identities for itself and PID 1 and require equality; it must also require every in-scope UID-1000 process to match that same triple. A missing, denied, malformed, or mismatched namespace link → **HOLD**. Network namespace is also part of the owner-reviewed scope if the deployment's `/proc` or workload isolation depends on it. Enumeration covers **all processes required by accepted A0/A4 same-UID policy** at minimum, and may not **narrow** below that without independent acceptance.
- **Per-process identity:** bind each observation to **`pid` + `starttime`** (from `/proc/<pid>/stat`) and full **Uid:** quartet from `/proc/<pid>/status`. Where the platform supports **`pidfd_open`**, use it to re-validate identity across snapshots; on identity change or `ESRCH`, **HOLD**.
- **FD enumeration:** for each in-scope process, list **every** entry under `/proc/<pid>/fd` in snapshot A and snapshot B; classify each slot as readable symlink, denied, or missing. Partial list → **HOLD** (extends physical **A4-FD-06**).
- **Drift rules:** new KVM or QEMU-associated FD/process between snapshots; FD count change without matching identity stability; process exit/reuse with same PID but different `starttime` → **HOLD** (**A4-FD-07**).
- **`pidfd_getfd`:** explicitly **out of scope** as a shortcut. It duplicates FDs across processes and implies stronger privilege than read-only `/proc` enumeration; any design that depends on it requires a **separate** security review and is not assumed here.

Snapshot A and B must bind to **one** current UID-1000 A4 readback correlation (**A4-FD-09**).

### (5) Bounded sanitized durable output

Durable artifacts and cross-system logs may include only **allowlisted aggregates**, for example:

- Protocol/version and fixed package identity digests (accepted hashes only).
- Fresh operation nonce id (opaque token, not replayable secret material).
- Snapshot pair id, monotonic bounds, and **counts** of processes, denied `fd` dirs, denied readlinks, KVM-tagged FD hits, QEMU-named processes.
- Per-process **opaque stable keys** derived from `(starttime, namespace id)` — **not** raw argv, environ, socket paths, SSH endpoints, or full command lines.
- Terminal classification: `HOLD` reason code from the matrix below; never raw `/proc` paths, secrets, or credential material.

The merged channel contract’s synthetic fields are **not** this wire format and never imply sanitized live output exists.

### (6) Negative and acceptance matrix (extend, do not duplicate)

Existing rows **A4-FD-01** … **A4-FD-15** remain mandatory. The following **extend** them for the refined architecture (same IDs where the condition is unchanged; new IDs only where the adversary is distinct).

| ID | Condition | Mandatory result |
| --- | --- | --- |
| A4-FD-01 | No accepted privileged inspector/channel/runtime install | **HOLD**; UID 1000 cannot manufacture trusted evidence |
| A4-FD-02 | Caller supplies executable, path, URL, ref, PID list, FD list, or privilege hint | **REFUSE** before privileged boundary |
| A4-FD-03 | Root or non-1000 invokes unmodified UID-1000 `dragonfly_gate_a4.py` or spoofs home/UID | Existing identity check **REFUSE** |
| A4-FD-04 | Forged, copied, replayed, or parser-only `zero KVM` narrative | **HOLD** |
| A4-FD-05 | Inspector/launcher package, blob, owner, mode, ancestor, or symlink drift | **HOLD** before invocation |
| A4-FD-06 | Missing `/proc` entry, denied `/proc/<pid>/fd`, unreadable link/stat/UID field | **HOLD**; zero not inferred |
| A4-FD-07 | PID reuse, exit, or `starttime` change between snapshots | **HOLD** |
| A4-FD-08 | `/dev/kvm` FD or QEMU process in either snapshot | **HOLD** |
| A4-FD-09 | Snapshots not bound to one current UID-1000 A4 readback | **HOLD** |
| A4-FD-10 | Nonce/correlation stale, duplicated, or non-monotonic | **HOLD** |
| A4-FD-11 | User-controlled channel, unexpected peer, or missing receiver-measured producer identity | **HOLD** |
| A4-FD-12 | Synthetic clean complete stable zero-KVM fixture (incl. parser round-trip) | **`DATA_ONLY_NOT_AUTHORIZED`** only |
| A4-FD-13 | A4 receipt, SSH/Tailscale, or pinned A0/A4 source check fails | **HOLD** regardless of inspector story |
| A4-FD-14 | Inspector “success” without V2/queue/#10 admission | No JIT/runner/dispatch promotion |
| A4-FD-15 | Inspector unavailable, timeout, transport error | **HOLD**; no `pgrep`/weaker fallback |
| A4-FD-16 | Effective `CAP_SYS_PTRACE` absent in target user namespace | **HOLD** before enumeration |
| A4-FD-17 | `PTRACE_MODE_READ` / fscreds path not demonstrated per process | **HOLD**; `ptrace_scope` alone insufficient |
| A4-FD-18 | Dumpability/LSM prevents complete `fd` readback | **HOLD** (`enumeration_incomplete`) |
| A4-FD-19 | PID namespace scope ambiguous or differs between snapshots | **HOLD** |
| A4-FD-20 | `pidfd` identity recheck fails or unsupported without accepted alternate | **HOLD** |
| A4-FD-21 | Verifier accepts caller-supplied socket FD or inherited spoofed channel | **REFUSE** / **HOLD** |
| A4-FD-22 | `SCM_CREDENTIALS` or peer UID 0 presented as package proof | **HOLD** |
| A4-FD-23 | Reliance on `pidfd_getfd` without separate accepted review | **REFUSE** in this contract |
| A4-FD-24 | Channel parser classifies envelope as well-formed | Still **`DATA_ONLY_NOT_AUTHORIZED`** until physical pairing gate |

Tests (future implementation) must assert **terminal classifications**, not string presence of `PASS`.

## Ordered gates, rollback, and explicit OPEN security decisions

1. **This design contract** — influence-clean architecture/security review; revise or reject. **No runtime claim.**
2. **Bounded source candidate** — immutable launcher/inspector **source**, channel binding, deterministic matrix tests; **no** system install, **no** standing service, **no** privileged CI runner, **no** ChromeOS or memory-reserve change (2 GiB guest + 8 GiB host reserve unchanged).
3. **Independent owner/security runtime approval** — explicit authority for exact install, on-shot execution, and **rollback** with current byte verification; #98 synthetic sudo history is **not** reusable permission.
4. **Physical REDRIX pairing** — one owner-authorized secretless privileged read paired with untouched UID-1000 A4; reconcile or **HOLD**. Prior owner-authorized Gate B remains **UNCONSUMED** until explicitly exercised under this sequence.
5. **JIT publication chain** — #52/#186 V2, #10 queue, then at most one #139 canary; teardown independently proven.

**Rollback (design-only):** close draft PR without merge — no deployed state. Future install must document fail-closed uninstall with no lingering unit, credential, listener, or widened sudoers.

## Related source (read-only cross-reference)

- UID-1000 FD core (synthetic): [`REDRIX_A4_FD_INSPECTOR_CORE.md`](REDRIX_A4_FD_INSPECTOR_CORE.md) — does not replace A0/A4.
- Merged channel **parser** (DATA_ONLY): `tools/dragonfly_gate_a4_channel_contract.py` — no root attestation.
- Adversarial feasibility: [#139 comment 6676287868](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139#issuecomment-6676287868).

References: [#139](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/139), [#96](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/96), [#115](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/115), [#10](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/10), [#52](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/52), [#186](https://github.com/LowcountryDigitalWorks/infrastructure-tools/issues/186).


## Live bounded kernel evidence module — candidate source, not accepted privilege (Nov 8, 2026)

This candidate adds `tools/dragonfly_gate_a4_live_evidence.py` and
`tests/dragonfly-canary-publication/test_gate_a4_live_evidence.py`. The
module has **no CLI, launcher, sudo call, setter, service, network
connection, or permission mutation**. Its public `collect_live_evidence()`
has no input paths or arbitrary invocation parameters and references only
fixed Linux `/proc`. It **always** returns `a4Pass=false`,
`runtimeAuthority=false`, and `jitAdmissionAuthorized=false`,
including when full kernel readback is technically successful. It does not
create a valid issuer, protected channel, runtime A4 proof or canary.

The bounded source candidate specifically requires:
- An actually executing effective UID 0 **plus both effective and bounded**
  `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`; UID 0 by itself fails.
- Equality of current process and PID1 **user and PID namespaces**;
  every UID-1000-associated process in the snapshot must match.
- Exactly two full snapshots of the bounded numeric `/proc` PID set,
  paired with `pidfd_open` held until both passes finish, with nonblocking
  pidfd liveness checks and repeated PID/starttime/four-UID identity checks.
- The kernel-mediated `/proc/PID/exe` and **every** `/proc/PID/fd/N`
  `readlink` call to actually succeed for the selected process scope.
  Denied links and exited/reused PIDs yield `HOLD`, never a zero-FD
  claim. This uses read-only readlink permissions (read-fscreds kernel
  check), **not** `pidfd_getfd`, ptrace attach or modified sysctls.
- An unchanged PID/FD identity set, no observed QEMU process or
  `/dev/kvm` FD, no more than 4,096 processes/4,096 per-process FDs,
  and a max six-second paired capture. Any race or ambiguity yields
  sanitized `HOLD`; result outputs aggregate counts only, no PIDs,
  network addresses, argv, environment, FD targets or credential bytes.

These checks are a **source-only candidate to address the H1/M2 design
questions**, not an accepted runtime design. The closed-code provenance,
first installation via a separately controlled trusted issuer, immutable
launcher/process identity, one-time authenticated channel, A0/A4 receipt
pairing, broader arbitrary-comm QEMU evasion resistance, and protected
rollback are still OPEN under #52/#186/#139. A source test or a root
invocation of this module may **not** promote its DATA_ONLY result to PASS.
Any verification of actual device behavior requires a separately accepted,
source-pinned, protected installer and complete independent review.

There is no memory admission change: the accepted production nested-guest
2 GiB + 8 GiB Crostini-visible reserve remains. Eddie's repeatedly
observed ChromeOS-host available memory of 17–20 GiB is a separate ledger
and must never be misdiagnosed as physical host exhaustion by the
Crostini-only observation.
