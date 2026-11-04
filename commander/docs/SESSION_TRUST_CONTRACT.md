# LDW Commander — Gate A Session Trust Contract (REVIEW CANDIDATE)

Status: PROPOSED / SOURCE-ONLY / INDEPENDENT SECURITY REVIEW REQUIRED
Issue: infrastructure-tools #209
Owner goal: first-party Desktop Commander replacement with **real Administrator/root capabilities** across expressly enrolled owner-controlled hosts, accessible from ordinary ChatGPT Chat and local CLI, no Work or GitHub runtime bus, no per-operation UAC, and no third-party Desktop Commander usage/quota.

This proposal does **not** grant a ChatGPT model independent authority to become Administrator/root merely by asking. It enables a powerful, short-lived, revocable **owner-authorized session**, not a permanent unauthenticated remote shell.

## 1. Distinct authority planes

- **LDW Host Agent:** host visibility and normal-user lifecycle. It does not interpret arbitrary privileged commands.
- **Existing Admin Broker (#52/#176/#185/#186):** sealed catalog of reviewed typed operations, already capable of a UAC-free elevated proof. Its protected interface remains unchanged.
- **New LDW Commander Agent (this contract):** separate protected per-host service for arbitrary terminal/files/process/service work after a session grant; never reuse the existing Hyper-V SYSTEM observer, CI/JIT protected worker or fixed-operation Admin Broker as a generic shell.
- **LDW Commander Session Authority:** validates authenticated owner/delegated operator policy and issues short-lived, host- and privilege-bound capabilities. It is not an LLM, a chat transcript, a mutable GitHub comment or a bearer passed as a chat parameter.
- **LDW Commander CLI:** local owner-side operator that does not depend on ChatGPT, Cloudflare, GitHub or third-party Desktop Commander.
- **Normal ChatGPT Chat plugin/connector:** a convenience control surface that sends bounded session operation requests through a supported authenticated private connector. Plugin availability, write approvals and actual chat-plan support must be proven; tool invocation is not privilege authority.

One canonical operation/session state per host. No second independent session broker, duplicated queue or global static admin credential.

## 2. Trust roots and enrollment

Each host must be paired independently with owner presence or an already accepted trusted enrollment proof. Enrollment records are protected locally; each binds an immutable host identifier, OS platform, pinned host public key/certificate, accepted Commander agent binary/package digest, allowed owner/operator identities, revocation epoch and expiry/rotation policy.

Do not treat a hostname, IP, Tailscale peer name, LAN presence or command-line requested target as sufficient host authentication. Pairing credentials must be per-host, not one wildcard key that compromises all machines.

Preferred transport is mutually authenticated, encrypted and private (e.g. approved overlay network or outbound authenticated relay) with pinned endpoints and separately rotated connection identities. No default public management port, unauthenticated inbound listener, copied SSH private key or raw Windows admin password in the model context.

An off-site host that cannot presently be reached returns HOST_UNAVAILABLE. The rest of the fleet must not inherit its authority or fall back to an unauthenticated transport. REDRIX/Dragonfly host enrollment remains HW&VM ORCH-owned and cannot alter its reviewed #98/#192 controls as a side effect.

## 3. Three privilege envelopes

- OBSERVE: read host status, approved process and file metadata. Never implies arbitrary secret reads.
- MAINTAIN: only owner-delegated recurring maintenance categories with reviewed operation policy and bounded parameters. May be auto-issued for already-approved LDW tasks without Eddie clicking UAC.
- FULL_ADMIN: intentionally supports arbitrary owner-authorized Windows Administrator / Linux root terminal and associated file/process/service operations **within one accepted short-lived session**. Broad capability is an explicit feature, not a fixed-command-only substitute. Requesting FULL_ADMIN is a separate high-trust policy action, not inferred from general chat authority.

A session grant is minted by the protected Session Authority **only after verification of a separately authenticated owner decision record or an existing signed scoped delegation**. A chat message, prompt, GitHub comment, browser page, relay tool call or role label is never owner consent. Routine pre-authorized MAINTAIN operations do not require Eddie on each action; novel destructive, customer, identity/MFA, billing, legal, DNS, public-exposure, production/risk or recovery actions preserve their existing gates. A FULL_ADMIN grant does not erase those per-action risk gates.

### Gate A1 — independently authenticated owner decision and issuance (fixes independent M1)

1. The owner decision is captured in a **separate trusted local authorization UI/CLI**, not by an agent reading a chat transcript or a checkbox in tool arguments. The trusted flow authenticates the owner with existing accepted OS/device-bound identity (a concrete platform-backed authentication decision, optionally local presence). A model can request authorization but cannot satisfy it or generate its signature.
2. The authorization is a **signed canonical decision record** binding operator identity, issuer/key generation, immutable host identity and enrolled host key, approved privilege, decision type (one-time FULL_ADMIN or narrowly delegated MAINTAIN), approved command/activity class or exact batch digest, allowed sensitive-data/network/egress classes, unique nonce, issue/expiry times, absolute duration, maximum commands and the recorded human-visible risk wording. A signed MAINTAIN delegation must explicitly enumerate reviewed classes, parameters, host and lifetime; "owner broadly approves everything" is not a standing unrestricted delegated policy.
3. The protected issuer verifies the independent signer/public trust root, identity, scope, nonce uniqueness, version, TTL and current revocation epoch **before** minting the host-audience grant. The host agent independently verifies the resulting grant, its decision-record digest and its *local protected policy* on every command; there is no optional trust in the chat plugin or relay.
4. An **unrestricted FULL_ADMIN shell** can be opened only with a fresh, owner-authenticated risk acceptance for the exact named host/session. Within that accepted session, arbitrary commands are functionally possible, but genuinely new consequential intents or egress/sensitive-data classes beyond the signed session decision need a **new out-of-model signed decision**. A batch explicitly accepted in that signed decision can run without repeated UAC or repetitive approval for every command.
5. If an owner decision is absent, forged, stale, replayed, broadened, from a wrong host, from a model/tool argument or revoked, the result is `OWNER_AUTH_NOT_PROVEN`; no FULL_ADMIN session opens and no degraded implicit alternative is allowed.

**Required negative proof:** a forged "Eddie approved" text inside Slack, a repository file, an MCP tool argument or a browser page must not mint FULL_ADMIN; an already accepted MAINTAIN grant must not widen to FULL_ADMIN or a different host; a new destructive command outside an accepted FULL_ADMIN decision scope must be refused pending fresh trusted consent. Distinguish one-time owner decision from a durable delegated maintenance policy so already accepted routine tasks remain UAC-free.

The existing Windows protected helper cannot be silently repurposed or modified to accept arbitrary commands. Design and install a distinct, independently reviewed privileged implementation.

## 4. Session grant and lifecycle

A grant binds, at minimum:
- issuer identity and revocation epoch;
- authenticated operator identity and concrete delegated authority reference;
- exact enrolled host key/fingerprint, OS and local protected agent instance;
- unique session UUID, per-command correlation and anti-replay nonce sequence;
- fixed privilege envelope, maximum session duration and absolute expiry;
- concurrency and rate/bandwidth budget;
- explicit audit/sensitive-output classification policy;
- revocation/stop contact and rollback/resume conditions.

The protected host agent independently checks signature/MAC, audience, clock window, local authorization policy and current revocation epoch on **every** command, even after a session was opened. The remote transport/controller must not be trusted to validate its own grant.

Proposed initial bounds for an isolated synthetic canary: at most one FULL_ADMIN session per host, at most 5 minutes, at most one active command in that session, bounded streams, and no renewal. These are candidate limits for security review, not arbitrary permanent product limits.

Grant expiry, revocation, disconnect or conflicting session MUST refuse new commands and trigger host-owned process containment/drain verification. A mere shell exit or command timeout is not completion: enforce and inspect descendants, services and scheduled jobs as described in Gate A3 below. Block new privileged grants until the host proves the previous session clean or enters quarantine. Do not claim irreversible system mutations can always be undone or call a forced kill a graceful rollback.

## 5. Real operations inside the admitted session

The Commander is intended to expose:
- typed host/session enumeration, open, inspect, revoke and close;
- interactive or one-shot command execution with bounded stdin/stdout/stderr and exit-state correlation;
- constrained file read/write/edit/search and hash-verified transfers (path restrictions depend on admitted privilege envelope);
- processes, services, system health and owner-authorized machine maintenance;
- optional OS GUI interaction later as a separately reviewed adapter.

FULL_ADMIN means the operator can request arbitrary administrative commands **after** receiving the FULL_ADMIN grant. Do not reduce this to a fixed allowlist of strings. The guardrail is session authorization, target/issuer identity, bounded duration, collision control, audit and owner policy.

However, a model can be induced by untrusted page/tool/agent text to issue a dangerous command. Any command offered by a ChatGPT model is an untrusted proposal until the owner/delegated action policy permits it. Model-driven full-admin use requires a reviewed confirmation/allowance policy for high-impact targets and cannot silently override existing consequential gates.

A command that timed out or lost connection has an AMBIGUOUS execution result, not safe-to-retry. No automatic replay of a potentially mutating shell command. Each command uses a single unique idempotency identity with protected local readback. The command admission gate matches the signed owner activity/egress class **before** a command starts; never infer safety from its stdout, exit code or model rationale.

## 6. Secret and sensitive-output boundary

No reusable privileged credential, private key or administrator password is returned through model-visible tools, command arguments, GitHub, chat logs or unencrypted file output.

Arbitrary Administrator/root commands **can** read private secrets and send them to stdout; pattern-based redaction cannot guarantee their safety. Therefore:
- run initial live tests on disposable/synthetic isolated systems with no owner/customer credentials in reach;
- classify output before model exposure; refuse output or return a sanitized summary for protected-data locations;
- use per-host protected audit and short retention under the existing approved information-placement policy;
- treat raw shell output from untrusted programs/web pages as data, never as authorization instructions.

A command that itself exports files/secrets or changes a production system is still consequential. Explicit owner/accepted delegated authority and appropriate data boundary apply even inside a full-admin session.

### Gate A2 — pre-execution data/egress authorization (fixes independent M2)

- The host's **protected admission service** classifies each proposed command (including arguments, execution context, file targets, child-process/network capability and requested outbound destination) against the signed owner decision and protected local allow/deny policy *before* privileged execution. A chat model's classification or "safe" label is untrusted. A command that is impossible to classify reliably is `UNKNOWN_HIGH_RISK` and is refused unless the owner freshly authorized its full blast radius.
- First live proof runs on a **disposable, secret-free host/VM image with external egress blocked outside the command process's authority** and no real credentials, customer data, host SSH keys or connected production mounts. Deny network, outbound file transfers and sensitive path reads by default; only a named test fixture and fixed harmless canary may be accessed.
- Concrete **negative acceptance test**: proposed admin command attempting to read a synthetic secret fixture and send it via curl/HTTP/DNS (or encoded variant) is refused **before process start**, with a redacted denial record and no outbound packet/file copy. Test direct commands and delegated child-process attempt. An exfiltration test that merely hides stdout is a failure.
- On an actual owner machine, **full host Administrator/root can alter firewall policy, read protected files, launch services or egress through other processes**. A same-privilege pre-command parser, stdout redactor or environment variable restriction **cannot guarantee confinement** of arbitrary FULL_ADMIN. If no stronger OS/hypervisor boundary exists, require the owner to explicitly accept the named host/session's *unrestricted* egress/secrets risk, or refuse live FULL_ADMIN and use a disposable isolated VM or a narrower MAINTAIN operation. Never advertise complete exfil prevention on an unrestricted production root/admin shell.
- For allowed operations, use enforcement outside the process privilege boundary where possible (dedicated network namespace/host firewalls on a separate trusted control plane, private overlay policy, no production mounts). The first privileged proof must verify **actual network denial**, not merely an expected policy string. Persist only minimal security audit results in approved protected local state; do not capture synthetic secret content into chat/GitHub.

### Gate A3 — privileged descendants, session drainage and quarantine (fixes independent M3)

- The privileged host agent creates a protected **per-session process containment identity**. Windows uses a non-breakaway Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, verifies direct child and descendant membership, denies unapproved service/Task Scheduler creation and audits child handles. Linux uses a protected cgroup v2/systemd scope or proven equivalent with process-group tracking, kill/drain of all descendants, and no escape from the session boundary by an untrusted command.
- On expiry, revoke, disconnect or owner stop: stop admitting commands; signal/drain all tracked descendants; read back process count, job/scope identity, services/jobs and any file/side-effect ledger; then mark terminal `DRAINED_VERIFIED` **only if** no privileged descendants or detached jobs remain. A child still alive, missing audit/agent, unknown detached service or failed cleanup is `AMBIGUOUS_PRIVILEGED_RESIDUE`, not PASS.
- An ambiguous/failed drain puts that host in **QUARANTINED** and rejects new FULL_ADMIN sessions; a separate trusted owner recovery or independently accepted repair step must inspect the affected processes/services and restore a verified clean state. No blind retry or silent reap that hides evidence.
- **Hard limit:** unrestricted root/Administrator on a normal host can intentionally evade OS containment or create durable services. These protections are provable for the **restricted canary workload**. Broad non-bypassable containment requires a stronger isolation boundary (e.g. a disposable VM/microVM) outside the privileged workload's authority, or an explicit owner risk acceptance; do not promise otherwise.
- Required tests: canary spawns a child then expires; child must be demonstrably gone and host verified clean; deliberate disconnected/failed-drain case must become QUARANTINED; Windows Job Object breakout/service creation and Linux daemon/cgroup escape attempts must be rejected or explicitly reported UNCONTAINED. Persistence outside the process graph is a separately documented recovery/owner gate.

### Gate A4 — issuer key rotation and clock recovery (fixes independent L1)

- Issuer private signing key is generated/stored only in an approved protected OS/TPM-backed key store; signed public verification keys are pinned by enrolled host with issuer/key ID, validity and rotation generation. No plaintext shared signing secret on the host; no issuer private key in a ChatGPT plugin or agent.
- The agent keeps a **protected monotonic revocation epoch and command nonce journal** with atomic integrity-checked updates, independent from the untrusted chat/relay. A failed journal write, state rollback, cloned node or stale enrolled host key fails closed.
- Require a monotonic local time source where available and **at most 30 seconds** measured wall-clock skew versus a trusted signed time authority. A detected wall-clock rollback, failed attestation, time-source uncertainty or expired signer key means `CLOCK_UNTRUSTED` / no session or command until authenticated time reconciliation.
- Rotate: stage next pinned issuer public key with owner-authenticated policy, increment protected generation/epoch, confirm exact host readback, only then retire old verifier and revoke old grants. Compromise: freeze new sessions, revoke epoch, quarantine affected hosts, re-enroll with out-of-band owner trust, rotate signing and transport keys independently, and require negative tests proving old grants fail even after restart or key rollback.
- A bootstrap/demo may generate ephemeral software-only signing keys **only on a disposable synthetic host**. It is not evidence of production key recovery, secure clock, or physical owner presence.

## 7. Failure and attacker matrix

| Attack / failure | Required property |
| --- | --- |
| Prompt injection in webpage, repository, Slack or mailbox | Untrusted text cannot mint a privileged grant |
| Forged source ChatGPT role or tool argument | No session without cryptographically authenticated delegated operator |
| Stolen one-host key or session token | Cannot administer another host; revoke host epoch locally |
| Replayed grant/command | Single-use nonce and command ID; duplicate returns existing result only |
| Stale/granted-but-revoked session | Agent revalidates every command, refuses after revocation |
| ChatGPT/relay/provider outage | Local CLI remains usable with separate locally accepted trust path |
| Owner host offline or role mismatched | HOST_UNAVAILABLE / IDENTITY_MISMATCH, no guessed alias fallback |
| Process still running after timeout | AMBIGUOUS / track and drain or report unresolved; no false success |
| Separate sessions race on service/files | One writer/host or explicit lock; deny untracked conflict |
| Captured admin stdout contains credentials | Output blocked/sanitized; never emitted raw by default |
| Prompt-injection claims owner consent or widens a delegated scope | No out-of-model signed decision: OWNER_AUTH_NOT_PROVEN, no admin grant |
| Privileged command calls DNS/HTTP to leak fixture secrets | Host pre-admission denies before execution + external egress boundary blocks packets |
| Detached privileged child survives revocation/disconnect | Host QUARANTINED until descendant/job/service drain is independently verified |
| Issuer signer key compromised, clock rolled back, or epoch journal missing | Freeze sessions and require trusted owner recovery/re-enrollment |
| Malicious local normal-user process | Cannot modify protected agent, trust root, credential store or privileged policy |
| Revoked node later reappears | Re-enrollment required; no replayed enrollment with same stale key |
| Failed install/upgrade | Exact artifact provenance and rollback, no unrelated host/service mutation |

## 8. Trust-plan independence

No GitHub API, GitHub issue, or Actions schedule is needed for routine command delivery. GitHub can remain version-control history for reviewed source. No ChatGPT Work-mode sessions or Desktop Commander calls should be needed for first-party operational requests after the plugin/tool channel is accepted.

The custom ChatGPT plugin/MCP write-action and idle-chat wake capabilities are **provider-/plan-gated**. Source-level Commander availability must not be misrepresented as guaranteed capability from every ChatGPT account or arbitrary ChatGPT conversation. Keep the CLI and private host control functional when the plugin is unavailable.

## 9. Separate implementation and acceptance gates

**Gate A — architecture:** this contract and an independent security/architecture challenge, including threat-model findings and a frozen trust decision. The GM17 author is not eligible to terminally accept its own design.

**Gate B — synthetic user-mode source:** a stand-alone disposable local CLI + session state machine and harmless file/process/command proof, with protected identity, expiry/revoke/replay/collision tests. Also require fake-owner-consent refusal, unapproved command/network-exfil refusal **before spawn**, forged issuer, epoch/clock rollback, expired grant, and child-process revoke/drain/quarantine demonstrations. It must not install a privileged service or claim protected production isolation. Current #215/#217 source tests do not yet satisfy all of these new Gate B requirements.

**Gate C — Windows protected proof:** new reviewed protected service/session helper installed only under a separate consequential owner/security gate, authorized FULL_ADMIN on an isolated **secret-free disposable Windows target**, one harmless elevated command with identity readback, verified non-breakaway Job Object descendants, owner-signed session scope, bounded external egress and clean revoke/drain/quarantine behavior, no per-command UAC and no external remote-control dependency. Do not install on the owner's production workstation merely because a synthetic source PR passes.

**Gate D — Linux protected proof:** distinct OS-specific root-capable source and disposable **secret-free** proof with protected cgroup/process drain, network-egress denial, clock/revocation recovery and quarantine negative cases; preserve ChromeOS verified boot, owner login and existing REDRIX isolation boundaries. No assumption that ChromeOS penguin containers can safely prove root host control.

**Gate E — normal ChatGPT Chat connector:** two separately enrolled hosts reachable from an actually supported private plugin/tool connection in ordinary Chat mode; verify authenticated command/result and account/plan controls without Work or Desktop Commander. Must still work locally through CLI during remote outage.

**Gate F — recovery and real-use acceptance:** one eligible file edit, one process/service action and one harmless elevated command on each accepted target; confirm auditable session close, expiry refusal, offline/revocation behavior, failover without wildcard credentials, rollback and no surprise restart, no customer/regulated data or additional variable spend.

## Decision requested from independent reviewer

Choose whether FULL_ADMIN session authority can be introduced alongside the existing typed Admin Broker without giving a general chat prompt privileged control. Challenge the grant issuer, owner delegation, host trust roots, role spoofing, local process compromise, secret-output boundary, revocation and no-owner-relay assumptions.

This file is a **proposal**, not accepted privilege policy, implementation code, service deployment or permission to change provider/security settings. $0 incremental; real production session issuance remains gated.
