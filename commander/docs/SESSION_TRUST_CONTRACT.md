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

A session grant is minted by a protected Session Authority using an accepted owner-backed policy or a fresh owner consent step for previously unapproved consequential work. The request body from a ChatGPT model is **not** itself approval. Routine pre-authorized maintenance does not require Eddie on each action; novel destructive, customer, identity/MFA, billing, legal, DNS, public-exposure, production/risk or recovery actions preserve their existing decision gates.

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

Grant expiry, revocation, disconnect or conflicting session MUST refuse new commands. An already-started process may require an OS-specific job-object/process-group termination or explicit typed drain. Do not claim an irreversible system mutation can always be undone, and do not call a forced kill a graceful rollback.

## 5. Real operations inside the admitted session

The Commander is intended to expose:
- typed host/session enumeration, open, inspect, revoke and close;
- interactive or one-shot command execution with bounded stdin/stdout/stderr and exit-state correlation;
- constrained file read/write/edit/search and hash-verified transfers (path restrictions depend on admitted privilege envelope);
- processes, services, system health and owner-authorized machine maintenance;
- optional OS GUI interaction later as a separately reviewed adapter.

FULL_ADMIN means the operator can request arbitrary administrative commands **after** receiving the FULL_ADMIN grant. Do not reduce this to a fixed allowlist of strings. The guardrail is session authorization, target/issuer identity, bounded duration, collision control, audit and owner policy.

However, a model can be induced by untrusted page/tool/agent text to issue a dangerous command. Any command offered by a ChatGPT model is an untrusted proposal until the owner/delegated action policy permits it. Model-driven full-admin use requires a reviewed confirmation/allowance policy for high-impact targets and cannot silently override existing consequential gates.

A command that timed out or lost connection has an AMBIGUOUS execution result, not safe-to-retry. No automatic replay of a potentially mutating shell command. Each command uses a single unique idempotency identity with protected local readback.

## 6. Secret and sensitive-output boundary

No reusable privileged credential, private key or administrator password is returned through model-visible tools, command arguments, GitHub, chat logs or unencrypted file output.

Arbitrary Administrator/root commands **can** read private secrets and send them to stdout; pattern-based redaction cannot guarantee their safety. Therefore:
- run initial live tests on disposable/synthetic isolated systems with no owner/customer credentials in reach;
- classify output before model exposure; refuse output or return a sanitized summary for protected-data locations;
- use per-host protected audit and short retention under the existing approved information-placement policy;
- treat raw shell output from untrusted programs/web pages as data, never as authorization instructions.

A command that itself exports files/secrets or changes a production system is still consequential. Explicit owner/accepted delegated authority and appropriate data boundary apply even inside a full-admin session.

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
| Malicious local normal-user process | Cannot modify protected agent, trust root, credential store or privileged policy |
| Revoked node later reappears | Re-enrollment required; no replayed enrollment with same stale key |
| Failed install/upgrade | Exact artifact provenance and rollback, no unrelated host/service mutation |

## 8. Trust-plan independence

No GitHub API, GitHub issue, or Actions schedule is needed for routine command delivery. GitHub can remain version-control history for reviewed source. No ChatGPT Work-mode sessions or Desktop Commander calls should be needed for first-party operational requests after the plugin/tool channel is accepted.

The custom ChatGPT plugin/MCP write-action and idle-chat wake capabilities are **provider-/plan-gated**. Source-level Commander availability must not be misrepresented as guaranteed capability from every ChatGPT account or arbitrary ChatGPT conversation. Keep the CLI and private host control functional when the plugin is unavailable.

## 9. Separate implementation and acceptance gates

**Gate A — architecture:** this contract and an independent security/architecture challenge, including threat-model findings and a frozen trust decision. The GM17 author is not eligible to terminally accept its own design.

**Gate B — synthetic user-mode source:** a stand-alone disposable local CLI + session state machine and harmless file/process/command proof, with protected identity, expiry/revoke/replay/collision tests. It must not install a privileged service.

**Gate C — Windows protected proof:** new reviewed protected service/session helper installed only under a separate consequential owner/security gate, authorized FULL_ADMIN on an isolated owner-controlled Windows target, one harmless elevated command with identity readback and clean revoke, no per-command UAC and no external remote-control dependency.

**Gate D — Linux protected proof:** distinct OS-specific root-capable source and disposable proof; preserve ChromeOS verified boot, owner login and existing REDRIX isolation boundaries.

**Gate E — normal ChatGPT Chat connector:** two separately enrolled hosts reachable from an actually supported private plugin/tool connection in ordinary Chat mode; verify authenticated command/result and account/plan controls without Work or Desktop Commander. Must still work locally through CLI during remote outage.

**Gate F — recovery and real-use acceptance:** one eligible file edit, one process/service action and one harmless elevated command on each accepted target; confirm auditable session close, expiry refusal, offline/revocation behavior, failover without wildcard credentials, rollback and no surprise restart, no customer/regulated data or additional variable spend.

## Decision requested from independent reviewer

Choose whether FULL_ADMIN session authority can be introduced alongside the existing typed Admin Broker without giving a general chat prompt privileged control. Challenge the grant issuer, owner delegation, host trust roots, role spoofing, local process compromise, secret-output boundary, revocation and no-owner-relay assumptions.

This file is a **proposal**, not accepted privilege policy, implementation code, service deployment or permission to change provider/security settings. $0 incremental; real production session issuance remains gated.
