# LDW Commander — host-side session restart and quarantine proof

**SYNTHETIC ONLY.** Owning product: infrastructure-tools #209. This is a separate source-only Gate B proof extending the **accepted actual-main foundation**: Gate A design PR #214, signed session + issuer journal PR #237 and the disposable file/process proof PR #217 (merge `220c6e1b20f99eaf0de0a3e08ed3952d0e3147ca`). It does not install an Agent, use root/Administrator, connect to ChatGPT, or create remote access.

## Added semantics

The issuer's approval journal and the host's session journal answer different questions:

- **Issuer approval journal (accepted main via PR #237):** was a particular signed owner decision already consumed to mint a session grant? One atomic single-use approval record prevents a fresh grant from the same decision across concurrent issuers or restart.
- **Host session journal (this proof):** was a particular signed session grant already admitted on this host, and can its previous session be positively accounted for? A second use of its immutable session UUID fails `HOST_SESSION_REPLAY`, including after agent restart. A previous OPEN session without verified cleanup makes a newly started agent report `HOST_QUARANTINED` and refuse all new sessions.

The new `HostSessionJournal` is a **separate, private, disposable SQLite store** with one-time trusted test initialization; the normal host process cannot create a missing ledger during restart. `BEGIN IMMEDIATE` with unique session IDs serializes cross-process reservations. Any missing, corrupt, inaccessible or ambiguously updated journal refuses new sessions. The journal's only terminal state is `REVOKED_VERIFIED`, and it is set solely by the synthetic zero-OS-process revoke method; no remote/model-facing reset/recovery tool exists.

`JournalBoundSyntheticAgent` is a **new opt-in proof subclass**; this branch does not modify existing approved Host Agent, Admin Broker, or deployed LDW Commander (none exists). It inherits the earlier synthetic Ed25519 signed grant + separate owner decision verification, but still executes only `CANARY_ECHO`. The parent `SyntheticAgent` remains a deliberately weaker proof and **MUST NOT** be used for live authorization.

## Negative tests and status output

Test cases cover: initial OPEN + same-process idempotence; same-grant reuse after restart; new grant quarantine while old OPEN exists; verified synthetic revoke and permanent old-grant tombstone; failed cleanup persisting quarantine; two concurrent host instances with different grants (one admitted); deleted/corrupt journal refusal; wrong host not consuming a grant; missing mandatory journal; expired grant not recorded; refusal to expose reset/repair/shell tools.

The host journal emits only `NO_UNVERIFIED_SESSIONS` or `HOST_QUARANTINED` plus counts, and one exact session state when requested locally. **This is a possible future safe diagnostic input to the existing LDW Host Agent**, not an installed Host Agent probe and not evidence of application readiness. Monitoring integration remains with business-operations #554 / HW&VM owner and must be independently reviewed.

## Local validation

From repo root with pinned test dependency installed:

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

The inherited Commander workflow runs the suite under Ubuntu and Windows, with the standard security checks. A local synthetic SQLite store lives only under a temporary private directory and is removed on test cleanup.

## Critical unsolved security and product gates

**Do not equate a SQLite tombstone with protected Administrator/root containment.** An actual privileged operation can create detached child processes, services or durable mutations that require OS-specific Windows Job Objects / Linux cgroup service tracking, out-of-process network restrictions, independently verified stop/drain, persistent anti-rollback trusted storage, protected key custody, secure time, and genuinely authenticated owner presence. This proof's `REVOKED_VERIFIED` is valid ONLY because its inherited agent executes no operating-system commands.

A real host reboot with an OPEN record **stays quarantined indefinitely** in this proof. Recovery must later require a separately accepted trusted owner recovery ceremony and independent evidence of no privileged descendants, not a model-supplied `clear` call or automatic deletion.

No production host access, Host Agent service/UI changes, secrets, customer data, privileged installer, new recurring subscription or Work/GitHub runtime message bus. Target incremental cash: **$0**. Author GM17 and GM20 main-integration work are ineligible for independent terminal security review. This current-main-targeted draft cannot merge until its own fresh exact-head tests, independent source review, and guarded source-only owner acceptance.
