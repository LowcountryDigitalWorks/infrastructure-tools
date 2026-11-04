# Commander — per-command intent journal (synthetic source proof)

**Owner:** infrastructure-tools #209. **Release status:** unprivileged, standalone source proof only; this branch is stacked on Commander draft #222. Not installed, not connected to an OS command runner, not an elevated service or approved session authority.

## Why this exists

The issuer approval journal prevents reusing a signed *owner decision*. The host session journal prevents re-opening an *old session*. Neither yet keeps a persistent record of an individual *command request ID*. An intermittent connection or restarted agent must not run a potentially mutating operation a second time simply because the transport retried its message.

`command_intent_journal.py` introduces an intentionally separate, minimal SQLite ledger of command attempts with a command UUID (unique across the ledger), session UUID, SHA-256 digest of a canonical command intent and three stages:

- `RESERVED_UNVERIFIED`: an attempt has been atomically reserved. This is written **before** any future process launch. After crash/restart it is **ambiguous**, not evidence that a process started or finished. An unknown attempt cannot be replayed.
- `PROCESS_DRAIN_VERIFIED`: a future independently reviewed caller will be allowed to assert positive OS child-process cleanup *after independent proof*, not inferred from shell exit or an operation timeout. It does not claim host authorization was cleanly closed or system changes were rolled back.
- `HOST_CLOSE_VERIFIED`: a future independently reviewed caller will assert that the host-session journal shows verified closure. Only this state releases the journal from quarantine for **different fresh commands**, while the original command ID remains a permanent one-use tombstone.

One atomic `BEGIN IMMEDIATE` transaction prevents two threads or issuer instances sharing a database from reserving the same command ID concurrently. A second command is refused while *any* prior attempt lacks verified host closure. An exact duplicate returns `COMMAND_ALREADY_RESERVED` (no execution/retry); a changed session/intent reusing that ID returns `COMMAND_ID_CONFLICT`. All errors are bounded reason codes; no raw command, output or secret is echoed in the journal result.

The digest binds exactly the signed session token hash, session ID, host, registered operation, registered workload and command ID. This is correlation only: **not itself a signature, owner consent, safe-operation classifier, replay-proof global remote state, or an authorization to run anything**. The registry and signed-grant verification remain separate trust gates.

## Verification

Tests run on Windows and Ubuntu as part of the inherited Commander synthetic workflow:

    python -m unittest discover -s commander/prototype -p 'test_*.py' -v

The new tests cover atomic transitions, unavailable/corrupt/missing/reinitialized ledger, distinct-session collisions, concurrent same-ID and different-ID admission, restart replay denial, illegal early `HOST_CLOSE_VERIFIED`, invalid IDs/digests, read-only status and absence of shell/reset APIs.

The disposable SQLite database is created by a separate one-time synthetic test bootstrap in an owner-private temporary folder, then deleted after test cleanup. Normal reopen uses `mode=rw`; a missing or corrupt database fails closed and is never automatically recreated. On POSIX, private parent and file modes are required. Windows file ACL hardening and rollback-resistant storage are **not** established here.

## Hard limits and next integration gate

**This branch does not wire the journal to the real fixed-workload process harness.** That coupling must be separately implemented and independently reviewed: validate actual owner/session grant before reservation, atomically reserve intent before spawn, bind to existing exact host allowlist, independently observe the OS drain, check host-journal `REVOKED_VERIFIED`, and only then mark command `HOST_CLOSE_VERIFIED`. Any crash/error leaves the attempt ambiguous/quarantined. Never guess terminal success from a transport timeout.

The command journal itself cannot demonstrate arbitrary Administrator/root safety, external network/secret containment, tamper-proof/OS-protected storage, real owner presence, native ChatGPT Chat-to-Chat wake, a deployed remote host, or integration with the existing LDW Host Agent. No process executor, shell, network listener, privileged service, account credential or self-repair method is included.

The stack remains blocked for release by the current exact-head **independent Gate A** acceptance and the dependent security reviews of #215, #217, #219, #221 and #222. This source is a DRAFT, not an accepted product or permission to install anything. It is separate from the existing protected Admin Broker. No extra SaaS spend, no customer/regulated data and no host/runtime changes. Target incremental cash $0.
