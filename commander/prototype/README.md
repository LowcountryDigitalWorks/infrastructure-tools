# LDW Commander — synthetic session authorization proof (Gate B candidate)

SOURCE ONLY / no shell execution / no Administrator or root privileges / not deployed.

This prototype advances infrastructure-tools #209 without changing the accepted Admin Broker, Host Agent, Dragonfly, Operations Bridge or any LDW-owned endpoint.

The finished owner product remains a first-party Desktop Commander replacement with terminal, file, process, service and elevated Admin/root operations on enrolled hosts, callable from ordinary ChatGPT Chat and local CLI. This is not that product yet. It tests the session trust foundation and deliberately refuses to execute OS commands.

## Proofed mechanisms

- Trusted local issuer applies fixed operator, exact host, privilege and duration owner policy. This issuer is not an HTTP endpoint or model-approvable action.
- A short-lived grant is signed with Ed25519 over canonical JSON binding host, operator, scope, policy, session UUID, issuer, command budget, revocation epoch and validity. Only the trusted issuer has the private key; the synthetic host agent holds the verifier's public key only.
- The synthetic agent rechecks signature, target/actor identity and policy, and refuses occupied hosts, stale grants and invalid identity.
- A separate disposable Ed25519 **owner-decision** signer in `owner_decision.py` signs synthetic host/operator/policy/risk/TTL/scope-bound decisions. FULL_ADMIN session minting and the host verifier reject missing, forged, expired, wrong-host, wrong-operator, wrong-scope and replayed decisions. A chat message is not an owner decision; no model can choose an issuer signing key through a tool call.
- This is **NOT genuine owner authentication**: no trusted OS/hardware owner-presence UI or protected authorization record is implemented. The synthetic signer is a test fixture only and MUST NOT be installed as live owner consent.
- Consent replay tracking currently lives in **process memory**. Durable nonce persistence, concurrent-mint race resistance, secure clock/epoch recovery, per-command high-impact authorization, and signed narrow MAINTAIN delegation are **NOT proven**. Do not accept production FULL_ADMIN based on this prototype.
- The ONLY operation is an in-memory bounded uppercase CANARY_ECHO. It does not start a process, read/write a file, elevate privileges or contact a host.
- Command IDs are idempotent only for identical inputs; changes conflict. Three distinct synthetic commands per grant; expiry and revoke fail closed.

## Test

From repo root, Python 3.11+ and pinned cryptography==46.0.4 dependency (for Ed25519 signatures):

    python3 -m pip install -r commander/prototype/requirements.txt
    python3 -m unittest discover -s commander/prototype -p 'test_*.py' -v

Only the pinned cryptography dependency is required; no live keys, credentials, network listener, OS process/privilege changes, provider API, GitHub runtime transport or Desktop Commander required. Test signing keys are disposable synthetic fixtures and are not security credentials.

## Next gates

1. Commander Gate A trust design PR #214 must first receive independent security/architecture review and acceptance. This prototype remains a draft stacked PR until then.
2. Address missing trusted owner authentication, durable replay/concurrency control, revocation and per-command authorization before any privileged runtime; reconcile with accepted design and fix deviations. Require exact-head tests, security workflows and author-independent review before source acceptance.
3. Separately build OS-specific privilege adapters and local CLI on disposable systems without customer credentials. A real elevated install is a consequential gate with protected artifact identity, revocation, audit, recovery and safe rollback.
4. Ordinary ChatGPT plugin connectivity, cross-host authentication and plan support are separate provider gates; source acceptance here does not establish them.

No reusable broad admin secret, public remote shell, insecure fallback, model-visible credentials, deployed privileged service, customer/regulated data, new paid subscription or background schedule. Incremental cash target $0.
