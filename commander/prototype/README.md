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
- The FULL_ADMIN issuer now requires a separately bootstrapped disposable **SQLite approval journal** (`approval_journal.py`). Its atomic unique-ID transaction consumes a signed decision **before any grant returns**, including multiple issuer objects and process restarts sharing a protected local path. No journal, missing/corrupt journal, double consumption or untrusted directory -> fail closed. A single-issuer RLock also serializes issuance.
- The journal is a **synthetic cross-restart/thread replay proof, not production-grade protected owner state**. It does not implement a TPM-bound signer, hardened Windows ACL/OS rollback prevention, verifiable protected state recovery, hostile same-owner process integrity, independent host-side persistent drain/nonce ledger, secure clock/epoch recovery, command egress policy, owner-attested approval UI, or signed narrow MAINTAIN delegation. An attacker with actual full machine Administrator/root could tamper with local state; stronger isolation and trusted owner authentication remain consequential gates. **Do not accept production FULL_ADMIN based on this prototype.**
- The ONLY operation is an in-memory bounded uppercase CANARY_ECHO. It does not start a process, read/write a file, elevate privileges or contact a host.
- Command IDs are idempotent only for identical inputs; changes conflict. Three distinct synthetic commands per grant; expiry and revoke fail closed.

Two-host enrollment / revocation denial matrix (synthetic compose-only): see `TWO_HOST_ENROLLMENT_DENIAL.md` and `test_two_host_enrollment_denial.py`.

## Test

From repo root, Python 3.11+ and pinned cryptography==50.0.2 dependency (for Ed25519 signatures):

    python3 -m pip install -r commander/prototype/requirements.txt
    python3 -m unittest discover -s commander/prototype -p 'test_*.py' -v

Dependency security disposition (PR237 independent IR M1): `cryptography==50.0.2` is the latest upstream stable release available at this November 2026 source-authoring checkpoint, and declares Python 3.11 support. The earlier 48.0.1 increment fixed the two originally reported advisories — [GHSA-r6ph-v2qm-q3c2](https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2), fixed in 46.0.5, and [GHSA-537c-gmf6-5ccf](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf), fixed in 48.0.1 — but subsequent July 2026 advisories also affect older releases. [GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5) (PKCS#7 oracle) is fixed in 50.0.0, while [GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww) and [GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c) are fixed in 49.0.0. This synthetic implementation uses only Ed25519, not SECT/PKCS#7/X.509-path validation, but we avoid maintaining a knowingly outdated dependency. Upstream release metadata alone is not a compatibility test: the exact new HEAD must pass the existing Linux/Windows Python 3.11 CI and current security checks, then a distinct independent review. No production signer, key, root/Admin session or privileged runtime is authorized by this dependency bump. Re-check provider advisories at promotion time.

Only the pinned cryptography dependency is required; SQLite is part of the Python standard library. Tests create their own private temporary database, run concurrent and restart replay cases, and remove the database afterward. No live keys, credentials, network listener, remote host, OS privilege changes, provider API, GitHub runtime transport or Desktop Commander required. Test signing keys are disposable synthetic fixtures, not production security credentials.

## Next gates

1. Commander Gate A trust design PR #214 must first receive independent security/architecture review and acceptance. This prototype remains a draft stacked PR until then.
2. Independent reviewers must challenge the new **synthetic** issuer journal and prove rejection of missing, corrupt, replayed and concurrently used approvals on both operating systems. Protected owner presence, durable rollback-resistant **production** issuer and host state, privileged child drain, egress and per-command authorization remain missing; do not promote the disposable SQLite proof to an accepted root/Admin grant service. Reconcile with Gate A before any consequential runtime. Require exact-head tests, security workflows and author-independent review before source acceptance.
3. Separately build OS-specific privilege adapters and local CLI on disposable systems without customer credentials. A real elevated install is a consequential gate with protected artifact identity, revocation, audit, recovery and safe rollback.
4. Ordinary ChatGPT plugin connectivity, cross-host authentication and plan support are separate provider gates; source acceptance here does not establish them.

No reusable broad admin secret, public remote shell, insecure fallback, model-visible credentials, deployed privileged service, customer/regulated data, new paid subscription or background schedule. Incremental cash target $0.
