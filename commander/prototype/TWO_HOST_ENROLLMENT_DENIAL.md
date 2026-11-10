# Two-host synthetic enrollment denial (#209)

Status: **SOURCE-ONLY** / **SYNTHETIC_NO_EXECUTION** / independent security review required.

Composes existing `canonical_command_batch`, `signed_batch_binding`, `gate_a_admission`, and `session` fixtures to prove that host **A** and host **B** enrollments are cryptographically distinct:

- Per-host batch binding and Gate A admission (`WRONG_HOST` cross-host).
- Cross-host session grant refusal on the synthetic agent.
- Stale batch generation, wrong signer generation, issuer epoch rotation (`REVOKED_EPOCH`).
- Revoked session tombstone (`REVOKED_SESSION`).
- TTL upper bound (`BATCH_NOT_BOUND`).
- Wrong verifier key (`WRONG_KEY`), nonce replay (`BATCH_REPLAY`), split-brain batch digest drift (`SPLIT_BRAIN`).

No network, shell, enrollment writes, or `execute: true`. Software Ed25519 keys are disposable test material only.

Tests: `python -m unittest commander.prototype.test_two_host_enrollment_denial -v` (from repo root with `PYTHONPATH=commander/prototype` or discover from `commander/prototype`).
