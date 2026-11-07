# Signed batch binding (Gate B synthetic proof)

Status: SOURCE-ONLY / VERIFIER ONLY / NOT OWNER CONSENT

Issue: infrastructure-tools #209. `owner_decision.py` v1 signs a decision that is not bound to a command batch. This proof does not change that module and does not treat a v1 signature as batch approval.

`verify_signed_batch` checks an Ed25519 signature over canonical UTF-8 JSON version `ldw.commander.signed-batch-decision.v1`. The record must name the exact SHA-256 of the canonical batch bytes from `canonical_command_batch.py`, plus host, operator, public signer-key id and generation, session, decision, and batch ids, mode `SYNTHETIC_BATCH_IDENTITY_ONLY`, issuance, expiry, generation, command budget, risk class, and a separate intent digest. The private key is created inside unit tests only.

A changed argv, payload, stdin, environment, cwd, intent, or an added command produces different batch bytes and is refused. Duplicate keys and noncanonical JSON are refused. `SyntheticNonceLedger` rejects a second use of the same nonce in one process. That ledger is not OS-protected replay storage. No process is spawned, no path is opened, and no Administrator or root session is created.

Cost: $0. No new dependency.
